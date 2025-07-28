// TRIX: Inference of Transient Violation Times from Logged Routing Events or Collected BGP Messages
// Copyright (C) 2024-2025 Roland Schmid <roschmi@ethz.ch> and Tibor Schneider <sctibor@ethz.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::BufReader,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use clap::Parser;
use itertools::Itertools;
use mac_address::MacAddress;
use pcap_file::pcap::PcapReader;
use pnet_packet::{ethernet, ip, ipv4, Packet};
use rayon::prelude::*;
use serde::Serialize;

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
    records::{DPRecord, FWRecord, PathRecord, Router},
    util, Prefix as P,
};
use trix_utils::other::send_slack_notification;
use bgpsim::formatter::NetworkFormatter;
use bgpsim::prelude::*;

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";

/// Process all pcaps
pub(crate) async fn process_pcaps(
    data_root: impl AsRef<Path>,
    filter: Filter,
    plot_histogram_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let data_root = data_root.as_ref();

    // get all (topo, scenario) combinations
    fs::read_dir(data_root)
        .expect("path should exist!")
        .flat_map(|topo_dir| {
            let topo_path = topo_dir.unwrap().path();

            fs::read_dir(topo_path.display().to_string())
                .unwrap()
                .map(move |scenario_dir| {
                    (
                        topo_path.clone(),
                        scenario_dir
                            .unwrap()
                            .path()
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .to_string(),
                    )
                })
                .filter(|(topo_path, scenario_name)|
                    topo_path
                        .display()
                        .to_string()
                        .contains(&filter.topo)
                    && scenario_name.contains(&filter.scenario)
                    && scenario_name.ends_with(&filter.scenario_end)
                )
        })
        .unique()
        .collect_vec()
        .into_par_iter()
        //.into_iter()
        .for_each(|(topo_path, scenario_name)| {
            let topo_name = topo_path.file_name().unwrap().to_string_lossy();

            let mut data_path = data_root.to_path_buf();
            data_path.push(&topo_name.to_string());
            data_path.push(&scenario_name);

            // path under which to place processed violation times
            //let eval_root = "./data/";
            //let mut eval_path = PathBuf::from(eval_root);
            //eval_path.push(&topo_name.to_string());
            //eval_path.push(&scenario_name);
            let eval_path = data_path.clone();
            fs::create_dir_all(&eval_path).unwrap();

            let mut reachability_violation_file_path = eval_path.clone();
            reachability_violation_file_path.push("violation_reachability.json");
            #[cfg(feature = "all-fw-properties")]
            let mut loopfreedom_violation_file_path = eval_path.clone();
            #[cfg(feature = "all-fw-properties")]
            loopfreedom_violation_file_path.push("violation_loopfreedom.json");
            #[cfg(feature = "all-fw-properties")]
            let mut stable_path_violation_file_path = eval_path.clone();
            #[cfg(feature = "all-fw-properties")]
            stable_path_violation_file_path.push("violation_stable_path.json");
            // add waypoint_violation_file_path later
            #[cfg(feature = "all-fw-properties")]
            let mut waypoint_violation_file_paths: BTreeMap<RouterId, _> = BTreeMap::new();
            let mut useful_packets_counter_file_path = eval_path.clone();
            useful_packets_counter_file_path.push("useful_packets_counter.csv");

            // evaluate the data captured by the cisco_analyzer
            let mut analyzer_csv_path = data_path.clone();
            analyzer_csv_path.push("cisco_analyzer.csv");
            if !analyzer_csv_path.exists() {
                log::trace!(
                    "Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet."
                );
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }
            log::info!("Loading: {topo_name}/{scenario_name}/cisco_analyzer.csv");
            let analyzer_csv = fs::File::open(analyzer_csv_path.clone()).unwrap();
            let mut csv = csv::Reader::from_reader(analyzer_csv);

            let Ok(analyzer) = util::get_analyzer(&topo_name, &scenario_name) else {
                log::trace!("Could not build `Analyzer` for experiment in {analyzer_csv_path:?}.");
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            };

            let mut reachability_violation_times: Vec<Sample> = Vec::new();
            let mut reachability_update_times: Vec<DPRecord> = Vec::new();
            let mut path_update_times: Vec<PathRecord> = Vec::new();
            let mut forwarding_update_times: Vec<FWRecord> = Vec::new();
            #[cfg(feature = "all-fw-properties")]
            let mut loopfreedom_violation_times: Vec<Sample> = Vec::new();
            #[cfg(feature = "all-fw-properties")]
            let mut stable_path_violation_times: Vec<Sample> = Vec::new();
            #[cfg(feature = "all-fw-properties")]
            let mut waypoint_violation_times: HashMap<RouterId, Vec<Sample>> = HashMap::new();

            #[cfg(feature = "incremental")]
            if reachability_violation_file_path.exists() {
                let serialized_reachability_violation_times =
                    fs::read_to_string(&reachability_violation_file_path).unwrap();
                reachability_violation_times =
                    serde_json::from_str(&serialized_reachability_violation_times).unwrap();

                if csv.deserialize().all(|record| {
                    let record: CiscoAnalyzerData = record.unwrap();
                    reachability_violation_times.iter().any(|s| s.sample_id == record.execution_timestamp)
                }) {
                    log::trace!("Skipping scenario {scenario_name} on topology {topo_name} because processing is already complete!");
                    return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
                }
                // re-open csv
                let analyzer_csv = fs::File::open(analyzer_csv_path).unwrap();
                csv = csv::Reader::from_reader(analyzer_csv);
            }

            #[cfg(all(feature = "incremental", feature = "all-fw-properties"))]
            {
                if loopfreedom_violation_file_path.exists() {
                    let serialized_loopfreedom_violation_times =
                        fs::read_to_string(&loopfreedom_violation_file_path).unwrap();
                    loopfreedom_violation_times =
                        serde_json::from_str(&serialized_loopfreedom_violation_times).unwrap();
                }

                if stable_path_violation_file_path.exists() {
                    let serialized_stable_path_violation_times =
                        fs::read_to_string(&stable_path_violation_file_path).unwrap();
                    stable_path_violation_times =
                        serde_json::from_str(&serialized_stable_path_violation_times).unwrap();
                }

                let mut glob_path = eval_path.to_string_lossy().to_string();
                glob_path.push_str("/violation_waypoint_*.json");
                for glob_result in glob::glob(&glob_path).unwrap() {
                    let waypoint_violation_file_path = glob_result.unwrap();
                    let waypoint = waypoint_violation_file_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                        .replace("violation_waypoint_", "")
                        .replace(".json", "");
                    let waypoint_rid = analyzer.original_net.get_router_id(waypoint).unwrap();

                    let serialized_waypoint_violation_times =
                        fs::read_to_string(&waypoint_violation_file_path).unwrap();
                    waypoint_violation_times.insert(
                        waypoint_rid,
                        serde_json::from_str(&serialized_waypoint_violation_times).unwrap()
                    );
                    waypoint_violation_file_paths.insert(waypoint_rid, waypoint_violation_file_path);
                }
            }

            'samples: for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                if !record.execution_timestamp.contains(&filter.sample_id) {
                    log::trace!("skipping {} due to filter on sample_id...", record.pcap_filename);
                    continue 'samples;
                }

                #[cfg(all(feature = "incremental", not(feature = "all-fw-properties")))]
                if reachability_violation_times.iter().any(|s| s.sample_id == record.execution_timestamp) {
                    log::trace!("skipping {} due to incremental processing...", record.pcap_filename);
                    continue 'samples;
                }
                #[cfg(all(feature = "incremental", feature = "all-fw-properties"))]
                if reachability_violation_times.iter().any(|s| s.sample_id == record.execution_timestamp)
                    && loopfreedom_violation_times.iter().any(|s| s.sample_id == record.execution_timestamp)
                    && stable_path_violation_times.iter().any(|s| s.sample_id == record.execution_timestamp)
                    && waypoint_violation_times.values().all(|xs| xs.iter().any(|s| s.sample_id == record.execution_timestamp))
                {
                    log::trace!("skipping {} due to incremental processing...", record.pcap_filename);
                    continue 'samples;
                }

                if record.packets_dropped != 0 {
                    log::error!("skipping {} due to {} packets dropped upon capture", record.pcap_filename, record.packets_dropped);
                    continue 'samples;
                }

                let mut reachability_sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();
                #[cfg(feature = "all-fw-properties")]
                let mut loopfreedom_sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();
                #[cfg(feature = "all-fw-properties")]
                let mut stable_path_sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();
                #[cfg(feature = "all-fw-properties")]
                let mut waypoint_sample_data: HashMap<RouterId, HashMap<String, HashMap<String, ViolationInfo>>> =
                    HashMap::new();

                // extract event's starting time, using it as an offset so the trace starts at 0.0
                let time_offset = record.event_start;

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = data_path.clone();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                log::trace!("reading hw mapping from {hardware_mapping_path:?}");
                let serialized_hardware_mapping = fs::read_to_string(&hardware_mapping_path).unwrap();
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping).unwrap();

                // check that the generated network still has the same router assignment as the
                // hardware mapping
                for rid in analyzer.original_net.device_indices() {
                    assert_eq!(rid.fmt(&analyzer.original_net), hardware_mapping.get(&rid).expect("router should still exist").name);
                }

                // allows to get the `RouterId` (rid) of an internal router from its corresponding
                // prober src ip address
                let prober_ip_to_rid_mapping: HashMap<Ipv4Addr, RouterId> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        // external routers do not send prober packets
                        .filter(|(_, router)| !router.is_external)
                        .map(|(rid, router)| (router.prober_src_ip.unwrap(), *rid)),
                );

                // allows to get rids of an internal router and its connected external router
                let last_mac_to_ext_rid_mapping: HashMap<MacAddress, (RouterId, RouterId)> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        // external routers do not send prober packets
                        .filter(|(_, router)| router.is_external)
                        .map(|(ext, router)| {
                            assert!(router.ifaces.len() == 1);
                            (
                                router.ifaces[0].neighbor_mac.unwrap(),
                                (router.ifaces[0].neighbor, *ext)
                            )
                        }),
                );

                // allows to get rids of neighboring internal routers
                let neighbor_mapping: HashMap<(MacAddress, MacAddress), _> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        .filter(|(_, router)| !router.is_external)
                        .flat_map(|(rid, router)| {
                            router.ifaces
                                .iter()
                                .filter(|iface| iface.neighbor_mac.is_some())
                                .map(|iface| {
                                (
                                    (
                                        // interfaces where the src_mac is None are external routers
                                        iface.mac.unwrap(),
                                        iface
                                            .neighbor_mac
                                            .unwrap(),
                                    ),
                                    (*rid, iface.neighbor),
                                )
                            })
                        }),
                );

                // read pcap_path from the cisco_analyzer.csv
                let mut pcap_path = data_path.clone();
                pcap_path.push(&record.pcap_filename);

                // check if processing is even necessary
                if plot_histogram_path.is_some() {
                    let mut paths = Vec::new();

                    let mut output_path = data_path.clone();
                    output_path.push(&format!("path_updates_{}.csv", record.pcap_filename,));
                    paths.push(output_path);

                    let mut output_path = data_path.clone();
                    output_path.push(&format!("dp_updates_{}.csv", record.pcap_filename,));
                    paths.push(output_path);

                    let mut output_path = data_path.clone();
                    output_path.push(&format!("fw_updates_{}.csv", record.pcap_filename,));
                    paths.push(output_path);

                    // if all of these already exist, abort processing this scenario
                    if paths.into_iter().all(|p| p.exists()) {
                        continue 'samples;
                    }
                }

                // Open the gzipped pcap file
                let mut gunzip = Command::new("gunzip")
                    .args(["-c", &pcap_path.to_string_lossy()])
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let gunzip_reader = BufReader::new(gunzip.stdout.take().unwrap());

                let mut pcap_reader = PcapReader::new(gunzip_reader).unwrap();

                // store for each prober packet when it was sent
                let mut prober_in: BTreeMap<(RouterId, Ipv4Addr), BTreeMap<u64, f64>> =
                    BTreeMap::new();
                // store for each prober packet when it reached which external router
                let mut prober_out: BTreeMap<(RouterId, Ipv4Addr), BTreeMap<u64, (f64, RouterId)>> =
                    BTreeMap::new();

                // rid, dst_ip -> prober_idx -> to_rid (on link) -> counter
                let mut node_tracking: BTreeMap<(RouterId, Ipv4Addr), BTreeMap<u64, BTreeMap<RouterId, u64>>> = BTreeMap::new();
                // rid, dst_ip -> prober_idx -> from_rid (on link), to_rid (on link) -> counter
                #[allow(clippy::type_complexity)]
                let mut link_tracking: BTreeMap<(RouterId, Ipv4Addr), BTreeMap<u64, BTreeMap<(RouterId, RouterId), u64>>> = BTreeMap::new();
                // rid, dst_ip -> prober_idx -> Vec<rid>
                #[allow(clippy::type_complexity)]
                let mut path_tracking: BTreeMap<(RouterId, Ipv4Addr), BTreeMap<u64, Vec<RouterId>>> = BTreeMap::new();

                // from_rid (on link), to_rid (on link), src_ip, dst_ip, prober_idx -> Vec<t_recv>
                let mut delayer_tracking: BTreeMap<(RouterId, RouterId, Ipv4Addr, Ipv4Addr, u64), Vec<f64>> =
                    BTreeMap::new();

                let mut prober_init_counter: u64 = 0;

                let mut first_timestamp = f64::NAN;
                let mut last_timestamp = f64::NAN;

                // count how many packets were useful to determine violation times, so that we can
                // estimate the impace of some packets dropped
                let mut packets_counter: u64 = 0;
                let mut useful_packets_counter: u64 = 0;
                let mut acc_packet_size: u64 = 0;
                let mut acc_useful_packet_size: u64 = 0;

                // allow to determine whether we see this packet for the first time
                let mut observed_packets: HashSet<(RouterId, Ipv4Addr, u64)> = HashSet::new();
                // store previously seen next_hop for each (rid, prefix)
                let mut last_next_hop: HashMap<(RouterId, Ipv4Addr), (RouterId, u64)> = HashMap::new();

                while let Some(next_packet) = pcap_reader.next_packet() {
                    // skip packets that cannot be parsed
                    let Ok(packet) = next_packet else {
                        continue;
                    };

                    packets_counter += 1;
                    acc_packet_size += packet.orig_len as u64;

                    // check packet length
                    if packet.orig_len < PROBER_PACKET_SIZE {
                        continue;
                    }

                    // construct the packet
                    let Some(eth) = ethernet::EthernetPacket::new(packet.data.borrow()) else {
                        continue;
                    };

                    // check the type
                    if eth.get_ethertype() != ethernet::EtherTypes::Ipv4 {
                        continue;
                    }

                    let Some(ip) = ipv4::Ipv4Packet::new(eth.payload()) else {
                        continue;
                    };

                    // check the protocol is Test1
                    if ip.get_next_level_protocol() != ip::IpNextHeaderProtocols::Test1 {
                        continue;
                    }

                    // get the sequence number
                    let Ok(idx) = ip.payload().try_into().map(u64::from_be_bytes) else {
                        eprintln!("Packet does not contain enough bytes to extract a prober sequence number!");
                        continue;
                    };

                    // get the packet metadata
                    let time_received = packet.timestamp.as_secs_f64() - time_offset;
                    let src_mac = eth.get_source();
                    let dst_mac = eth.get_destination();
                    let src_ip = ip.get_source();
                    let dst_ip = ip.get_destination();

                    if first_timestamp.is_nan() {
                        first_timestamp = time_received;
                    }
                    last_timestamp = time_received;

                    // count regardless of finding the prober IP in the mapping – this should count
                    // the same thing though!
                    if MacAddress::from(src_mac.octets()) == MacAddress::from_str(PROBER_SRC_MAC).unwrap() {
                        prober_init_counter += 1;
                    }

                    // check if this packet is a measurement packet
                    if let Some(rid) = prober_ip_to_rid_mapping.get(&src_ip) {
                        let prefix = &dst_ip; // use dst_ip as the prefix since this is what's
                                              // available from the pcap

                        let mut delayed = false; // easy access to whether this current packet has
                                                 // been delayed or not (pre / post delayer)
                        let mut _looped = false; // easy access to whether this current packet has
                                                // looped or not

                        // check that the measurement packet is not on its first or last hop
                        if MacAddress::from(src_mac.octets()) == MacAddress::from_str(PROBER_SRC_MAC).unwrap() {
                            let duplicate = prober_in.entry((*rid, dst_ip))
                                .or_default()
                                .insert(idx, time_received);
                            assert!(duplicate.is_none());
                        } else if let Some((_from_rid, ext)) = last_mac_to_ext_rid_mapping.get(&MacAddress::from(src_mac.octets())) {
                            let duplicate = prober_out.entry((*rid, dst_ip))
                                .or_default()
                                .insert(idx, (packet.timestamp.as_secs_f64(), *ext));
                            assert!(duplicate.is_none());
                            useful_packets_counter += 1;
                            acc_useful_packet_size += packet.orig_len as u64;
                        } else if let Some((from_rid, to_rid)) = neighbor_mapping.get(&(MacAddress::from(src_mac.octets()), MacAddress::from(dst_mac.octets()))) {
                            // delayer tracking
                            let track = delayer_tracking
                                .entry((*from_rid, *to_rid, src_ip, dst_ip, idx))
                                .or_default();
                            track.push(packet.timestamp.as_secs_f64());
                            delayed = track.len() % 2 == 0;
                        }

                        // get `RouterId`s for internal and the last hop to external routers
                        if let Some((from_rid, to_rid)) = neighbor_mapping
                            .get(&(MacAddress::from(src_mac.octets()), MacAddress::from(dst_mac.octets())))
                            .or(last_mac_to_ext_rid_mapping.get(&MacAddress::from(src_mac.octets()))) {
                            let first_observation = observed_packets.insert((*rid, dst_ip, idx));
                            // loopfreedom tracking
                            {
                                // initialize node_tracking HashMap for the current packet flow if necessary
                                let packet_node = node_tracking.entry((*rid, *prefix)).or_default();
                                // initialize HashMap for the current packet if necessary
                                let node_idx_counter = packet_node.entry(idx).or_insert(BTreeMap::from([
                                    // initialize counter to have reached the prober src router as the
                                    // neighbor mapping will not match the injected packet
                                    (*rid, 2_u64)
                                ]));
                                // initialize counter for the current link if necessary
                                let counter = node_idx_counter.entry(*to_rid).or_insert(0);
                                // count current packet from pcap
                                *counter += 1;

                                // if we see the packet more than twice (due to delayer), this packet
                                // has looped!
                                if *counter > 2 {
                                    log::trace!(
                                        "[{}] Looped packet from {} to {} with id {idx} reaching {} (count: #{})\nlinks: {:?}",
                                        packet.timestamp.as_secs_f64(),
                                        rid.fmt(&analyzer.original_net),
                                        prefix,
                                        to_rid.fmt(&analyzer.original_net),
                                        *counter / 2,
                                        link_tracking
                                            .entry((*rid, *prefix))
                                            .or_default()
                                            .entry(idx)
                                            .or_default()
                                            .iter()
                                            .map(|((from_rid, to_rid), _)|
                                                 (from_rid.fmt(&analyzer.original_net), to_rid.fmt(&analyzer.original_net))
                                             )
                                            .collect_vec(),
                                    );
                                    _looped = true;
                                }
                            }
                            // path tracking
                            {
                                // initialize link_tracking HashMap for the current packet flow if necessary
                                let packet_link = link_tracking.entry((*rid, *prefix)).or_default();
                                // initialize HashMap for the current packet if necessary
                                let link_idx_counter = packet_link.entry(idx).or_default();
                                // initialize counter for the current link if necessary and count current packet from pcap
                                *link_idx_counter.entry((*from_rid, *to_rid)).or_insert(0) += 1;

                                if !delayed {
                                    // initialize path_tracking HashMap for the current packet flow if necessary
                                    let packet_path = path_tracking.entry((*rid, *prefix)).or_default();
                                    // initialize path for the current packet with the originating router if necessary,
                                    // and append the next hop from the current link
                                    packet_path.entry(idx).or_insert(vec![*from_rid]).push(*to_rid);
                                }
                            }
                            // fw update tracking, only if packets are on first hop from emanating router
                            if plot_histogram_path.is_some() && first_observation && time_received > first_timestamp + 1.0 {
                                let last = last_next_hop.insert((*rid, *prefix), (*to_rid, idx));
                                assert!(last.is_none() || last.unwrap().1 < idx);

                                // check if first packet forwarded, forwarded to a different
                                // next_hop or forwarded to the same next_hop after some drops
                                if last.is_none() || last.unwrap().0 != *to_rid || (last.unwrap().1 + 1) < idx {
                                    // compute potential black hole
                                    match last.map(|(_, old_idx)| idx - (old_idx + 1)) {
                                        Some(black_hole) if black_hole > 0 => {
                                            if packet.timestamp.as_secs_f64()
                                                    - black_hole as f64 / record.capture_frequency as f64 >= 0.0 {
                                                forwarding_update_times.push(FWRecord {
                                                    time: packet.timestamp.as_secs_f64()
                                                        - black_hole as f64 / record.capture_frequency as f64,
                                                    src: *rid,
                                                    src_name: Router::from_str(rid.fmt(&analyzer.original_net)).ok(),
                                                    prefix: *prefix,
                                                    seq: last.map(|(_, idx)| idx),
                                                    next_hop: None,
                                                    next_hop_name: None,
                                                });
                                                log::trace!("[FW] Found black hole: {:?}", forwarding_update_times[forwarding_update_times.len() - 1]);
                                            } else {
                                                println!("negative time caused by blackhole! {}", packet.timestamp.as_secs_f64()
                                                    - black_hole as f64 / record.capture_frequency as f64);
                                            }
                                        }
                                        _ => {}
                                    }
                                    // new next_hop
                                    forwarding_update_times.push(FWRecord {
                                        time: packet.timestamp.as_secs_f64(),
                                        src: *rid,
                                        src_name: Router::from_str(rid.fmt(&analyzer.original_net)).ok(),
                                        prefix: *prefix,
                                        seq: Some(idx),
                                        next_hop: Some(*to_rid),
                                        next_hop_name: Router::from_str(to_rid.fmt(&analyzer.original_net)).ok(),
                                    });
                                    log::trace!("[FW] Found new next hop: {:?}", forwarding_update_times[forwarding_update_times.len() - 1]);
                                }
                            }
                        }
                    }
                }

                #[derive(Serialize)]
                struct UsefulPackets {
                    sample_id: String,
                    packets_counter: u64,
                    useful_packets_counter: u64,
                    rate_packets_useful: f64,
                    acc_packet_size: u64,
                    acc_useful_packet_size: u64,
                    rate_bytes_useful: f64,
                }

                let mut csv = csv::WriterBuilder::new()
                    .has_headers(!useful_packets_counter_file_path.exists()
                                 || fs::metadata(&useful_packets_counter_file_path).unwrap().len() == 0)
                    .from_writer(
                    fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .truncate(false)
                        .open(&useful_packets_counter_file_path)
                        .unwrap(),
                );
                csv.serialize(UsefulPackets {
                    sample_id: record.execution_timestamp.to_string(),
                    packets_counter,
                    useful_packets_counter,
                    rate_packets_useful: useful_packets_counter as f64 / packets_counter as f64,
                    acc_packet_size,
                    acc_useful_packet_size,
                    rate_bytes_useful: acc_useful_packet_size as f64 / acc_packet_size as f64,
                }).unwrap();
                csv.flush().unwrap();

                assert_eq!(prober_in.values().map(|idx_map| idx_map.len() as u64).sum::<u64>(), prober_init_counter);

                if !scenario_name.contains("Delay0") {
                    // check for delayer drops
                    let delayer_in = delayer_tracking
                        .iter()
                        .filter(|(_, times)| times.iter().any(|t_recv| first_timestamp + 1.0 > *t_recv)
                                || times.iter().all(|t_recv| *t_recv < last_timestamp - 1.0)
                            )
                        .collect_vec();
                    let delayer_out = delayer_in
                        .iter()
                        .filter(|(_, times)| times.len() >= 2)
                        .collect_vec();
                    if delayer_in.len() != delayer_out.len() {
                        log::error!("discarding sample due to drops in the delayers\n  -> {scenario_name}\n  -> {pcap_path:?}");
                        continue 'samples;
                    }

                    // check for inaccurate delay values
                    let mut observed_delays: HashMap<(RouterId, RouterId), Vec<f64>> = HashMap::new();
                    for ((from_rid, to_rid, _, _, _), times) in delayer_out.iter() {
                        let sorted_times = times
                            .iter()
                            .sorted_by(|a, b| a.total_cmp(b))
                            .collect_vec();

                        assert!(sorted_times.len() >= 2);
                        assert!(sorted_times[1] >= sorted_times[0]);

                        observed_delays
                            .entry((*from_rid, *to_rid))
                            .or_default()
                            .push(sorted_times[1] - sorted_times[0]);
                    }

                    for (_, delays) in observed_delays.into_iter() {
                        let sorted_delays = delays
                            .into_iter()
                            .sorted_by(|a, b| a.total_cmp(b))
                            .collect_vec();
                        if !sorted_delays.is_empty() {
                            let med = sorted_delays[sorted_delays.len() / 2];
                            if sorted_delays[sorted_delays.len() / 100] < 0.8 * med
                                || sorted_delays[2 * sorted_delays.len() / 100] < 0.85 * med
                                || sorted_delays[10 * sorted_delays.len() / 100] < 0.9 * med
                                || sorted_delays[90 * sorted_delays.len() / 100] > 1.1 * med
                                || sorted_delays[98 * sorted_delays.len() / 100] > 1.15 * med
                                || sorted_delays[99 * sorted_delays.len() / 100] > 1.2 * med
                            {
                                log::error!("discarding sample due to bad accuracy of the delayers (measured w.r.t. the median delay on the link)\n  -> {scenario_name}\n  -> {pcap_path:?}");
                                continue 'samples;
                            }
                        }
                    }
                }

                //let mut paths_histogram = plotly::Plot::new();

                // post-processing reachability, loopfreedom, stable_path, and waypoint violations
                let prober_flows = prober_in.keys().cloned().collect_vec();
                'prober_flows: for (rid, prefix_ip) in prober_flows.iter() {
                    let prober_in_flow = prober_in.get(&(*rid, *prefix_ip)).unwrap();
                    let mut prefix_handles = Vec::new();

                    let prefix = P::from(*prefix_ip);

                    if !prober_in_flow
                            .iter()
                            .any(|(_, t_recv)| *t_recv <= first_timestamp + 1.0)
                        || !prober_in_flow
                            .iter().any(|(_, t_recv)| *t_recv > last_timestamp - 1.0)
                    {
                        // skip this sample entirely
                        log::warn!("could not find prober traffic for prefix {prefix_ip:?} at the start/end of the experiment! skipping this prober flow...");
                        send_slack_notification(format!("could not find prober traffic for prefix {prefix_ip:?} at the start/end of the experiment! skipping this prober flow..."));
                        continue 'prober_flows;
                    }


                    let considered_prober_packets: BTreeMap<u64, f64> = BTreeMap::from_iter(
                        prober_in
                            .get(&(*rid, *prefix_ip))
                            .unwrap_or(&BTreeMap::new())
                            .iter()
                            .filter(|(_, t_recv)| first_timestamp + 1.0 <= **t_recv
                                    && **t_recv < last_timestamp - 1.0)
                            .map(|(k, v)| (*k, *v))
                    );

                    // post-processing reachability
                    let received_packets = prober_out
                        .entry((*rid, *prefix_ip))
                        .or_default()
                        .iter()
                        .filter(|(idx, _)| considered_prober_packets.contains_key(idx))
                        .collect_vec();

                    let prefix_handle = reachability_sample_data
                        .entry(prefix.to_string())
                        .or_default();
                    prefix_handle.insert(
                        rid.fmt(&analyzer.original_net).to_string(),
                        ViolationInfo::Time(
                            (considered_prober_packets.len() - received_packets.len()) as f64 / record.capture_frequency as f64,
                        ),
                    );
                    prefix_handles.push(prefix_handle);

                    if let Some(plot_dir) = plot_histogram_path {
                        // ensure the directory exists
                        fs::create_dir_all(plot_dir).unwrap();
                        let mut output = plot_dir.to_path_buf();
                        output.push(format!("histogram_reachability_{}_{scenario_name}.html", prefix.as_num()));

                        // Histogram plots for the counters
                        let mut plot = plotly::Plot::new();

                        let t_sent_vec = received_packets
                            .iter()
                            .map(|(_, (t_sent, _))| *t_sent - time_offset)
                            .collect_vec();
                        let t_min = t_sent_vec.iter().min_by(|a, b| a.total_cmp(b)).unwrap();
                        let _t_sent_normalized = t_sent_vec.iter().map(|x| x - t_min).collect_vec();

                        plot.add_trace(
                            plotly::Histogram::new(t_sent_vec)
                                .n_bins_x(10_000)
                            //plotly::Histogram::new(t_sent_normalized)
                                .name(format!("{}-{prefix:?}", rid.fmt(&analyzer.original_net))),
                        );

                        plot.write_html(output);

                        // Histogram plots for the paths taken
                        /*
                        let passed_links: BTreeMap<u64, Vec<(RouterId, RouterId)>> = BTreeMap::from_iter(link_tracking
                            .entry((*rid, *prefix_ip))
                            .or_default()
                            .iter()
                            .filter(|(idx, _)| considered_prober_packets.contains_key(idx))
                            .map(|(idx, link_counter)| (
                                    *idx,
                                    link_counter
                                        .iter()
                                        .filter(|(_, counter)| **counter > 0)
                                        .map(|(link, _)| *link)
                                        .sorted_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)))
                                        .collect_vec()
                                    )
                                )
                            );
                        for (path, times) in considered_prober_packets
                            .iter()
                            .map(|(idx, time_recv)| {
                                let path = passed_links
                                    .get(idx)
                                    .unwrap()
                                    .iter()
                                    .map(|(from, to)|
                                        format!(
                                            "({}, {})",
                                            from.fmt(&analyzer.original_net),
                                            to.fmt(&analyzer.original_net),
                                        )
                                    ).join(",");
                                (path, time_recv)
                            })
                            .sorted_by_key(|(path, _time)| path.clone())
                            .group_by(|(path, _time)| path.clone())
                            .into_iter()
                            .map(|(path, group)| (path, group.map(|(_path, time)| *time).collect_vec()))
                        {
                            // add a trace for each path, for this specific router-prefix pair
                            paths_histogram.add_trace(
                                plotly::Histogram::new(times)
                                    .name(format!("{}-{prefix:?}: {path}", rid.fmt(&analyzer.original_net)))
                                    // group all outgoing traffic from this router together
                                    .bin_group(rid.fmt(&analyzer.original_net)),
                            );
                        }
                        */

                        // compute path changes
                        let mut last = vec![];
                        for (idx, _t_recv) in considered_prober_packets.iter().sorted_by_key(|(idx, _t)| *idx) {
                            let path = path_tracking.get(&(*rid, *prefix_ip))
                                .and_then(|packet_path| packet_path.get(idx))
                                .cloned()
                                .unwrap_or(vec![]);
                            if *path != last {
                                last.clone_from(&path);
                                let t_sent = *prober_in.get(&(*rid, *prefix_ip)).unwrap().get(idx).unwrap();
                                path_update_times.push(PathRecord {
                                    time: t_sent + time_offset,
                                    src: *rid,
                                    src_name: Router::from_str(rid.fmt(&analyzer.original_net)).ok(),
                                    prefix: *prefix_ip,
                                    seq: Some(*idx),
                                    path_names: path.iter().map(|rid| Router::from_str(rid.fmt(&analyzer.original_net)).ok()).collect_vec(),
                                    path,
                                });
                            }
                        }

                        // compute reachability changes
                        let mut last = false;
                        for (idx, t_recv) in considered_prober_packets.iter().sorted_by(|(_, t1), (_, t2)| t1.total_cmp(t2)) {
                            let reachable = received_packets.iter().any(|(recv_idx, _)| *recv_idx == idx);
                            if reachable != last {
                                last = reachable;
                                reachability_update_times.push(DPRecord {
                                    time: *t_recv + time_offset,
                                    src: *rid,
                                    src_name: Router::from_str(rid.fmt(&analyzer.original_net)).ok(),
                                    prefix: *prefix_ip,
                                    reachable,
                                });
                            }
                        }

                        continue;
                    }

                    #[cfg(feature = "all-fw-properties")]
                    {
                        // post-processing loopfreedom
                        let idx_counters = node_tracking
                            .entry((*rid, *prefix_ip))
                            .or_default();
                        let looping_packets = idx_counters
                            .iter()
                            .filter(|(idx, _)| considered_prober_packets.contains_key(idx))
                            .filter(|(_, rid_counters)|
                                *rid_counters
                                    .values()
                                    .max()
                                    .unwrap() > 2
                                    )
                            .collect_vec();

                        let prefix_handle = loopfreedom_sample_data
                            .entry(prefix.to_string())
                            .or_default();
                        prefix_handle.insert(
                            rid.fmt(&analyzer.original_net).to_string(),
                            ViolationInfo::Time(
                                looping_packets.len() as f64 / record.capture_frequency as f64,
                            ),
                        );
                        prefix_handles.push(prefix_handle);


                        if !received_packets.is_empty() {
                            // post-processing stable_path
                            let first_packet = received_packets
                                            .iter()
                                            .sorted_by(|a, b| a.0.cmp(b.0))
                                            .next() // find first received packet
                                            .unwrap();
                            let last_packet = received_packets
                                            .iter()
                                            .sorted_by(|a, b| a.0.cmp(b.0))
                                            .last() // find last received packet
                                            .unwrap();

                            let passed_links: BTreeMap<u64, Vec<(RouterId, RouterId)>> = BTreeMap::from_iter(link_tracking
                                .entry((*rid, *prefix_ip))
                                .or_default()
                                .iter()
                                .filter(|(idx, _)| considered_prober_packets.contains_key(idx))
                                .map(|(idx, link_counter)| (
                                        *idx,
                                        link_counter
                                            .iter()
                                            .filter(|(_, counter)| **counter > 0)
                                            .map(|(link, _)| *link)
                                            .sorted_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)))
                                            .collect_vec()
                                        )
                                    )
                                );

                            // NOTE: assuming simple paths (represented as unordered sets of edges)
                            let first_path = passed_links.get(first_packet.0).unwrap();
                            let last_path = passed_links.get(last_packet.0).unwrap();

                            let received_packets_following_stable_path = received_packets
                                .iter()
                                .filter(|(idx, _)| {
                                    let path = passed_links.get(idx).unwrap();
                                    path == first_path || path == last_path
                                })
                                .collect_vec();

                            let prefix_handle = stable_path_sample_data
                                .entry(prefix.to_string())
                                .or_default();
                            prefix_handle.insert(
                                rid.fmt(&analyzer.original_net).to_string(),
                                ViolationInfo::Time(
                                    (received_packets.len() - received_packets_following_stable_path.len()) as f64 / record.capture_frequency as f64,
                                ),
                            );
                            prefix_handles.push(prefix_handle);

                            // add additional information to each of the violation_*.json files
                            // (except waypoints due to reference management issues)
                            for prefix_handle in prefix_handles.into_iter() {
                                prefix_handle.insert(
                                    format!("{}_ext_init", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::External(
                                        first_packet.1.1.fmt(&analyzer.original_net).to_string(),
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_ext_post", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::External(
                                        last_packet.1.1.fmt(&analyzer.original_net).to_string(),
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_links_init", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::Route(
                                        first_path
                                            .iter()
                                            .map(|(from, to)|
                                                format!("({}, {})",
                                                    from.fmt(&analyzer.original_net),
                                                    to.fmt(&analyzer.original_net),
                                                )
                                            ).collect_vec()
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_links_post", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::Route(
                                        last_path
                                            .iter()
                                            .map(|(from, to)|
                                                format!("({}, {})",
                                                    from.fmt(&analyzer.original_net),
                                                    to.fmt(&analyzer.original_net),
                                                )
                                            ).collect_vec()
                                    ),
                                );
                            }


                            // post-processing waypoint
                            let routers_first_path = first_path.iter().flat_map(|x| [x.0, x.1]).filter(|x| x != rid).unique().collect_vec();
                            let routers_last_path = last_path.iter().flat_map(|x| [x.0, x.1]).filter(|x| x != rid).unique().collect_vec();
                            // NOTE: potential waypoints may (and should) differ for different routers in the same sample!
                            let waypoints = routers_first_path.into_iter().filter(|x| routers_last_path.contains(x)).collect_vec();

                            for waypoint in waypoints {
                                // ensure that violation file gets created
                                let mut waypoint_violation_file_path = eval_path.clone();
                                waypoint_violation_file_path.push(&format!("violation_waypoint_{}.json", waypoint.fmt(&analyzer.original_net)));
                                waypoint_violation_file_paths.insert(waypoint, waypoint_violation_file_path);

                                let received_packets_passing_waypoint = received_packets
                                    .iter()
                                    .filter(|(idx, _)|
                                            (idx_counters.get(*idx).unwrap().contains_key(&waypoint)
                                                && *idx_counters.get(*idx).unwrap().get(&waypoint).unwrap() > 0)
                                            )
                                    .collect_vec();

                                let prefix_handle = waypoint_sample_data
                                    .entry(waypoint)
                                    .or_default()
                                    .entry(prefix.to_string())
                                    .or_default();
                                prefix_handle.insert(
                                    rid.fmt(&analyzer.original_net).to_string(),
                                    ViolationInfo::Time(
                                        (received_packets.len() - received_packets_passing_waypoint.len()) as f64 / record.capture_frequency as f64,
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_ext_init", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::External(
                                        first_packet.1.1.fmt(&analyzer.original_net).to_string(),
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_ext_post", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::External(
                                        last_packet.1.1.fmt(&analyzer.original_net).to_string(),
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_links_init", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::Route(
                                        first_path
                                            .iter()
                                            .map(|(from, to)|
                                                format!("({}, {})",
                                                    from.fmt(&analyzer.original_net),
                                                    to.fmt(&analyzer.original_net),
                                                )
                                            ).collect_vec()
                                    ),
                                );
                                prefix_handle.insert(
                                    format!("{}_links_post", rid.fmt(&analyzer.original_net)),
                                    ViolationInfo::Route(
                                        last_path
                                            .iter()
                                            .map(|(from, to)|
                                                format!("({}, {})",
                                                    from.fmt(&analyzer.original_net),
                                                    to.fmt(&analyzer.original_net),
                                                )
                                            ).collect_vec()
                                    ),
                                );
                            }
                        }
                    }
                }

                if let Some(_plot_dir) = plot_histogram_path {
                    /*
                    // plot paths histogram
                    let mut output = plot_dir.to_path_buf();
                    output.push(format!("histogram_paths_{scenario_name}.html"));

                    paths_histogram.write_html(output);
                    */

                    // store path changes as `PathRecord`s in a csv
                    let mut output_path = data_path.clone();
                    output_path.push(&format!("path_updates_{}.csv", record.pcap_filename,));
                    let mut csv = csv::WriterBuilder::new()
                        .has_headers(true)
                        .delimiter(b';')
                        .from_writer(
                            fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(&output_path)
                                .unwrap(),
                        );
                    for path_record in path_update_times.into_iter().sorted_by(|a, b| a.time.total_cmp(&b.time)) {
                        csv.serialize(path_record).unwrap();
                    }
                    csv.flush().unwrap();

                    // store reachability changes as `DPRecord`s in a csv
                    let mut output_path = data_path.clone();
                    output_path.push(&format!("dp_updates_{}.csv", record.pcap_filename,));
                    let mut csv = csv::WriterBuilder::new()
                        .has_headers(true)
                        .from_writer(
                            fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(&output_path)
                                .unwrap(),
                        );
                    for dp_record in reachability_update_times.into_iter().sorted_by(|a, b| a.time.total_cmp(&b.time)) {
                        csv.serialize(dp_record).unwrap();
                    }
                    csv.flush().unwrap();

                    // store forwarding changes as `FWRecord`s in a csv
                    let mut output_path = data_path.clone();
                    output_path.push(&format!("fw_updates_{}.csv", record.pcap_filename,));
                    let mut csv = csv::WriterBuilder::new()
                        .has_headers(true)
                        .from_writer(
                            fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(&output_path)
                                .unwrap(),
                        );
                    for fw_record in forwarding_update_times
                        .into_iter()
                        .sorted_by(|a, b| a.time.total_cmp(&b.time))
                    {
                        csv.serialize(fw_record).unwrap();
                    }
                    csv.flush().unwrap();

                    // can only plot histograms of one sample
                    //log::trace!("aborting after one sample as we are plotting histograms.");
                    //break 'samples;
                    forwarding_update_times = Vec::new();
                    path_update_times = Vec::new();
                    reachability_update_times = Vec::new();
                    continue 'samples;
                }

                reachability_violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: reachability_sample_data,
                });

                #[cfg(feature = "all-fw-properties")]
                loopfreedom_violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: loopfreedom_sample_data,
                });

                #[cfg(feature = "all-fw-properties")]
                stable_path_violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: stable_path_sample_data,
                });

                #[cfg(feature = "all-fw-properties")]
                for (waypoint, violation_times) in waypoint_sample_data.into_iter() {
                    waypoint_violation_times
                        .entry(waypoint)
                        .or_default()
                        .push(Sample {
                        sample_id: record.execution_timestamp.clone(),
                        violation_times,
                    });
                }

                // write out progress after processing each pcap
                // make sure to overwrite processed data only if we do not only produce the histogram
                if plot_histogram_path.is_none() {
                    // at this point we have a `Vec<Sample>` per property
                    fs::write(
                        &reachability_violation_file_path,
                        serde_json::to_string_pretty(&reachability_violation_times).unwrap(),
                    )
                    .unwrap();

                    #[cfg(feature = "all-fw-properties")]
                    fs::write(
                        &loopfreedom_violation_file_path,
                        serde_json::to_string_pretty(&loopfreedom_violation_times).unwrap(),
                    )
                    .unwrap();

                    #[cfg(feature = "all-fw-properties")]
                    fs::write(
                        &stable_path_violation_file_path,
                        serde_json::to_string_pretty(&stable_path_violation_times).unwrap(),
                    )
                    .unwrap();

                    #[cfg(feature = "all-fw-properties")]
                    for (waypoint, violation_times) in waypoint_violation_times.iter() {
                        fs::write(
                            waypoint_violation_file_paths.get(waypoint).unwrap(),
                            serde_json::to_string_pretty(&violation_times).unwrap(),
                        )
                        .unwrap();
                    }
                }
            }
        });

    Ok(())
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Overwrite the input path for data.
    //#[arg(short, long, default_value = "./data/")]
    #[arg(short, long, default_value = "./data_randomized10/")]
    data_root: String,
    /// Overwrite the topology filter for extracting BGP updates.
    #[arg(short, long, default_value = "Abilene")]
    topo: String,
    /// Overwrite the scenario filter for extracting BGP updates.
    #[arg(short, long, default_value = "")]
    scenario: String,
    /// Overwrite the scenario_end filter for extracting BGP updates.
    #[arg(short = 'e', long = "scenario-end", default_value = "")]
    scenario_end: String,
    /// Overwrite the scenario_end filter for extracting BGP updates.
    #[arg(short = 'i', long = "sample", default_value = "")]
    sample_id: String,
    /// Produce histograms instead of processing data. Store in the given locaion.
    #[arg(short = 'x', long = "histogram-path", default_value = None)]
    histogram_path: Option<String>,
}

#[tokio::main]
#[allow(unused)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    util::init_logging();

    let args = Args::parse();
    process_pcaps(
        args.data_root,
        Filter {
            topo: args.topo,
            scenario: args.scenario,
            scenario_end: args.scenario_end,
            sample_id: args.sample_id,
        },
        /*
        Filter {
            topo: "Abilene".to_string(),
            scenario: "Prefix1_PhysicalExternalWithdraw".to_string(),
            scenario_end: "".to_string(),
            sample_id: "".to_string(),
        },
        */
        args.histogram_path.map(PathBuf::from).as_deref(),
    )
    .await
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn pcap_processing() {
        util::init_logging();

        process_pcaps(
            "./src/test/pcap_processing/",
            Filter {
                topo: "Abilene".to_string(),
                scenario: "".to_string(),
                scenario_end: "".to_string(),
                sample_id: "".to_string(),
            },
            None,
        )
        .await
        .expect("Processing should pass withour errors.");
    }
}
