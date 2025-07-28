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
    collections::HashMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use itertools::Itertools;
use mac_address::MacAddress;
use pcap_file::pcap::PcapReader;
use pnet_packet::{ethernet, ip, ipv4, Packet};
use rayon::prelude::*;

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
    Prefix as P,
};
use bgpsim::formatter::NetworkFormatter;
use bgpsim::prelude::*;

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const EXTERNAL_ROUTER_MAC: &str = "08:c0:eb:6f:f5:26";
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");
    fs::create_dir_all(tmp_pcap_dir)?;

    let filter_topo = "";
    let filter_scenario = "Delay10000";
    let filter_scenario_end = "";

    // get all (topo, scenario) combinations
    fs::read_dir("./experiments/")
        .expect("./experiments/ cannot be read")
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
                .filter(|(topo_path, scenario)|
                    topo_path
                        .display()
                        .to_string()
                        .contains(filter_topo)
                    && scenario.contains(filter_scenario)
                    && scenario.ends_with(filter_scenario_end)
                )
        })
        .unique()
        .collect_vec()
        .into_par_iter()
        //.into_iter()
        .for_each(|(topo_path, scenario)| {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");
            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }

            let analyzer = deserialize_from_file(&scenario_path).unwrap();

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = topo_path.file_name().unwrap();

            let data_root = "./data/";
            //let data_root = "/media/roschmi-data-hdd/orval-backup/data/";
            let mut data_path = PathBuf::from(data_root);
            data_path.push(format!("{}", topo_name.to_string_lossy()));
            data_path.push(format!("{}", scenario_name.to_string_lossy()));

            if !data_path.exists() {
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }

            // path under which to place processed violation times
            let eval_root = "./data/";
            let mut eval_path = PathBuf::from(eval_root);
            eval_path.push(format!("{}", topo_name.to_string_lossy()));
            eval_path.push(format!("{}", scenario_name.to_string_lossy()));
            fs::create_dir_all(&eval_path).unwrap();

            let mut reachability_violation_file_path = eval_path.clone();
            reachability_violation_file_path.push("violation_reachability.json");
            let mut loopfreedom_violation_file_path = eval_path.clone();
            loopfreedom_violation_file_path.push("violation_loopfreedom.json");
            let mut stable_path_violation_file_path = eval_path.clone();
            stable_path_violation_file_path.push("violation_stable_path.json");
            // add waypoint_violation_file_path later
            let mut waypoint_violation_file_paths: HashMap<RouterId, _> = HashMap::new();

            // evaluate the data captured by the cisco_analyzer
            let mut analyzer_csv_path = data_path.clone();
            analyzer_csv_path.push("cisco_analyzer.csv");
            if !analyzer_csv_path.exists() {
                log::trace!(
                    "Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet."
                );
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }
            log::info!("Loading: {scenario_path:?}");
            let analyzer_csv = fs::File::open(analyzer_csv_path).unwrap();
            let mut csv = csv::Reader::from_reader(analyzer_csv);

            let mut reachability_violation_times: Vec<Sample> = Vec::new();
            let mut loopfreedom_violation_times: Vec<Sample> = Vec::new();
            let mut stable_path_violation_times: Vec<Sample> = Vec::new();
            let mut waypoint_violation_times: HashMap<RouterId, Vec<Sample>> = HashMap::new();

            #[cfg(feature = "incremental")]
            if reachability_violation_file_path.exists() {
                let serialized_reachability_violation_times =
                    fs::read_to_string(&reachability_violation_file_path).unwrap();
                reachability_violation_times =
                    serde_json::from_str(&serialized_reachability_violation_times).unwrap();

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

            for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                #[cfg(feature = "incremental")]
                if reachability_violation_times.iter().any(|s| s.sample_id == record.execution_timestamp) {
                    log::trace!("skipping {} due to incremental processing...", record.pcap_filename);
                    continue;
                }

                assert!(record.packets_dropped == 0);

                let mut reachability_sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();
                let mut loopfreedom_sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();
                let mut stable_path_sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();
                let mut waypoint_sample_data: HashMap<RouterId, HashMap<String, HashMap<String, ViolationInfo>>> =
                    HashMap::new();

                // read orig_pcap_path from the cisco_analyzer.csv
                let mut orig_pcap_path = data_path.clone();
                orig_pcap_path.push(&record.pcap_filename);

                // set new location for faster unzip
                let mut pcap_path = tmp_pcap_dir.to_path_buf();
                pcap_path.push(&record.pcap_filename);

                // unzip the pcap file
                let _ = Command::new("cp")
                    .args([
                        &orig_pcap_path.to_string_lossy().to_string(),
                        &pcap_path.to_string_lossy().to_string(),
                    ])
                    .output();

                log::trace!("unzipping {pcap_path:?}");
                let _ = Command::new("gunzip")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();
                // drop the .gz part of the filename
                pcap_path.set_extension("");

                // extract event's starting time, using it as an offset so the trace starts at 0.0
                let time_offset = record.event_start;

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = data_path.clone();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                let serialized_hardware_mapping = fs::read_to_string(&hardware_mapping_path).unwrap();
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping).unwrap();
                let prober_ip_to_rid_mapping: HashMap<Ipv4Addr, RouterId> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        // external routers do not send prober packets
                        .filter(|(_, router)| !router.is_external)
                        .map(|(rid, router)| (router.prober_src_ip.unwrap(), *rid)),
                );
                let last_mac_to_ext_rid_mapping: HashMap<MacAddress, RouterId> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        // external routers do not send prober packets
                        .filter(|(_, router)| router.is_external)
                        .map(|(rid, router)| {
                            assert!(router.ifaces.len() == 1);
                            (router.ifaces[0].neighbor_mac.unwrap(), *rid)
                        }),
                );
                let neighbor_mapping: HashMap<(MacAddress, MacAddress), _> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        .filter(|(_, router)| !router.is_external)
                        .flat_map(|(rid, router)| {
                            router.ifaces.iter().map(|iface| {
                                (
                                    (
                                        // interfaces where the src_mac is None are external routers
                                        iface.mac.unwrap(),
                                        // interfaces where the dst_mac is None are connected to an
                                        // external router directly, i.e., forward to the destination
                                        iface
                                            .neighbor_mac
                                            .unwrap_or(MacAddress::from_str(EXTERNAL_ROUTER_MAC).unwrap()),
                                    ),
                                    (*rid, iface.neighbor),
                                )
                            })
                        }),
                );

                log::trace!("Neighbor Mapping:\n{neighbor_mapping:#?}");

                // read and process pcap file
                let file_in = fs::File::open(&pcap_path).expect("Error opening pcap file");
                let mut pcap_reader = PcapReader::new(file_in).unwrap();

                let mut packets = Vec::new();
                while let Some(next_packet) = pcap_reader.next_packet() {
                    // skip packets that cannot be parsed
                    let Ok(packet) = next_packet else {
                        continue;
                    };

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

                    packets.push((
                            packet.timestamp.as_secs_f64(),
                            time_received,
                            src_mac,
                            dst_mac,
                            src_ip,
                            dst_ip,
                            idx,
                        ));
                }

                // store for each prober packet when it was sent
                let mut prober_in: HashMap<(RouterId, Ipv4Addr), HashMap<u64, f64>> =
                    HashMap::new();
                // store for each prober packet when it reached which external router
                let mut prober_out: HashMap<(RouterId, Ipv4Addr), HashMap<u64, (f64, RouterId)>> =
                    HashMap::new();

                // rid, dst_ip -> prober_idx -> to_rid (on link) -> counter
                let mut node_tracking: HashMap<(RouterId, Ipv4Addr), HashMap<u64, HashMap<RouterId, u64>>> = HashMap::new();
                // rid, dst_ip -> prober_idx -> from_rid (on link), to_rid (on link) -> counter
                #[allow(clippy::type_complexity)]
                let mut link_tracking: HashMap<(RouterId, Ipv4Addr), HashMap<u64, HashMap<(RouterId, RouterId), u64>>> = HashMap::new();

                // from_rid (on link), to_rid (on link), src_ip, dst_ip, prober_idx -> t_recv_first, counter
                #[allow(clippy::type_complexity)]
                let mut delayer_tracking: HashMap<(RouterId, RouterId, Ipv4Addr, Ipv4Addr, u64), (f64, u64)> =
                    HashMap::new();

                let mut observed_delays: HashMap<(RouterId, RouterId), Vec<(f64, f64)>> = HashMap::new();

                let mut prober_init_counter: u64 = 0;

                let mut first_timestamp = f64::NAN;
                let mut last_timestamp = f64::NAN;

                // make sure packets are processed in chronological order
                for (timestamp, time_received, src_mac, dst_mac, src_ip, dst_ip, idx) in packets
                    .into_iter()
                    .sorted_by(|a, b| a.0.total_cmp(&b.0))
                {
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

                        if MacAddress::from(src_mac.octets()) == MacAddress::from_str(PROBER_SRC_MAC).unwrap() {
                            let duplicate = prober_in.entry((*rid, dst_ip))
                                .or_default()
                                .insert(idx, time_received);
                            assert!(duplicate.is_none());
                        }

                        if MacAddress::from(dst_mac.octets()) == MacAddress::from_str(EXTERNAL_ROUTER_MAC).unwrap() {
                            let duplicate = prober_out.entry((*rid, dst_ip))
                                .or_default()
                                .insert(idx, (timestamp, *last_mac_to_ext_rid_mapping.get(&MacAddress::from(src_mac.octets())).unwrap()));
                            assert!(duplicate.is_none());
                        }

                        if let Some((from_rid, to_rid)) =
                            neighbor_mapping.get(&(MacAddress::from(src_mac.octets()), MacAddress::from(dst_mac.octets())))
                        {
                            // loopfreedom tracking
                            {
                                // initialize node_tracking HashMap for the current packet flow if necessary
                                let packet_node = node_tracking.entry((*rid, *prefix)).or_default();
                                // initialize HashMap for the current packet if necessary
                                let node_idx_counter = packet_node.entry(idx).or_insert(HashMap::from([
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
                                        "Looped packet from {} to {} with id {idx} reaching {} (count: #{})",
                                        rid.fmt(&analyzer.original_net),
                                        prefix,
                                        to_rid.fmt(&analyzer.original_net),
                                        *counter / 2,
                                    );
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
                            }
                            // delayer tracking
                            // check that the measurement packet is not on its first or last hop
                            if MacAddress::from(src_mac.octets()) != MacAddress::from_str(PROBER_SRC_MAC).unwrap()
                                && MacAddress::from(dst_mac.octets()) != MacAddress::from_str(EXTERNAL_ROUTER_MAC).unwrap() {
                                if let Some((t_recv, counter)) = delayer_tracking.get_mut(&(*from_rid, *to_rid, src_ip, dst_ip, idx)) {
                                    *counter += 1;

                                    assert!(*t_recv <= timestamp);

                                    if *counter == 2 {
                                        observed_delays
                                            .entry((*from_rid, *to_rid))
                                            .or_default()
                                            .push((timestamp - *t_recv, *t_recv - time_offset));
                                    }
                                } else {
                                    delayer_tracking.insert((*from_rid, *to_rid, src_ip, dst_ip, idx), (timestamp, 1));
                                }
                            }
                        }
                    }
                }

                assert_eq!(prober_in.values().map(|idx_map| idx_map.len() as u64).sum::<u64>(), prober_init_counter);

                // check for delayer drops
                let prober_counter = delayer_tracking
                    .iter()
                    .filter(|(_, (t_recv, _))| first_timestamp + 1.0 <= *t_recv
                            && *t_recv < last_timestamp - 1.0)
                    .count();
                let delayer_counter = delayer_tracking
                    .iter()
                    .filter(|(_, (t_recv, count))| *count >= 2
                            && first_timestamp + 1.0 <= *t_recv
                            && *t_recv < last_timestamp - 1.0)
                    .count();
                let delayer_drops = prober_counter - delayer_counter;

                // check for inaccurate delay values
                let mut discard_sample_due_to_inaccurate_delays = false;
                for (_link, delays) in observed_delays.iter() {
                    log::debug!("...");
                    let sorted_delays = delays
                        .iter()
                        .filter(|x| first_timestamp + 1.0 <= x.1 && x.1 < last_timestamp - 1.0)
                        .map(|x| x.0)
                        .sorted_by(|a, b| a.total_cmp(b))
                        .collect_vec();
                    if !sorted_delays.is_empty() {
                        let med = sorted_delays[sorted_delays.len() / 2];
                        if sorted_delays[sorted_delays.len() / 100] < 0.8 * med
                            && sorted_delays[2 * sorted_delays.len() / 100] < 0.85 * med
                            && sorted_delays[10 * sorted_delays.len() / 100] < 0.9 * med
                            && sorted_delays[90 * sorted_delays.len() / 100] > 1.1 * med
                            && sorted_delays[98 * sorted_delays.len() / 100] > 1.15 * med
                            && sorted_delays[99 * sorted_delays.len() / 100] > 1.2 * med
                        {
                            log::trace!("discarding sample due to bad accuracy of the delayers (measured w.r.t. the median delay on the link)");
                            discard_sample_due_to_inaccurate_delays = true;
                            break;
                        }
                    }
                }

                assert!(!discard_sample_due_to_inaccurate_delays);

                if (delayer_drops > 0 || discard_sample_due_to_inaccurate_delays) && !scenario.contains("Delay0") {
                    continue; // skip sample due to imprecisions stemming from delayers
                }

                // post-processing reachability, loopfreedom, stable_path, and waypoint violations
                for ((rid, prefix_ip), idx_counters) in node_tracking.iter() {
                    let mut prefix_handles = Vec::new();

                    let prefix = P::from(*prefix_ip);

                    let considered_prober_packets: HashMap<u64, f64> = HashMap::from_iter(
                        prober_in
                            .entry((*rid, *prefix_ip))
                            .or_default()
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
                        .filter(|(_, (t_recv, ext))| {
                            analyzer
                                .event
                                .collector_filter(&record.event_start, prefix, t_recv, ext)
                        }).collect_vec();

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


                    // post-processing loopfreedom
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

                        let passed_links: HashMap<u64, Vec<(RouterId, RouterId)>> = HashMap::from_iter(link_tracking
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

                reachability_violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: reachability_sample_data,
                });

                loopfreedom_violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: loopfreedom_sample_data,
                });

                stable_path_violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: stable_path_sample_data,
                });

                for (waypoint, violation_times) in waypoint_sample_data.into_iter() {
                    waypoint_violation_times
                        .entry(waypoint)
                        .or_default()
                        .push(Sample {
                        sample_id: record.execution_timestamp.clone(),
                        violation_times,
                    });
                }

                // remove the unzipped pcap file again
                let _ = Command::new("rm")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();
            }

            // at this point we have a `Vec<Sample>` per property
            fs::write(
                reachability_violation_file_path,
                serde_json::to_string_pretty(&reachability_violation_times).unwrap(),
            )
            .unwrap();

            fs::write(
                loopfreedom_violation_file_path,
                serde_json::to_string_pretty(&loopfreedom_violation_times).unwrap(),
            )
            .unwrap();

            fs::write(
                stable_path_violation_file_path,
                serde_json::to_string_pretty(&stable_path_violation_times).unwrap(),
            )
            .unwrap();

            for (waypoint, violation_times) in waypoint_violation_times {
                fs::write(
                    waypoint_violation_file_paths.get(&waypoint).unwrap(),
                    serde_json::to_string_pretty(&violation_times).unwrap(),
                )
                .unwrap();
            }
        });

    Ok(())
}
