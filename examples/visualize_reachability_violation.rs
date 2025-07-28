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
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");
    fs::create_dir_all(tmp_pcap_dir)?;

    let filter_topo = "";
    let filter_scenario = "";
    let filter_scenario_end = "";
    let filter_sample_id = "";
    let filter_plot_tracename = "";

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

            'samples: for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                if !record.execution_timestamp.contains(filter_sample_id) {
                    log::trace!("skipping {} due to filter on sample_id...", record.pcap_filename);
                    continue;
                }

                assert!(record.packets_dropped == 0);

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

                if !pcap_path.exists() {
                    log::warn!("skipping: cannot find {pcap_path:?}, original: {orig_pcap_path:?}");
                    continue;
                }

                // extract event's starting time, using it as an offset so the trace starts at 0.0
                let time_offset = record.event_start;

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = data_path.clone();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                let serialized_hardware_mapping = fs::read_to_string(&hardware_mapping_path).unwrap();
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping).unwrap();

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

                log::trace!("Neighbor Mapping:\n{neighbor_mapping:#?}");

                // read and process pcap file
                let file_in = fs::File::open(&pcap_path).expect("Error opening pcap file");
                let mut pcap_reader = PcapReader::new(file_in).unwrap();

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

                // from_rid (on link), to_rid (on link), src_ip, dst_ip, prober_idx -> Vec<t_recv>
                let mut delayer_tracking: HashMap<(RouterId, RouterId, Ipv4Addr, Ipv4Addr, u64), Vec<f64>> =
                    HashMap::new();

                let mut prober_init_counter: u64 = 0;

                let mut first_timestamp = f64::NAN;
                let mut last_timestamp = f64::NAN;

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
                        } else if let Some((_from_rid, ext)) = last_mac_to_ext_rid_mapping.get(&MacAddress::from(src_mac.octets())) {
                            let _duplicate = prober_out.entry((*rid, dst_ip))
                                .or_default()
                                .insert(idx, (packet.timestamp.as_secs_f64(), *ext));
                            //assert!(duplicate.is_none());
                        } else if let Some((from_rid, to_rid)) = neighbor_mapping.get(&(MacAddress::from(src_mac.octets()), MacAddress::from(dst_mac.octets()))) {
                            // delayer tracking
                            // check that the measurement packet is not on its first or last hop
                            delayer_tracking
                                .entry((*from_rid, *to_rid, src_ip, dst_ip, idx))
                                .or_default()
                                .push(packet.timestamp.as_secs_f64());
                        }

                        // get `RouterId`s for internal and the last hop to external routers
                        if let Some((from_rid, to_rid)) = neighbor_mapping
                            .get(&(MacAddress::from(src_mac.octets()), MacAddress::from(dst_mac.octets())))
                            .or(last_mac_to_ext_rid_mapping.get(&MacAddress::from(src_mac.octets()))) {
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
                        }
                    }
                }

                assert_eq!(prober_in.values().map(|idx_map| idx_map.len() as u64).sum::<u64>(), prober_init_counter);

                if !scenario.contains("Delay0") {
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
                        log::error!("skip sample due to drops in the delayers\n  -> {scenario}\n  -> {orig_pcap_path:?}");
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
                                log::error!("discarding sample due to bad accuracy of the delayers (measured w.r.t. the median delay on the link)\n  -> {scenario}\n  -> {orig_pcap_path:?}");
                                continue 'samples;
                            }
                        }
                    }
                }

                // post-processing reachability, loopfreedom, stable_path, and waypoint violations
                let mut reachability_sample_data: HashMap<(RouterId, P), Vec<(f64, u64)>> =
                    HashMap::new();
                let mut loopfreedom_sample_data: HashMap<(RouterId, P), Vec<(f64, u64)>> =
                    HashMap::new();
                let mut stable_path_sample_data: HashMap<(RouterId, P), Vec<(f64, u64)>> =
                    HashMap::new();
                #[allow(clippy::type_complexity)]
                let mut waypoint_sample_data: HashMap<RouterId, HashMap<(RouterId, P), Vec<(f64, u64)>>> =
                    HashMap::new();

                let prober_flows = prober_in.keys().cloned().collect_vec();
                for (rid, prefix_ip) in prober_flows.iter() {
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

                    reachability_sample_data
                        .insert(
                            (*rid, prefix),
                            received_packets
                                .iter()
                                .map(|(idx, _)| {
                                    let t_sent = considered_prober_packets.get(*idx).unwrap();
                                    (*t_sent, **idx)
                                }).collect_vec(),
                        );

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

                    loopfreedom_sample_data
                        .insert(
                            (*rid, prefix),
                            looping_packets
                                .iter()
                                .map(|(idx, _)| {
                                    let t_sent = considered_prober_packets.get(*idx).unwrap();
                                    (*t_sent, **idx)
                                }).collect_vec(),
                        );

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

                        stable_path_sample_data
                            .insert(
                                (*rid, prefix),
                                received_packets_following_stable_path
                                    .iter()
                                    .map(|(idx, _)| {
                                        let t_sent = considered_prober_packets.get(*idx).unwrap();
                                        (*t_sent, **idx)
                                    }).collect_vec(),
                            );


                        // post-processing waypoint
                        let routers_first_path = first_path.iter().flat_map(|x| [x.0, x.1]).filter(|x| x != rid).unique().collect_vec();
                        let routers_last_path = last_path.iter().flat_map(|x| [x.0, x.1]).filter(|x| x != rid).unique().collect_vec();
                        // NOTE: potential waypoints may (and should) differ for different routers in the same sample!
                        let waypoints = routers_first_path.into_iter().filter(|x| routers_last_path.contains(x)).collect_vec();

                        for waypoint in waypoints {
                            let received_packets_passing_waypoint = received_packets
                                .iter()
                                .filter(|(idx, _)|
                                        (idx_counters.get(*idx).unwrap().contains_key(&waypoint)
                                            && *idx_counters.get(*idx).unwrap().get(&waypoint).unwrap() > 0)
                                        )
                                .collect_vec();

                            // TODO (received_packets.len() - received_packets_passing_waypoint.len()) as f64 / record.capture_frequency as f64,
                            waypoint_sample_data
                                .entry(waypoint)
                                .or_default()
                                .insert(
                                    (*rid, prefix),
                                    received_packets_passing_waypoint
                                        .iter()
                                        .map(|(idx, _)| {
                                            let t_sent = considered_prober_packets.get(*idx).unwrap();
                                            (*t_sent, **idx)
                                        }).collect_vec(),
                                );
                        }
                    }
                }

                plot_histogram(
                    topo_name,
                    &scenario,
                    &analyzer.original_net,
                    "reachability",
                    &record.execution_timestamp,
                    &reachability_sample_data,
                    filter_plot_tracename,
                );

                plot_histogram(
                    topo_name,
                    &scenario,
                    &analyzer.original_net,
                    "loopfreedom",
                    &record.execution_timestamp,
                    &loopfreedom_sample_data,
                    filter_plot_tracename,
                );

                plot_histogram(
                    topo_name,
                    &scenario,
                    &analyzer.original_net,
                    "stable_path",
                    &record.execution_timestamp,
                    &stable_path_sample_data,
                    filter_plot_tracename,
                );

                for (waypoint, sample_data) in waypoint_sample_data.into_iter() {
                    plot_histogram(
                        topo_name,
                        &scenario,
                        &analyzer.original_net,
                        &format!("waypoint_{}", waypoint.fmt(&analyzer.original_net)),
                        &record.execution_timestamp,
                        &sample_data,
                        filter_plot_tracename,
                    );
                }


                // remove the unzipped pcap file again
                let _ = Command::new("rm")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();
            }
        });

    Ok(())
}

fn plot_histogram<Q>(
    topo_name: &std::ffi::OsStr,
    scenario: &str,
    net: &Network<P, Q>,
    property_name: &str,
    sample_id: &str,
    sample_data: &HashMap<(RouterId, P), Vec<(f64, u64)>>,
    filter_plot_tracename: &str,
) where
    Q: bgpsim::event::EventQueue<P> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
{
    let plot_dir = format!("./plots/{property_name}/");
    log::trace!("ensuring directory {plot_dir:?} exists");
    fs::create_dir_all(&plot_dir).unwrap();

    // generate histogram plots of the packets validating the property
    let mut plot = plotly::Plot::new();

    for ((rid, prefix), packet_vec) in sample_data.iter() {
        let trace_name = format!("{}-{prefix:?}", rid.fmt(net));
        if trace_name.contains(filter_plot_tracename) {
            plot.add_trace(
                plotly::Histogram::new(packet_vec.iter().map(|(t_sent, _)| *t_sent).collect_vec())
                    .name(&trace_name),
            );
        }
    }

    log::debug!(
        "Plotting {plot_dir}/histogram_{}_{scenario}_{sample_id}.html",
        topo_name.to_string_lossy(),
    );
    plot.write_html(format!(
        "{plot_dir}/histogram_{}_{scenario}_{sample_id}.html",
        topo_name.to_string_lossy(),
    ));
}
