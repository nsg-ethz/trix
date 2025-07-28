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
    collections::{HashMap, HashSet},
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
    analyzer::{compute_equivalence_class, CiscoAnalyzerData, HardwareMapping},
    experiments::*,
    transient_specification::TransientPolicy,
    MultiPrefixConvergenceTrace, Prefix as P,
};
use bgpsim::{formatter::NetworkFormatter, policies::FwPolicy, prelude::*};

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";
pub const EXTERNAL_ROUTER_MAC: &str = "08:c0:eb:6f:f5:26";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");
    fs::create_dir_all(tmp_pcap_dir)?;

    let filter_topo = "Abilene";
    let filter_scenario = "";
    let filter_scenario_end =
        "ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles";

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
        // parallelize execution on a single topology/scenario instead!
        //.into_par_iter()
        .into_iter()
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

            //let data_root = "./data/";
            let data_root = "/media/roschmi-data-hdd/orval-backup/data/";
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

            let n_samples_hw = 10;
            let records: Vec<CiscoAnalyzerData> = csv.deserialize().map(|x| x.unwrap()).collect_vec();
            let selected_records = records.iter().rev().take(n_samples_hw).collect_vec();

            let equiv_classes: Vec<u64> = selected_records.into_par_iter().map(|record| {
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

                // TODO get a list of prefix/IP mapping from somewhere
                let prefixes = ScenarioPrefix::SinglePrefix.prefixes();
                // TODO match to the specific prefix
                let first_prefix = prefixes[0];

                // keep track of the current forwarding state to detect changes
                let mut old_fw_state = analyzer.original_fw.clone();
                let mut new_fw_state = analyzer.scheduled_fw.clone();
                // get the diff from after applying the event
                let diff = old_fw_state.diff(&new_fw_state);
                // revert updates that did not happen at an external router
                for (rid, old_nhs, _) in diff.get(&first_prefix).unwrap_or(&vec![]).iter() {
                    if !analyzer.original_net.get_device(*rid).unwrap().is_external() {
                        new_fw_state.update(*rid, first_prefix, old_nhs.clone());
                    }
                }
                let diff = old_fw_state.diff(&new_fw_state);

                // prepare the initial trace containing only the event's immediate changes
                let mut trace: MultiPrefixConvergenceTrace = HashMap::new();
                // add the cleaned diff to the trace
                trace
                    .entry(first_prefix)
                    .or_default()
                    .push((diff.get(&first_prefix).unwrap().clone(), Some(0.0).into()));
                old_fw_state = new_fw_state.clone();

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = data_path.clone();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                let serialized_hardware_mapping = fs::read_to_string(&hardware_mapping_path).unwrap();
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping).unwrap();
                let neighbor_mapping: HashMap<(MacAddress, MacAddress, Ipv4Addr, Ipv4Addr), _> =
                    HashMap::from_iter(
                        hardware_mapping
                            .iter()
                            // external routers do not matter for the forwarding_state
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
                                            // prober packet's source IP
                                            router
                                                .prober_src_ip
                                                .unwrap(), // should never be empty as we filter
                                                           // out external routers
                                                //.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
                                            // TODO: generalize for multi-prefix scenarios
                                            Ipv4Addr::new(100, 0, 0, 1),
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

                let mut delayer_tracking: HashMap<(RouterId, RouterId, u64), f64> = HashMap::new();

                // detect black holes by tracking whether packets on first hop appear in order
                let mut highest_idx: u64 = 0;
                // for each router and destination, store last idx and timestamp seen
                let mut last_probes: HashMap<(RouterId, P), (u64, f64)> = HashMap::new();

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

                    // only consider fw updates after the event was introduced
                    if time_received < 0.0 {
                        continue;
                    }

                    // check if this packet is a measurement packet on its first hop
                    if let Some((rid, neighbor)) =
                        neighbor_mapping.get(&(
                                MacAddress::from(src_mac.octets()),
                                MacAddress::from(dst_mac.octets()),
                                src_ip,
                                dst_ip)
                            )
                    {
                        if let Some(t_recv) = delayer_tracking.get(&(*rid, *neighbor, idx)) {
                            log::trace!(
                                "Delayed packet from {} to {}: {}ms",
                                rid.fmt(&analyzer.original_net),
                                neighbor.fmt(&analyzer.original_net),
                                time_received - t_recv,
                            );
                        } else {
                            delayer_tracking.insert((*rid, *neighbor, idx), time_received);
                            continue;
                        }

                        // detect black holes
                        if idx > highest_idx {
                            // allow to initialize with some value without assuming a black hole
                            if highest_idx > 0 {
                                // check whether all routers had seen a new packet
                                for ((rid, prefix), (last_idx, last_time_received)) in
                                    last_probes.iter()
                                {
                                    // if missing a probe and not already black hole
                                    if *last_idx < highest_idx && new_fw_state.get_next_hops(*rid, *prefix) != vec![] {
                                        log::trace!(
                                            "[{last_time_received:?}] update ({rid:?}, {}) -> BLACK HOLE",
                                            rid.fmt(&analyzer.original_net),
                                        );

                                        // update to black hole!
                                        // compute the forwarding deltas and update the trace
                                        new_fw_state.update(*rid, *prefix, vec![]);
                                        let diff = old_fw_state.diff(&new_fw_state);
                                        old_fw_state.update(*rid, *prefix, vec![]);
                                        // add the diff to the trace
                                        trace.entry(*prefix).or_default().push((
                                            diff.get(prefix).unwrap().clone(),
                                            Some(*last_time_received).into(),
                                        ));
                                    }
                                }
                            }

                            // update highest_idx
                            highest_idx = idx;
                        }

                        *last_probes.entry((*rid, first_prefix)).or_default() =
                            (idx, time_received);

                        let old_next_hops = new_fw_state.get_next_hops(*rid, first_prefix);
                        let next_hops = vec![*neighbor];
                        if old_next_hops != next_hops {
                            log::trace!(
                                "[{time_received:?}] update ({rid:?}, {}) -> ({neighbor:?}, {})",
                                rid.fmt(&analyzer.original_net),
                                neighbor.fmt(&analyzer.original_net)
                            );

                            // compute the forwarding deltas and update the trace
                            new_fw_state.update(*rid, first_prefix, next_hops.clone());
                            let diff = old_fw_state.diff(&new_fw_state);
                            old_fw_state.update(*rid, first_prefix, next_hops.clone());
                            // add the diff to the trace
                            trace.entry(first_prefix).or_default().push((
                                diff.get(&first_prefix).unwrap().clone(),
                                Some(time_received).into(),
                            ));
                        }
                    }
                }

                // remove the unzipped pcap file again
                let _ = Command::new("rm")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();

                // restore timely order after inserting the black hole states possibly slightly out
                // of order
                for (_, prefix_trace) in trace.iter_mut() {
                    prefix_trace.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                }
                log::debug!("convergence trace:\n{trace:#?}");

                for (_, prefix_trace) in trace.iter() {
                    for (fw_deltas, time) in prefix_trace.iter() {
                        log::trace!("At time {time:?}");
                        for (rid, old, new) in fw_deltas.iter() {
                            log::trace!(
                                "    {}: {:?} -> {:?}",
                                rid.fmt(&analyzer.original_net),
                                old.iter()
                                    .map(|r| r.fmt(&analyzer.original_net))
                                    .collect::<Vec<_>>(),
                                new.iter()
                                    .map(|r| r.fmt(&analyzer.original_net))
                                    .collect::<Vec<_>>()
                            );
                        }
                    }
                }

                // initialize required variables to call the interval algorithm
                //let mut fw_state = analyzer.original_fw.clone();
                let policies =
                    Vec::from_iter(analyzer.original_net.internal_routers().map(|r| {
                        TransientPolicy::Atomic(FwPolicy::Reachable(r.router_id(), first_prefix))
                    }));

                compute_equivalence_class(&trace, &analyzer.scheduled_fw, &policies)
            }).collect();

            // keep the number of explored fw time series after each sample
            let mut fw_series: HashSet<u64> = HashSet::new();
            let mut num_fw_series: Vec<usize> = vec![0];

            for eq_class in equiv_classes {
                fw_series.insert(eq_class);

                // track number of explored equivalence classes
                num_fw_series.push(fw_series.len());
            }

            log::info!("number of explored series of fw states:");
            println!("method num_samples num_explored");
            for (x, y) in num_fw_series.iter().enumerate() {
                println!("hw {x} {y}");
            }
        });

    Ok(())
}
