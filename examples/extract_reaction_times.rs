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
    collections::{HashMap, HashSet},
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use itertools::Itertools;
use mac_address::MacAddress;

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
    serde_generic_hashmap::SerializeHashmap,
    Prefix as P,
};
use bgpsim::prelude::*;

// pub use to keep dependencies working where stuff was originally defined in this file
pub use trix_utils::{bgp_utils::*, pcap_utils::process_scenarios, reaction_times::*};

#[allow(dead_code)]
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");
    fs::create_dir_all(tmp_pcap_dir)?;

    let filter_topo = "Path_";
    let filter_scenario = "LinkFailureAtR0Ext";
    let filter_scenario_not = "KeepOther";
    let filter_scenario_end = "";
    let filter_sample_id = "";

    let _ = process_scenarios(
        tmp_pcap_dir,
        filter_topo,
        filter_scenario,
        filter_scenario_not,
        filter_scenario_end,
        |topo_name, scenario_name, scenario_path, data_path, _csv| {
            let analyzer = deserialize_from_file(&scenario_path).unwrap();

            // path under which to place processed violation times
            let eval_root = "./data/";
            //let eval_root = "./";
            let mut eval_path = PathBuf::from(eval_root);
            eval_path.push(&topo_name);
            eval_path.push(&scenario_name);
            fs::create_dir_all(&eval_path).unwrap();

            let mut reaction_file_path = eval_path.clone();
            reaction_file_path.push("reaction_times.json");
            let mut cp_reaction_file_path = eval_path.clone();
            cp_reaction_file_path.push("cp_reaction_times.json");
            let mut dp_reaction_file_path = eval_path.clone();
            dp_reaction_file_path.push("dp_reaction_times.json");
            let mut last_dp_reaction_file_path = eval_path.clone();
            last_dp_reaction_file_path.push("last_dp_reaction_times.json");

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

            // reaction times based on #withdrawn, #announced, #peers, and prefix
            let mut reaction_times: ReactionTimesMap<P> = HashMap::new();

            // HashMap mapping message size, number of peers, and prefix to control plane reaction times
            let mut cp_reaction_times: CPReactionTimesMap<P> = HashMap::new();
            // HashMap mapping message size to last router's data plane reaction times
            let mut last_dp_reaction_times: LastDPReactionTimesMap = HashMap::new();
            let mut last_dp_reaction_dedup: HashMap<(String, Ipv4Addr, String), f64> =
                HashMap::new();
            // HashMap mapping message size to data plane reaction times
            let mut dp_reaction_times: DPReactionTimesMap = HashMap::new();
            let mut dp_reaction_dedup: HashSet<(String, Ipv4Addr, String)> = HashSet::new();

            #[cfg(feature = "incremental")]
            if reaction_file_path.exists() {
                let serialized_reaction_times = fs::read_to_string(&reaction_file_path).unwrap();
                reaction_times = serde_json::from_str(&serialized_reaction_times).unwrap();

                if cp_reaction_file_path.exists() {
                    let serialized_cp_reaction_times =
                        fs::read_to_string(&cp_reaction_file_path).unwrap();
                    cp_reaction_times =
                        serde_json::from_str(&serialized_cp_reaction_times).unwrap();
                }

                if last_dp_reaction_file_path.exists() {
                    let serialized_last_dp_reaction_times =
                        fs::read_to_string(&last_dp_reaction_file_path).unwrap();
                    last_dp_reaction_times =
                        serde_json::from_str(&serialized_last_dp_reaction_times).unwrap();
                }

                if dp_reaction_file_path.exists() {
                    let serialized_dp_reaction_times =
                        fs::read_to_string(&dp_reaction_file_path).unwrap();
                    dp_reaction_times =
                        serde_json::from_str(&serialized_dp_reaction_times).unwrap();
                }
            }

            for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                if !record.execution_timestamp.contains(filter_sample_id) {
                    log::trace!(
                        "skipping {} due to filter on sample_id...",
                        record.pcap_filename
                    );
                    continue;
                }

                /*
                #[cfg(feature = "incremental")]
                if reaction_times
                    .iter()
                    .any(|s| s.sample_id == record.execution_timestamp)
                {
                    log::trace!(
                        "skipping {} due to incremental processing...",
                        record.pcap_filename
                    );
                    continue;
                }
                */

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

                // extract event's starting time, using it as an offset so the trace starts at 0.0
                let _time_offset = record.event_start;

                // get probed_prefixes for optimization
                let mut prober_result_path = data_path.clone();
                prober_result_path.push(&record.prober_result_filename);
                // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`
                let capture_result = serde_json::from_str::<Vec<_>>(
                    &fs::read_to_string(prober_result_path).unwrap(),
                )
                .unwrap()
                .into_iter()
                .collect::<HashMap<(RouterId, P, Ipv4Addr), Vec<(f64, f64, RouterId, u64)>>>();
                let probed_prefixes = capture_result
                    .keys()
                    .map(|(_, prefix, _)| prefix)
                    .unique()
                    .collect_vec();
                log::trace!("probed_prefixes: {probed_prefixes:?}");

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = data_path.clone();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                let serialized_hardware_mapping =
                    fs::read_to_string(&hardware_mapping_path).unwrap();
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping).unwrap();

                // allows to get the `RouterId`, the router's BGP router-id, its local prober_src
                // and its MAC prefix (first 4 bytes of the MAC)
                let router_mapping: HashMap<String, Router> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        // external routers do not send prober packets
                        .filter(|(_, router)| !router.is_external)
                        .map(|(rid, router)| {
                            (
                                router.name.clone(),
                                Router {
                                    rid: *rid,
                                    ip: router.ipv4,
                                    prober_src_ip: router.prober_src_ip.unwrap(),
                                    mac_prefix: router.ifaces[0]
                                        .mac
                                        .unwrap()
                                        .to_string()
                                        .split(':')
                                        .take(4)
                                        .join(":"),
                                },
                            )
                        }),
                );

                // allows to get the `RouterId` and MAC addresses of all directly connected
                // neighboring routers
                let mac_towards_neighbor_mapping: HashMap<RouterId, Vec<(RouterId, MacAddress)>> =
                    HashMap::from_iter(
                        hardware_mapping
                            .iter()
                            // external routers do not send prober packets
                            .filter(|(_, router)| !router.is_external)
                            .map(|(rid, router)| {
                                (
                                    *rid,
                                    router
                                        .ifaces
                                        .iter()
                                        .filter_map(|iface| {
                                            iface.mac.as_ref().map(|mac| (iface.neighbor, *mac))
                                        })
                                        .collect_vec(),
                                )
                            }),
                    );

                // hashmap to store prefixes, allowing to fill the blanks for what tshark
                // recognizes as a TCP retransmission
                let mut lookup_prefixes = HashMap::new();

                let mut delayer_tracking = HashSet::new();

                // get all bgp messages
                #[rustfmt::skip]
                let prefilter_by_port = Command::new("tcpdump")
                    .args([
                        "-r", pcap_path.to_string_lossy().as_ref(),
                        "(port 179)",
                        "-w", "-",
                    ])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();

                #[rustfmt::skip]
                let bgp_announces = String::from_utf8_lossy(
                    &Command::new("tshark")
                        .args([
                            "-r", "-",
                            "-Y", "!bgp.type || bgp.type != 4",
                            "-T", "fields",
                            "-E", "separator=;",
                            "-e", "frame.time_epoch",
                            "-e", "ip.src",
                            "-e", "ip.dst",
                            "-e", "eth.src",
                            "-e", "eth.dst",
                            "-e", "tcp.seq",
                            "-e", "bgp.mp_reach_nlri_ipv4_prefix",
                        ])
                        .stdin(std::process::Stdio::from(prefilter_by_port.stdout.unwrap()))
                        .output()
                        .unwrap()
                        .stdout
                )
                    .split('\n')
                    .filter_map(|row| parse_bgp_message_with_delayers(row, &mut lookup_prefixes, &mut delayer_tracking).ok())
                    //.filter(|bgp_message| !bgp_message.prefixes.is_empty())
                    .collect_vec()
                    .into_iter()
                    .filter_map(|mut bgp_message| {
                        if let Some(prefixes) = lookup_prefixes.get(&(bgp_message.src_ip, bgp_message.dst_ip, bgp_message.tcp_seq)) {
                            bgp_message.prefixes.clone_from(prefixes);
                        }
                        if !bgp_message.prefixes.is_empty() {
                            Some(bgp_message)
                        } else {
                            None
                        }
                    })
                    .sorted_by(|a, b| a.timestamp.total_cmp(&b.timestamp))
                    .collect_vec();

                //log::debug!("announces: {bgp_announces:#?}");

                // hashmap to store prefixes, allowing to fill the blanks for what tshark
                // recognizes as a TCP retransmission
                let mut lookup_prefixes = HashMap::new();

                let mut delayer_tracking = HashSet::new();

                #[rustfmt::skip]
                let prefilter_by_port = Command::new("tcpdump")
                    .args([
                        "-r", pcap_path.to_string_lossy().as_ref(),
                        "(port 179)",
                        "-w", "-",
                    ])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();

                #[rustfmt::skip]
                let bgp_withdraws = String::from_utf8_lossy(
                    &Command::new("tshark")
                        .args([
                            "-r", "-",
                            "-Y", "!bgp.type || bgp.type != 4",
                            "-T", "fields",
                            "-E", "separator=;",
                            "-e", "frame.time_epoch",
                            "-e", "ip.src",
                            "-e", "ip.dst",
                            "-e", "eth.src",
                            "-e", "eth.dst",
                            "-e", "tcp.seq",
                            "-e", "bgp.mp_unreach_nlri_ipv4_prefix",
                        ])
                        .stdin(std::process::Stdio::from(prefilter_by_port.stdout.unwrap()))
                        .output()
                        .unwrap()
                        .stdout
                )
                    .split('\n')
                    .filter_map(|row| parse_bgp_message_with_delayers(row, &mut lookup_prefixes, &mut delayer_tracking).ok())
                    //.filter(|bgp_message| !bgp_message.prefixes.is_empty())
                    .collect_vec()
                    .into_iter()
                    .filter_map(|mut bgp_message| {
                        if let Some(prefixes) = lookup_prefixes.get(&(bgp_message.src_ip, bgp_message.dst_ip, bgp_message.tcp_seq)) {
                            bgp_message.prefixes.clone_from(prefixes);
                        }
                        if !bgp_message.prefixes.is_empty() {
                            Some(bgp_message)
                        } else {
                            None
                        }
                    })
                    .sorted_by(|a, b| a.timestamp.total_cmp(&b.timestamp))
                    .collect_vec();

                //log::debug!("withdraws: {bgp_withdraws:#?}");

                // identify routers' roles based on the number of routers
                let Some(first_router) = router_mapping.get("r0") else {
                    log::trace!("skipping because router 'r0' could not be found!");
                    continue;
                };
                log::trace!("first_router: {first_router:?}");
                let Some(last_router) = router_mapping.get(&format!(
                    "r{}",
                    analyzer.original_net.internal_routers().count() - 1
                )) else {
                    log::trace!(
                        "skipping because last router 'r{}' could not be found!",
                        analyzer.original_net.internal_routers().count() - 1
                    );
                    continue;
                };
                log::trace!("last_router: {last_router:?}");

                // TODO: the following selection of peers only works for the full mesh case
                let peers = router_mapping
                    .values()
                    .filter(|&Router { rid, .. }| *rid != last_router.rid)
                    .collect_vec();
                log::trace!("peers: {peers:#?}");

                // TODO: requires peers to be configured equivalently for every prefix
                // TODO: only gives current RIB out, i.e., before the convergence
                /*
                let bgp_state = analyzer.original_net.get_bgp_state(*analyzer.original_net.get_known_prefixes().next().unwrap());
                let peers2 = router_mapping
                    .iter()
                    .map(|(_, router)| router)
                    .filter(|(rid, _, _, _)| bgp_state.peers_outgoing(last_router.rid).contains(rid))
                    .collect_vec();
                log::debug!("peers2: {peers2:#?}");
                */

                // select messages caused by event and caused to resolve the routing
                // TODO: match according to event type
                let event_messages = bgp_withdraws;
                let resolution_messages = bgp_announces;

                // reset dp reaction deduplication hashsets for each sample
                last_dp_reaction_dedup.clear();
                dp_reaction_dedup.clear();

                let mut counter_sent = 0;
                let mut counter_recv = 0;
                for prefix in analyzer.original_net.get_known_prefixes() {
                    // get timestamp of bgp message received at the last router
                    let Some(notify_last) = event_messages.iter().find(|bgp_message| {
                        bgp_message.src_ip == first_router.ip
                            && bgp_message.dst_ip == last_router.ip
                            && bgp_message.dst_mac.starts_with(&last_router.mac_prefix)
                            && bgp_message.prefixes.contains(prefix)
                            && bgp_message.delivered
                    }) else {
                        log::error!("no match found for {:?} -> {:?}, dst mac {}, {prefix:?} in {event_messages:?}", first_router.ip, last_router.ip, last_router.mac_prefix);
                        continue;
                    };
                    log::trace!(
                        "found t_last: {:?} for prefix {prefix:?}",
                        notify_last.timestamp
                    );

                    // get timestamps of all responses sent out to the peers
                    let mut t_sent_to_peer = HashMap::new();
                    let mut cp_reactions = Vec::new();
                    for peer in peers.iter() {
                        let Some(notify_peer) = resolution_messages.iter().find(|bgp_message| {
                            bgp_message.timestamp >= notify_last.timestamp
                                && bgp_message.src_ip == last_router.ip
                                && bgp_message.dst_ip == peer.ip
                                && bgp_message.src_mac.starts_with(&last_router.mac_prefix)
                                && bgp_message.prefixes.contains(prefix)
                                && !bgp_message.delivered
                        }) else {
                            log::trace!(
                                "no match found for {:?} -> {:?} sent, dst mac {}, {prefix:?}",
                                last_router.ip,
                                peer.ip,
                                peer.mac_prefix
                            );
                            counter_sent += 1;
                            continue;
                        };
                        let _ = t_sent_to_peer.insert(peer, notify_peer.timestamp);
                        assert!(notify_peer.timestamp >= notify_last.timestamp);
                        let cp_reaction = notify_peer.timestamp - notify_last.timestamp;
                        cp_reactions.push(cp_reaction);
                        cp_reaction_times
                            .entry((notify_last.prefixes.len(), peers.len(), *prefix))
                            .or_default()
                            .push(cp_reaction);
                    }

                    // get dp reaction of last router
                    // allow prober packets to flow to any of the attached external routers
                    let mac_src_filter = hardware_mapping
                        .iter()
                        .filter(|(_, router)| router.is_external)
                        .flat_map(|(_, router)| {
                            router.ifaces.iter().filter_map(|iface| {
                                if iface.neighbor == last_router.rid {
                                    iface.neighbor_mac.as_ref()
                                } else {
                                    None
                                }
                            })
                        })
                        .join(" or ether src ");
                    let prober_src_ip = last_router.prober_src_ip;
                    let prefix_filter = notify_last
                        .prefixes
                        .iter()
                        .map(|prefix| prefix.to_string())
                        .join(" or dst net ");
                    // check if any of these prefixes was probed in the pcap
                    let dp_reaction = last_dp_reaction_dedup
                        .get(&(mac_src_filter.clone(), prober_src_ip, prefix_filter.clone()))
                        .cloned()
                        .or_else(|| {
                            if notify_last.prefixes.iter().filter(|prefix| probed_prefixes.contains(prefix)).collect_vec().is_empty() {
                                return None;
                            }
                            #[rustfmt::skip]
                            let tcpdump_filter = Command::new("tcpdump")
                                .args([
                                    "-r", pcap_path.to_string_lossy().as_ref(),
                                    &format!("((ether src {mac_src_filter}) and src {prober_src_ip} and (dst net {prefix_filter}))"),
                                    "-w", "-",
                                    "-c", "1",
                                ])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .spawn()
                                .unwrap();

                            #[rustfmt::skip]
                            let tshark = Command::new("tshark")
                                    .args([
                                        "-r", "-",
                                        "-T", "fields",
                                        "-e", "frame.time_epoch",
                                    ])
                                    .stdin(std::process::Stdio::from(tcpdump_filter.stdout.unwrap()))
                                    .output()
                                    .unwrap();
                            let dp_change_time: f64 = std::str::from_utf8(&tshark.stdout).unwrap().trim().parse().unwrap();
                            assert!(dp_change_time >= notify_last.timestamp);
                            let dp_reaction = dp_change_time - notify_last.timestamp;
                            last_dp_reaction_times.entry(notify_last.prefixes.len()).or_default().push(dp_reaction);
                            last_dp_reaction_dedup.insert((mac_src_filter.clone(), prober_src_ip, prefix_filter.clone()), dp_reaction);
                            Some(dp_reaction)
                        });
                    let min = cp_reactions.iter().copied().min_by(|a, b| a.total_cmp(b));
                    let max = cp_reactions.iter().copied().max_by(|a, b| a.total_cmp(b));
                    reaction_times
                        .entry((notify_last.prefixes.len(), 0, peers.len(), *prefix))
                        .or_default()
                        .push(ReactionTime {
                            first_cp_reaction: min,
                            last_cp_reaction: max,
                            cp_reaction_increment: min
                                .zip(max)
                                .map(|(min, max)| (max - min) / (peers.len() - 1) as f64),
                            dp_reaction,
                        });

                    // get timestamps of all responses received by the peers
                    for peer in peers.iter() {
                        let Some(notify_peer) = resolution_messages.iter().find(|bgp_message| {
                            bgp_message.src_ip == last_router.ip
                                && bgp_message.dst_ip == peer.ip
                                && bgp_message.dst_mac.starts_with(&peer.mac_prefix)
                                && bgp_message.prefixes.contains(prefix)
                                && bgp_message.delivered
                        }) else {
                            log::trace!(
                                "no match found for {:?} -> {:?} received, dst mac {}, {prefix:?}",
                                last_router.ip,
                                peer.ip,
                                peer.mac_prefix
                            );
                            counter_recv += 1;
                            continue;
                        };
                        log::trace!("{peer:?} found t_peer: {:.4?} for prefix {prefix:?} received after {:.4}s, traveled {:.4}s", notify_peer.timestamp, notify_peer.timestamp - notify_last.timestamp, notify_peer.timestamp - t_sent_to_peer.get(&peer).unwrap());

                        // get timestamps of peers' dp reactions
                        let (scheduled_ospf_state, ospf_dst) =
                            analyzer.scheduled_net.get_ospf_forwarding_state();
                        // allow prober packets to flow to any of the potential next hops
                        let next_hops = scheduled_ospf_state
                            .get_next_hops(peer.rid, *ospf_dst.get(&last_router.rid).unwrap());
                        log::trace!("peer: {peer:?} -> next hops: {next_hops:?}");
                        let mac_src_filter = mac_towards_neighbor_mapping
                            .get(&peer.rid)
                            .unwrap()
                            .iter()
                            .filter(|(neighbor, _)| next_hops.contains(neighbor))
                            .map(|(_, mac)| mac)
                            .join(" or ether src ");
                        let prober_src_ip = peer.prober_src_ip;
                        let prefix_filter = notify_peer
                            .prefixes
                            .iter()
                            .map(|prefix| prefix.to_string())
                            .join(" or dst net ");
                        // check if any of these prefixes was probed in the pcap
                        if !notify_peer
                            .prefixes
                            .iter()
                            .filter(|prefix| probed_prefixes.contains(prefix))
                            .collect_vec()
                            .is_empty()
                            && dp_reaction_dedup.insert((
                                mac_src_filter.clone(),
                                prober_src_ip,
                                prefix_filter.clone(),
                            ))
                        {
                            #[rustfmt::skip]
                            let tcpdump_filter = Command::new("tcpdump")
                                .args([
                                    "-r", pcap_path.to_string_lossy().as_ref(),
                                    &format!("((ether src {mac_src_filter}) and src {prober_src_ip} and (dst net {prefix_filter}))"),
                                    "-w", "-",
                                    "-c", "1",
                                ])
                                .stdout(std::process::Stdio::piped())
                                .stderr(std::process::Stdio::piped())
                                .spawn()
                                .unwrap();

                            #[rustfmt::skip]
                            let tshark = Command::new("tshark")
                                    .args([
                                        "-r", "-",
                                        "-T", "fields",
                                        "-E", "separator=;",
                                        "-e", "frame.time_epoch",
                                        "-e", "ip.dst",
                                    ])
                                    .stdin(std::process::Stdio::from(tcpdump_filter.stdout.unwrap()))
                                    .output()
                                    .unwrap();
                            let dp_change_raw = std::str::from_utf8(&tshark.stdout)
                                .unwrap()
                                .trim()
                                .split(';')
                                .collect_vec();
                            let dp_reaction: f64 =
                                dp_change_raw[0].parse::<f64>().unwrap() - notify_peer.timestamp;
                            let observed_prefix = dp_change_raw[1];
                            dp_reaction_times
                                .entry(notify_peer.prefixes.len())
                                .or_default()
                                .push(dp_reaction);
                            reaction_times
                                .entry((
                                    0,
                                    notify_peer.prefixes.len(),
                                    0,
                                    P::from(Ipv4Addr::from_str(observed_prefix).unwrap()),
                                ))
                                .or_default()
                                .push(ReactionTime {
                                    first_cp_reaction: None,
                                    last_cp_reaction: None,
                                    cp_reaction_increment: None,
                                    dp_reaction: Some(dp_reaction),
                                });
                        }
                    }
                }
                log::info!("{pcap_path:?}: missing {counter_sent} replies sent and {counter_recv} received by peers");

                // remove the unzipped pcap file again
                let _ = Command::new("rm")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();
            }

            // at this point we have a `HashMap<(usize, usize, usize, P), ReactionTime>`
            //
            fs::write(
                reaction_file_path,
                serde_json::to_string_pretty(&SerializeHashmap::from(reaction_times)).unwrap(),
            )
            .unwrap();

            // at this point we have a `HashMap<(usize, usize, P), Vec<f64>>`
            fs::write(
                cp_reaction_file_path,
                serde_json::to_string_pretty(&SerializeHashmap::from(cp_reaction_times)).unwrap(),
            )
            .unwrap();

            // at this point we have a `HashMap<usize, Vec<f64>>`
            fs::write(
                dp_reaction_file_path,
                serde_json::to_string_pretty(&SerializeHashmap::from(dp_reaction_times)).unwrap(),
            )
            .unwrap();

            // at this point we have a `HashMap<usize, Vec<f64>>`
            fs::write(
                last_dp_reaction_file_path,
                serde_json::to_string_pretty(&SerializeHashmap::from(last_dp_reaction_times))
                    .unwrap(),
            )
            .unwrap();
        },
    );

    Ok(())
}
