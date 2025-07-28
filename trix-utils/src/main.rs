use std::{
    collections::{HashMap, HashSet},
    fs,
    net::Ipv4Addr,
    path::Path,
    process::Command,
};

use clap::Parser;
use itertools::Itertools;

use bgpsim::prelude::*;
use router_lab::hardware_mapping::HardwareMapping;

use trix_utils::{
    bgp_utils::BGPFilter,
    pcap_utils::{process_pcaps, process_scenarios},
    reaction_times::*,
    serde::CiscoAnalyzerData,
};

type Prefix = Ipv4Prefix;

#[derive(Parser, Debug)]
#[command(author, version, about)] // get author/version information from Cargo.toml
struct Args {
    /// test
    tmp_pcap_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");

    let filter_topo = "Path_";
    let filter_scenario = "LinkFailureAtR0Ext";
    let filter_scenario_not = "KeepOther";
    let filter_scenario_end = "";
    let filter_sample_id = "";

    let _ = process_pcaps(
        tmp_pcap_dir,
        filter_topo,
        filter_scenario,
        filter_scenario_not,
        filter_scenario_end,
        |pcap_path| {
            println!("processing pcap {pcap_path:?}");
        },
    );

    let _ = process_scenarios(
        tmp_pcap_dir,
        filter_topo,
        filter_scenario,
        filter_scenario_not,
        filter_scenario_end,
        |_topo_name, _scenario_name, scenario_path, data_path, _csv| {
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
            let mut reaction_times: ReactionTimesMap<Prefix> = HashMap::new();

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

                // get probed_prefixes for optimization
                let mut prober_result_path = data_path.clone();
                prober_result_path.push(&record.prober_result_filename);
                // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`
                let capture_result = serde_json::from_str::<Vec<_>>(
                    &fs::read_to_string(prober_result_path).unwrap(),
                )
                .unwrap()
                .into_iter()
                .collect::<HashMap<(RouterId, Prefix, Ipv4Addr), Vec<(f64, f64, RouterId, u64)>>>();
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

                // hashmap to store prefixes, allowing to fill the blanks for what tshark
                // recognizes as a TCP retransmission
                let mut lookup_prefixes = HashMap::new();

                let mut delayer_tracking = HashSet::new();

                // get all bgp messages
                let bgp_announces = BGPFilter::Announcements
                    .filter_with_delayers::<Prefix>(
                        &pcap_path,
                        &mut lookup_prefixes,
                        &mut delayer_tracking,
                    )
                    //.filter(|bgp_message| !bgp_message.prefixes.is_empty())
                    .collect_vec()
                    .into_iter()
                    .filter_map(|mut bgp_message| {
                        if let Some(prefixes) = lookup_prefixes.get(&(
                            bgp_message.src_ip,
                            bgp_message.dst_ip,
                            bgp_message.tcp_seq,
                        )) {
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

                log::trace!("announces: {bgp_announces:#?}");

                // hashmap to store prefixes, allowing to fill the blanks for what tshark
                // recognizes as a TCP retransmission
                let mut lookup_prefixes = HashMap::new();

                let mut delayer_tracking = HashSet::new();

                let bgp_withdraws = BGPFilter::Withdraws
                    .filter_with_delayers::<Prefix>(
                        &pcap_path,
                        &mut lookup_prefixes,
                        &mut delayer_tracking,
                    )
                    //.filter(|bgp_message| !bgp_message.prefixes.is_empty())
                    .collect_vec()
                    .into_iter()
                    .filter_map(|mut bgp_message| {
                        if let Some(prefixes) = lookup_prefixes.get(&(
                            bgp_message.src_ip,
                            bgp_message.dst_ip,
                            bgp_message.tcp_seq,
                        )) {
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

                log::trace!("withdraws: {bgp_withdraws:#?}");

                // identify routers' roles based on the number of routers
                let Some(first_router) = router_mapping.get("r0") else {
                    log::trace!("skipping because router 'r0' could not be found!");
                    continue;
                };
                log::trace!("first_router: {first_router:?}");
                let Some(last_router) = router_mapping.iter().max_by_key(|(k, _)| *k).map(|x| x.1)
                else {
                    log::trace!("skipping because no router found!");
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

                for prefix in probed_prefixes.iter() {
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
                            continue;
                        };
                        let _ = t_sent_to_peer.insert(peer, notify_peer.timestamp);
                        assert!(notify_peer.timestamp >= notify_last.timestamp);
                        let cp_reaction = notify_peer.timestamp - notify_last.timestamp;
                        cp_reactions.push(cp_reaction);
                    }

                    let min = cp_reactions.iter().copied().min_by(|a, b| a.total_cmp(b));
                    let max = cp_reactions.iter().copied().max_by(|a, b| a.total_cmp(b));
                    reaction_times
                        .entry((notify_last.prefixes.len(), 0, peers.len(), **prefix))
                        .or_default()
                        .push(ReactionTime {
                            first_cp_reaction: min,
                            last_cp_reaction: max,
                            cp_reaction_increment: min
                                .zip(max)
                                .map(|(min, max)| (max - min) / (peers.len() - 1) as f64),
                            dp_reaction: None,
                        });
                }
            }
        },
    );

    Ok(())
}
