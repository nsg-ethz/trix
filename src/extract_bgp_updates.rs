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
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    str::FromStr,
};

use bgp_parser::{BgpIterator, Delayer, Watcher};
use bgpkit_parser::models::NetworkPrefix;
use clap::Parser;
use ipnet::IpNet;
use itertools::Itertools;
use mac_address::MacAddress;
use rayon::{iter::ParallelIterator, prelude::IntoParallelIterator};

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
    records::*,
    util::{self, get_num_prefixes},
};
use bgpsim::prelude::*;

mod visualize_bgp_updates;
use visualize_bgp_updates::visualize_bgp_updates;

mod bgp_parser;
mod time_series_of_fw_updates;

struct ExtractedMeasurement {
    scenario_name: String,
    root: PathBuf,
    timestamp: String,
    num_prefixes: usize,
    #[allow(dead_code)]
    updated: bool,
    t0: f64,
}

/// Extract BGP updates from the pcaps matching the given filter.
///
/// Beware: This functions requires processing the pcap (copy it to /tmp/pcaps, unzip, run a
/// tcpdump pipeline on it).
pub(crate) async fn extract_bgp_updates_to_csv(
    data_root: impl AsRef<Path>,
    filter: Filter,
    replace: bool,
) -> Result<Vec<ExtractedMeasurement>, Box<dyn std::error::Error>> {
    let data_root = data_root.as_ref();

    Ok(util::par_map_data(
        data_root,
        filter.clone(),
        #[allow(clippy::type_complexity)]
        move |topo_name, scenario_name, eval_path| -> Vec<ExtractedMeasurement> {
            // evaluate the data captured by the cisco_analyzer
            let mut analyzer_csv_path = eval_path.to_path_buf();
            analyzer_csv_path.push("cisco_analyzer.csv");
            if !analyzer_csv_path.exists() {
                log::trace!(
                    "Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet."
                );
                return vec![]; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }
            log::trace!("Loading: {topo_name}/{scenario_name}/cisco_analyzer.csv");
            let analyzer_csv = fs::File::open(analyzer_csv_path.clone()).unwrap();
            let mut csv = csv::Reader::from_reader(analyzer_csv);

            let mut results = Vec::new();

            'samples: for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                if !record.execution_timestamp.contains(&filter.sample_id) {
                    log::trace!(
                        "skipping {} due to filter on sample_id...",
                        record.pcap_filename
                    );
                    continue 'samples;
                }

                if record.packets_dropped != 0 {
                    log::error!(
                        "skipping {} due to {} packets dropped upon capture",
                        record.pcap_filename,
                        record.packets_dropped
                    );
                    continue 'samples;
                }

                // get output path and check if it exists already
                let mut output_root = data_root.to_path_buf();
                output_root.push(topo_name);
                output_root.push(scenario_name);
                fs::create_dir_all(output_root.clone()).unwrap();
                let mut output_path = output_root.clone();
                output_path.push(format!("bgp_updates_{}.csv", record.pcap_filename,));
                let mut skip_file = output_root.clone();
                skip_file.push(format!("bgp_updates_{}.skip", record.pcap_filename,));
                if (output_path.exists() || skip_file.exists()) && !replace {
                    log::trace!("skipping {output_path:?} as it has been processed already",);
                    results.push(ExtractedMeasurement {
                        scenario_name: format!("{topo_name}_{scenario_name}"),
                        root: eval_path.to_path_buf(),
                        timestamp: record.execution_timestamp.clone(),
                        num_prefixes: get_num_prefixes(scenario_name).unwrap(),
                        updated: false,
                        t0: record.event_start,
                    });
                    continue 'samples;
                }
                log::info!("Processing {output_path:?}");

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = eval_path.to_path_buf();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                let serialized_hardware_mapping =
                    fs::read_to_string(&hardware_mapping_path).unwrap();
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping).unwrap();

                // allows to get `Router`s based on their IP
                let ip_mapping: HashMap<Ipv4Addr, (RouterId, Router)> = HashMap::from_iter(
                    hardware_mapping.iter().flat_map(|(rid, router_mapping)| {
                        let router = Router::from_str(&router_mapping.name).unwrap();
                        [(router_mapping.ipv4, (*rid, router))].into_iter().chain(
                            router_mapping
                                .ifaces
                                .iter()
                                .map(move |iface| (iface.ipv4, (*rid, router))),
                        )
                    }),
                );

                // allows to get rids and `Router`s representing neighboring routers
                let mac_mapping: HashMap<MacAddress, (RouterId, Router)> = HashMap::from_iter(
                    hardware_mapping
                        .iter()
                        .filter(|(_, router)| !router.is_external)
                        .flat_map(|(rid, router)| {
                            router
                                .ifaces
                                .iter()
                                .filter(|iface| iface.neighbor_mac.is_some())
                                .flat_map(|iface| {
                                    [
                                        (
                                            // interfaces where the src_mac is None are external routers
                                            iface.mac.unwrap(),
                                            (*rid, Router::from_str(&router.name).unwrap()),
                                        ),
                                        (
                                            iface.neighbor_mac.unwrap(),
                                            (
                                                iface.neighbor,
                                                Router::from_str(&iface.neighbor_name).unwrap(),
                                            ),
                                        ),
                                    ]
                                    .into_iter()
                                })
                        }),
                );

                // prepare all watchers
                let mut watchers = Vec::new();
                for mapping in hardware_mapping.values() {
                    if mapping.is_external {
                        // external routers will be configured to be watched before the delayer
                        for iface in &mapping.ifaces {
                            // only add interfaces for which we actually have a mac address
                            if let Some(mac) = iface.mac {
                                watchers.push(Watcher::before(iface.ipv4, mac.bytes()));
                            }
                        }
                    } else {
                        // go through all interfaces
                        for iface in &mapping.ifaces {
                            let dst_mac = iface.mac.unwrap().bytes();
                            // check if the neighbor is an external router. If so, collect before
                            // the delayer and use the interface IP address. Otherwise, collect
                            // after the delayer and use the loopback address.
                            let (dst_ip, delayer) = if hardware_mapping
                                .get(&iface.neighbor)
                                .map(|x| x.is_external)
                                .unwrap_or(false)
                            {
                                // external
                                (iface.ipv4, Delayer::Before)
                            } else {
                                // internal
                                // TODO change to after, once we fixed the parsing pipeline.
                                (mapping.ipv4, Delayer::Before)
                            };
                            watchers.push(Watcher {
                                dst_ip,
                                dst_mac,
                                delayer,
                            });
                        }
                    }
                }

                // read pcap_path from the cisco_analyzer.csv
                let mut pcap_path = eval_path.to_path_buf();
                pcap_path.push(&record.pcap_filename);

                // generate the iterator
                let mut bgp_iter = BgpIterator::new(&pcap_path, watchers).unwrap();

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
                let mut error_occurred = false;

                for msg in bgp_iter.by_ref() {
                    let bgp_parser::Msg {
                        time,
                        src_mac,
                        dst_mac,
                        src_ip,
                        dst_ip,
                        msg,
                        ..
                    } = match msg {
                        Ok(msg) => msg,
                        Err(_) => {
                            // there was an error! in that case, we must mark this file as not-usable!
                            error_occurred = true;
                            break;
                        }
                    };

                    // resolve src, src_name, dst, dst_name
                    let src_rid_name = ip_mapping.get(&src_ip);
                    let src = src_rid_name.map(|(x, _)| *x);
                    let src_name = src_rid_name.map(|(_, x)| *x);

                    let dst_rid_name = ip_mapping.get(&dst_ip);
                    let dst = dst_rid_name.map(|(x, _)| *x);
                    let dst_name = dst_rid_name.map(|(_, x)| *x);

                    // resolve link attributes
                    let link_src_rid_name = mac_mapping.get(&src_mac);
                    let link_src = link_src_rid_name.map(|(x, _)| *x);
                    let link_src_name = link_src_rid_name.map(|(_, x)| *x);
                    let link_dst_rid_name = mac_mapping.get(&dst_mac);
                    let link_dst = link_dst_rid_name.map(|(x, _)| *x);
                    let link_dst_name = link_dst_rid_name.map(|(_, x)| *x);

                    let ipv4net = |p: &NetworkPrefix| match p.prefix {
                        IpNet::V4(ipv4_net) => Some(ipv4_net.addr()),
                        IpNet::V6(_) => None,
                    };
                    let ipv4addr = |a: IpAddr| match a {
                        IpAddr::V4(a) => Some(a),
                        IpAddr::V6(_) => None,
                    };

                    // extract the relevant information from the message
                    let unreach = msg
                        .attributes
                        .get_unreachable_nlri()
                        .map(|nlri| nlri.prefixes.iter())
                        .unwrap_or(msg.withdrawn_prefixes.iter())
                        .filter_map(ipv4net)
                        .collect();
                    let reach = msg
                        .attributes
                        .get_reachable_nlri()
                        .map(|nlri| nlri.prefixes.iter())
                        .unwrap_or(msg.announced_prefixes.iter())
                        .filter_map(ipv4net)
                        .collect::<Vec<_>>();
                    let path_length = msg.attributes.as_path().map(|x| x.route_len());
                    let next_hop = msg
                        .attributes
                        .get_reachable_nlri()
                        .and_then(|nlri| nlri.next_hop)
                        .map(|nh| nh.addr())
                        .or_else(|| msg.attributes.next_hop())
                        .and_then(ipv4addr);
                    let local_preference = msg.attributes.local_preference();

                    if !reach.is_empty(){
                        if path_length.is_none() {
                            log::warn!("BGP update from {src_name:?} ({src_ip}) to {dst_name:?} ({dst_ip}) has no as_path_len!\n  time: {time}\n  packet: {msg:#?}")
                        }
                        if next_hop.is_none() {
                            log::warn!("BGP update from {src_name:?} ({src_ip}) to {dst_name:?} ({dst_ip}) has no next_hop!\n  time: {time}\n  packet: {msg:#?}")
                        }
                    }

                    csv.serialize(Record {
                        time,
                        link_src,
                        link_dst,
                        src_mac,
                        dst_mac,
                        link_src_name,
                        link_dst_name,
                        unreach,
                        reach,
                        path_length,
                        next_hop,
                        local_preference,
                        src,
                        dst,
                        src_ip,
                        dst_ip,
                        src_name,
                        dst_name,
                    })
                    .unwrap();
                }

                csv.flush().unwrap();
                std::mem::drop(csv);

                // ensure that the buffers are not empty
                if bgp_iter.check_buffers().is_err() {
                    log::error!("Some messages remain unparsed!");
                    error_occurred = true;
                }

                // if there was any error, mark this file as incomplete
                if error_occurred {
                    log::error!("Ignoring the BGP messages of this message");
                    // delete the file
                    std::fs::remove_file(&output_path).unwrap();
                    // create a file to remember that we need to skip it
                    std::fs::write(&skip_file, b"skip").unwrap();
                }

                results.push(ExtractedMeasurement {
                    scenario_name: format!("{topo_name}_{scenario_name}"),
                    root: eval_path.to_path_buf(),
                    timestamp: record.execution_timestamp.clone(),
                    num_prefixes: get_num_prefixes(scenario_name).unwrap(),
                    updated: true,
                    t0: record.event_start,
                });
            }

            results
        },
    )
    .flatten()
    .collect::<Vec<_>>())
}

#[derive(Parser, Debug, Clone)]
#[command(about, long_about = None)]
struct Args {
    /// Overwrite the input path for data.
    #[arg(short, long, default_value = "./data/")]
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
    /// Overwrite the scenario_id filter for extracting BGP updates.
    #[arg(short = 'i', long = "sample", default_value = "")]
    sample_id: String,
    /// Replace all files, instead of skipping those that already exist
    #[arg(long)]
    replace: bool,
    /// directly show the plot
    #[arg(long)]
    show_plot: bool,
}

#[tokio::main]
#[allow(unused)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    util::init_logging();

    let args = Args::parse();

    let mut bgp_updates_csv = extract_bgp_updates_to_csv(
        args.data_root.clone(),
        Filter {
            topo: args.topo.clone(),
            scenario: args.scenario.clone(),
            scenario_end: args.scenario_end.clone(),
            sample_id: args.sample_id.clone(),
        },
        args.replace,
        /*
        Filter {
            topo: "Abilene".to_string(),
            scenario: "".to_string(),
            scenario_end: "ExtLosAngelesKansasCity_FullMesh_Prefix100000_PhysicalExternalUpdateAllWorseAtLosAngeles".to_string(),
            sample_id: "2024-10-19_12-04-38".to_string(),
        },
        */
    )
    .await?;

    let ts_updates_csv = time_series_of_fw_updates::run(&args)?;
    let updates = bgp_updates_csv
        .into_iter()
        .chain(ts_updates_csv)
        .unique_by(|m| format!("{}_{}", m.scenario_name, m.timestamp))
        .collect::<Vec<_>>();

    updates.into_par_iter().for_each(
        |ExtractedMeasurement {
             scenario_name,
             root,
             timestamp,
             num_prefixes,
             updated,
             t0,
         }| {
            if updated || args.replace {
                visualize_bgp_updates(
                    scenario_name,
                    root,
                    timestamp,
                    num_prefixes,
                    args.show_plot,
                    t0,
                )
                .unwrap();
            }
        },
    );

    Ok(())
}
