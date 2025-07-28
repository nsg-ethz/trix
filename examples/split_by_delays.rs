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
use core::str::FromStr;
use std::{
    borrow::Borrow, collections::HashMap, fs, net::Ipv4Addr, path::PathBuf, process::Command,
};

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
};
use bgpsim::prelude::*;

use mac_address::MacAddress;
use pcap_file::pcap::PcapReader;
use pnet_packet::{ethernet, ip, ipv4, Packet};

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const EXTERNAL_ROUTER_MAC: &str = "08:c0:eb:6f:f5:26";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    // get all scenario names from the topology
    let topos = fs::read_dir("./experiments/").expect("./experiments/ cannot be read");
    for topo_dir in topos {
        let topo_path = topo_dir.unwrap().path();

        if topo_path.to_string_lossy().to_string().contains("Abilene")
            || !topo_path.to_string_lossy().to_string().contains("Path_5")
        {
            log::trace!("skipping due to topo filter");
            continue;
        }

        let scenarios = fs::read_dir(topo_path.display().to_string()).unwrap();

        for scenario in scenarios
            .map(|s| {
                s.unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .filter(|s| !s.contains("_Delay"))
        {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");

            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                continue;
            }

            let analyzer = deserialize_from_file(&scenario_path)?;

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = scenario_path.parent().unwrap().file_name().unwrap();

            let data_root = "/mnt/roschmi-data/orval-backup/data/";
            let mut data_path = PathBuf::from(data_root);
            data_path.push(format!("{}", topo_name.to_string_lossy()));
            data_path.push(format!("{}", scenario_name.to_string_lossy()));

            // evaluate the data captured by the cisco_analyzer
            let mut analyzer_csv_path = data_path.clone();
            analyzer_csv_path.push("cisco_analyzer.csv");
            if !analyzer_csv_path.exists() {
                log::trace!(
                    "Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet."
                );
                continue;
            }
            log::info!("Loading: {scenario_path:?}");
            let analyzer_csv = fs::File::open(analyzer_csv_path)?;
            let mut csv = csv::Reader::from_reader(analyzer_csv);

            for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record?;

                // read pcap_path from the cisco_analyzer.csv
                let mut pcap_path = data_path.clone();
                pcap_path.push(&record.pcap_filename);
                let orig_pcap_path = pcap_path.clone();

                if !pcap_path.exists() {
                    log::trace!(
                        "skipping due to (already) missing pcap: {}",
                        pcap_path.to_string_lossy()
                    );
                    continue;
                }

                // unzip the pcap file
                let _ = Command::new("gunzip")
                    .args(["-k", pcap_path.to_string_lossy().as_ref()])
                    .output();
                // drop the .gz part of the filename
                pcap_path.set_extension("");

                // extract event's starting time, using it as an offset so the trace starts at 0.0
                let time_offset = record.event_start;

                // TODO get a list of prefix/IP mapping from somewhere
                let prefixes = ScenarioPrefix::SinglePrefix.prefixes();
                // TODO match to the specific prefix
                let _first_prefix = prefixes[0];

                // read hardware mapping and compose packet filter / map to forwarding updates for
                // prober packets
                let mut hardware_mapping_path = data_path.clone();
                hardware_mapping_path.push(&record.hardware_mapping_filename);
                let serialized_hardware_mapping = fs::read_to_string(&hardware_mapping_path)?;
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping)?;
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
                                            iface.neighbor_mac.unwrap_or(
                                                MacAddress::from_str(EXTERNAL_ROUTER_MAC).unwrap(),
                                            ),
                                            // prober packet's source IP
                                            router
                                                .prober_src_ip
                                                .unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
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
                let mut delays = Vec::new();

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
                    if let Some((rid, neighbor)) = neighbor_mapping.get(&(
                        MacAddress::from(src_mac.octets()),
                        MacAddress::from(dst_mac.octets()),
                        src_ip,
                        dst_ip,
                    )) {
                        if let Some(t_recv) = delayer_tracking.get(&(*rid, *neighbor, idx)) {
                            log::trace!(
                                "Delayed packet from {} to {}: {}ms",
                                rid.fmt(&analyzer.original_net),
                                neighbor.fmt(&analyzer.original_net),
                                (time_received - t_recv) * 1000.0,
                            );
                            delays.push((time_received - t_recv) * 1000.0);
                            if delays.len() >= 10_000 {
                                break;
                            }
                        } else {
                            delayer_tracking.insert((*rid, *neighbor, idx), time_received);
                            continue;
                        }

                        if MacAddress::from(dst_mac.octets())
                            != MacAddress::from_str(EXTERNAL_ROUTER_MAC).unwrap()
                        {
                            // first (undelayed) packet
                        }
                    }
                }

                // zip the pcap file again
                let _ = Command::new("rm")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();

                delays.sort_by(|a, b| a.partial_cmp(b).unwrap());

                if delays.is_empty() {
                    log::warn!(
                        "skipping due to empty delays vector: {}",
                        pcap_path.to_string_lossy()
                    );
                    continue;
                }

                let median_delay = delays[delays.len() / 2];
                let delay = if median_delay < 4.0 {
                    3000
                } else if median_delay < 7.5 {
                    5000
                } else if median_delay < 12.5 {
                    10000
                } else {
                    log::warn!("Found median delay of {median_delay}!");
                    0
                };

                // log some delay distribution stats if spread is large
                if delays[9 * delays.len() / 10] - delays[delays.len() / 10] > 1.0 {
                    log::debug!(
                        "Found min: {}, 10%: {}, 25%: {}, median: {}, 75%: {}, 90%: {}, max: {}",
                        delays[0],                     //  0%
                        delays[delays.len() / 10],     // 10%
                        delays[delays.len() / 4],      // 25%
                        median_delay,                  // 50%
                        delays[3 * delays.len() / 4],  // 75%
                        delays[9 * delays.len() / 10], // 90%
                        delays[delays.len() - 1],      //100%
                    );
                }

                let mut new_data_path = data_path.clone();
                new_data_path.pop();
                new_data_path.push(format!("{}_Delay{delay}", scenario_name.to_string_lossy()));
                std::fs::create_dir_all(&new_data_path)?;

                let mut prober_result_path = data_path.clone();
                prober_result_path.push(&record.prober_result_filename);

                // move pcap, hw_mapping, and prober file to the correct directory and append
                // record to the cisco_analyzer.csv
                log::trace!(
                    "Running: mv -t {} {} {} {}",
                    new_data_path.to_string_lossy().to_string(),
                    orig_pcap_path.to_string_lossy().to_string(),
                    hardware_mapping_path.to_string_lossy().to_string(),
                    prober_result_path.to_string_lossy().to_string(),
                );
                let _ = Command::new("mv")
                    .args([
                        "-t",
                        new_data_path.to_string_lossy().as_ref(),
                        orig_pcap_path.to_string_lossy().as_ref(),
                        hardware_mapping_path.to_string_lossy().as_ref(),
                        prober_result_path.to_string_lossy().as_ref(),
                    ])
                    .output();

                let mut new_analyzer_csv_path = new_data_path.clone();
                new_analyzer_csv_path.push("cisco_analyzer.csv");

                log::trace!(
                    "And writing record to {}",
                    new_analyzer_csv_path.to_string_lossy().to_string()
                );

                let mut new_csv = csv::WriterBuilder::new()
                    .has_headers(
                        !new_analyzer_csv_path.exists()
                            || fs::metadata(&new_analyzer_csv_path)?.len() == 0,
                    )
                    .from_writer(
                        fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .truncate(false)
                            .open(&new_analyzer_csv_path)?,
                    );
                new_csv.serialize(record)?;
            }
        }
    }

    Ok(())
}
