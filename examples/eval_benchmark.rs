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

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
};
use bgpsim::prelude::*;

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const EXTERNAL_ROUTER_MAC: &str = "08:c0:eb:6f:f5:26";
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");
    fs::create_dir_all(tmp_pcap_dir)?;

    for k in 2..=12 {
        // manually select a topo & scenario for benchmarking
        let filter_topo = &format!("Path_{k}");
        let scenario = "ExtAtEnds_FullMesh_Prefix1_WithdrawPrefix0AtR0_Delay10000";

        let topos = fs::read_dir("./experiments/").expect("./experiments/ cannot be read");
        for topo_dir in topos {
            let topo_path = topo_dir.unwrap().path();
            if !topo_path.to_string_lossy().contains(filter_topo) {
                continue;
            }

            let mut scenario_path = topo_path.clone();
            scenario_path.push(scenario);
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

            let data_root = "./benchmark/";
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

                log::debug!("unzipping...");
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
                let serialized_hardware_mapping = fs::read_to_string(&hardware_mapping_path)?;
                let hardware_mapping: HardwareMapping =
                    serde_json::from_str(&serialized_hardware_mapping)?;
                let neighbor_mapping: HashMap<(MacAddress, MacAddress, Ipv4Addr), _> =
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

                let mut delayer_tracking: HashMap<(RouterId, RouterId, Ipv4Addr, u64), (f64, u64)> =
                    HashMap::new();
                let mut observed_delays: Vec<f64> = Vec::new();

                let mut prober_init_counter: u64 = 0;
                let mut prober_peak_counter: u64 = 0;

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

                    if MacAddress::from(src_mac.octets())
                        == MacAddress::from_str(PROBER_SRC_MAC).unwrap()
                    {
                        prober_init_counter += 1;
                    }

                    // check if this packet is a measurement packet on its first hop
                    if let Some((rid, neighbor)) = neighbor_mapping.get(&(
                        MacAddress::from(src_mac.octets()),
                        MacAddress::from(dst_mac.octets()),
                        dst_ip,
                    )) {
                        if let Some((t_recv, count)) =
                            delayer_tracking.get_mut(&(*rid, *neighbor, src_ip, idx))
                        {
                            log::trace!(
                                "Delayed packet from {} to {}: {}ms",
                                rid.fmt(&analyzer.original_net),
                                neighbor.fmt(&analyzer.original_net),
                                time_received - *t_recv,
                            );
                            observed_delays.push(time_received - *t_recv);
                            *count += 1;
                        } else if MacAddress::from(src_mac.octets())
                            != MacAddress::from_str(PROBER_SRC_MAC).unwrap()
                            && MacAddress::from(dst_mac.octets())
                                != MacAddress::from_str(EXTERNAL_ROUTER_MAC).unwrap()
                        {
                            delayer_tracking
                                .insert((*rid, *neighbor, src_ip, idx), (time_received, 1));
                            if time_received > 3.0 && time_received < 4.0 {
                                prober_peak_counter += 1;
                            }
                        }
                    }
                }

                let prober_counter = delayer_tracking
                    .iter()
                    .filter(|(_, (t_recv, _count))| {
                        first_timestamp + 1.0 <= *t_recv && *t_recv < last_timestamp - 1.0
                    })
                    .count();
                let delayer_counter = delayer_tracking
                    .iter()
                    .filter(|(_, (t_recv, count))| {
                        first_timestamp + 1.0 <= *t_recv
                            && *t_recv < last_timestamp - 1.0
                            && *count > 1
                    })
                    .count();
                let loop_counter = delayer_tracking
                    .iter()
                    .filter(|(_, (t_recv, count))| {
                        first_timestamp + 1.0 <= *t_recv
                            && *t_recv < last_timestamp - 1.0
                            && *count > 2
                    })
                    .count();
                log::info!(
                    "{filter_topo} at capture_frequency = {}:",
                    record.capture_frequency,
                );
                println!("    - parsed {prober_counter} prober packets successfully.");
                println!("    - parsed {delayer_counter} delayed prober packets successfully.");
                println!("    - packets potentially looping: {loop_counter}.");
                println!(
                    "    - observed {} / {}pps (expected) peak load on the delayer.",
                    prober_peak_counter as f64,
                    (k - 1) * k * record.capture_frequency / 2,
                );
                println!("    - observed delays (expected 10ms = 0.0100).");
                println!(
                    "        min {:.4}s",
                    observed_delays
                        .iter()
                        .min_by(|a, b| a.total_cmp(b))
                        .unwrap(),
                );
                println!(
                    "        avg {:.4}s",
                    observed_delays.iter().sum::<f64>() / observed_delays.len() as f64,
                );
                println!(
                    "        med {:.4}s",
                    observed_delays
                        .iter()
                        .sorted_by(|a, b| a.total_cmp(b))
                        .nth(observed_delays.len() / 2)
                        .unwrap(),
                );
                println!(
                    "        max {:.4}s",
                    observed_delays
                        .iter()
                        .max_by(|a, b| a.total_cmp(b))
                        .unwrap(),
                );
                println!(
                    "    - observed {} / {}pps produced by the prober.",
                    prober_init_counter as f64 / (last_timestamp - first_timestamp),
                    k * record.capture_frequency,
                );

                // remove the unzipped pcap file again
                let _ = Command::new("rm")
                    .args([pcap_path.to_string_lossy().to_string()])
                    .output();
            }
        }
    }

    Ok(())
}
