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
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rayon::prelude::*;

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::*,
    prelude::*,
};

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const EXTERNAL_ROUTER_MAC: &str = "08:c0:eb:6f:f5:26";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let tmp_pcap_dir = Path::new("/tmp/pcaps/");
    fs::create_dir_all(tmp_pcap_dir)?;

    // get all scenario names from the topology
    let topos = fs::read_dir("./experiments/").expect("./experiments/ cannot be read");
    for topo_dir in topos {
        let topo_path = topo_dir.unwrap().path();

        if topo_path.to_string_lossy().to_string().contains("Abilene") {
            log::trace!("skipping due to topo filter");
            continue;
        }

        log::trace!("running pipeline for topo {}", topo_path.to_string_lossy());

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
            .filter(|s| s.contains("Withdraw"))
        {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");

            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                continue;
            }

            log::trace!("  - scenario {scenario}");

            let analyzer = deserialize_from_file(&scenario_path)?;

            match &analyzer.event {
                AnalyzerEvent::AnnounceRoutingInputs(event_inputs)
                | AnalyzerEvent::WithdrawRoutingInputs(event_inputs) => {
                    // get the correct output folder name
                    scenario_path.pop(); // remove "scenario.json"
                    let scenario_name = scenario_path.file_name().unwrap();
                    let topo_name = scenario_path.parent().unwrap().file_name().unwrap();

                    let data_root = "/mnt/roschmi-data/orval-backup/data/";
                    //let data_root = "./data/";
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

                    let mut new_analyzer_csv_path = data_path.clone();
                    new_analyzer_csv_path.push("cisco_analyzer_fixed.csv");

                    if new_analyzer_csv_path.exists() {
                        log::trace!("Skipping because this csv has already been processed.");
                        continue;
                    }

                    log::debug!(
                        "Writing fixed records to {}",
                        new_analyzer_csv_path.to_string_lossy().to_string()
                    );

                    let new_records = csv
                        .deserialize()
                        .map(|record| record.expect("error parsing record from csv"))
                        .collect::<Vec<CiscoAnalyzerData>>()
                        .into_par_iter()
                        .map(|mut record| {
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

                            if !pcap_path.exists() {
                                log::trace!(
                                    "skipping due to missing pcap: {}",
                                    pcap_path.to_string_lossy()
                                );
                                return record;
                            }

                            // read hardware mapping and compose packet filter
                            let mut hardware_mapping_path = data_path.clone();
                            hardware_mapping_path.push(&record.hardware_mapping_filename);
                            let serialized_hardware_mapping =
                                fs::read_to_string(&hardware_mapping_path)
                                    .expect("problem reading hw mapping");
                            let hardware_mapping: HardwareMapping =
                                serde_json::from_str(&serialized_hardware_mapping)
                                    .expect("problem parsing hw mapping");

                            // extract the event's correct starting time, using it as an offset so the trace starts at 0.0
                            log::debug!("stored event_start: {}", record.event_start);

                            // set up filter for non-keepalive (85 bytes) BGP packets, add a
                            // null-statement in front to append all neighbors afterwards as a
                            // disjunction
                            let mut filter =
                                String::from("port 179 and len > 85 and ((port 1 and port 2)");

                            for ext in event_inputs.external_routers().iter().map(|(rid, _)| rid) {
                                for iface in hardware_mapping[ext].ifaces.iter() {
                                    filter.push_str(&format!(
                                        " or (src {} and dst {})",
                                        iface.ipv4, iface.neighbor_ip
                                    ));
                                }
                            }

                            filter.push(')');

                            // get the alternate event_start from the pcap
                            let tcpdump = Command::new("tcpdump")
                                .args([
                                    "-r",
                                    pcap_path.to_string_lossy().as_ref(),
                                    "-w",
                                    "-",
                                    &filter,
                                ])
                                .stdout(Stdio::piped())
                                .spawn()
                                .expect("problem spawning tcpdump");
                            let tshark = Command::new("tshark")
                                .args([
                                    "-r",
                                    "-",
                                    "-Y",
                                    "bgp.type != 4",
                                    "-c1",
                                    "-T",
                                    "fields",
                                    "-e",
                                    "frame.time_epoch",
                                ])
                                .stdin(Stdio::from(tcpdump.stdout.unwrap()))
                                .stdout(Stdio::piped())
                                .spawn()
                                .expect("problem spawning tshark");
                            let output = tshark.wait_with_output().expect("problem executing pipe");

                            record.event_start = std::str::from_utf8(&output.stdout)
                                .expect("problem decoding from utf8")
                                .trim()
                                .parse()
                                .expect("problem parsing float");
                            log::info!(
                                "Computing alternate event_start from pcap: {}",
                                record.event_start
                            );

                            // remove the unzipped pcap file again
                            let _ = Command::new("rm")
                                .args([pcap_path.to_string_lossy().to_string()])
                                .output();

                            record
                        })
                        .collect::<Vec<_>>();

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

                    for record in new_records {
                        // write fixed records to cisco_analyzer_fixed.csv
                        new_csv
                            .serialize(record)
                            .expect("problem serializing final record");
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}
