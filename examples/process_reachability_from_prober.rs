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
use std::{collections::HashMap, fs, net::Ipv4Addr, path::PathBuf};

use itertools::Itertools;
use rayon::prelude::*;

use trix::{analyzer::CiscoAnalyzerData, experiments::*, Prefix as P};
use bgpsim::formatter::NetworkFormatter;
use bgpsim::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    // get all (topo, scenario) combinations
    fs::read_dir("./experiments/")
        .unwrap()
        .flat_map(|topo_dir| {
            let topo_path = topo_dir.unwrap().path();

            fs::read_dir(
                topo_path.display().to_string()
            )
            .unwrap()
            .map(move |scenario_dir| (
                topo_path.clone(),
                scenario_dir.unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
                ))
        })
        .unique()
        .collect_vec()
        .into_par_iter()
        .for_each(|(topo_path, scenario)|
    {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");

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

            let mut violation_file_path = eval_path.clone();
            violation_file_path.push("violation_reachability.json");

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

            let mut violation_times: Vec<Sample> = Vec::new();

            for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                assert!(record.packets_dropped == 0);

                let mut sample_data: HashMap<String, HashMap<String, ViolationInfo>> =
                    HashMap::new();

                // read stuff from the cisco_analyzer.csv
                let mut prober_result_path = data_path.clone();
                prober_result_path.push(&record.prober_result_filename);
                // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`
                let capture_result = serde_json::from_str::<Vec<_>>(&fs::read_to_string(
                    prober_result_path,
                ).unwrap()).unwrap()
                .into_iter()
                .collect::<HashMap<(RouterId, P, Ipv4Addr), Vec<(f64, f64, RouterId, u64)>>>();

                for ((rid, prefix, _), samples) in capture_result
                    .iter()
                    // sort by prefix, router id
                    .sorted_by(|((r1, p1, _), _), ((r2, p2, _), _)| p1.cmp(p2).then(r1.cmp(r2)))
                {
                    let len = samples
                        .iter()
                        .filter(|(_, t_rx, ext, _)| {
                            analyzer
                                .event
                                .collector_filter(&record.event_start, *prefix, t_rx, ext)
                        })
                        .count();

                    log::trace!(
                        "Discarding {} samples happening after the event_start for router {}",
                        samples.len() - len,
                        rid.fmt(&analyzer.original_net)
                    );

                    if samples.len() - len > 100 {
                        log::error!(
                            "Discarding {} samples happening after the event_start for router {} and prefix {prefix:?}",
                            samples.len() - len,
                            rid.fmt(&analyzer.original_net)
                        );
                        log::debug!(
                            "First and last 10 discarded packets:\n{:#?}\n\n...\n\n{:#?}",
                            samples
                                .iter()
                                .filter(|(_, t_rx, ext, _)| {
                                    analyzer.event.collector_filter(
                                        &record.event_start,
                                        *prefix,
                                        t_rx,
                                        ext,
                                    )
                                })
                                .take(10)
                                .map(|(a, b, ext, d)| (a, b, ext.fmt(&analyzer.original_net), d))
                                .collect_vec(),
                            samples
                                .iter()
                                .filter(|(_, t_rx, ext, _)| {
                                    analyzer.event.collector_filter(
                                        &record.event_start,
                                        *prefix,
                                        t_rx,
                                        ext,
                                    )
                                })
                                .rev()
                                .take(10)
                                .map(|(a, b, ext, d)| (a, b, ext.fmt(&analyzer.original_net), d))
                                .collect::<Vec<_>>()
                                .iter()
                                .rev()
                                .collect_vec(),
                        );
                        //todo!("fix that more than 100 packets are being discarded!");
                    }

                    let total_num_samples = (samples.iter().map(|x| x.3).max().unwrap_or(0)
                        - samples.iter().map(|x| x.3).min().unwrap_or(0))
                        as usize
                        + 1;
                    log::debug!(
                        "{}: violation {} on prefix {prefix:?}",
                        rid.fmt(&analyzer.original_net),
                        (total_num_samples - len) as f64 / record.capture_frequency as f64,
                    );
                    let prefix_handle = sample_data
                        .entry(prefix.to_string())
                        .or_default();
                    prefix_handle.insert(
                        rid.fmt(&analyzer.original_net).to_string(),
                        ViolationInfo::Time(
                            (total_num_samples - len) as f64 / record.capture_frequency as f64,
                        ),
                    );
                    if !samples.is_empty() {
                        prefix_handle.insert(
                            format!("{}_ext_init", rid.fmt(&analyzer.original_net)),
                            ViolationInfo::External(
                                samples[0].2.fmt(&analyzer.original_net).to_string(),
                            ),
                        );
                        prefix_handle.insert(
                            format!("{}_ext_post", rid.fmt(&analyzer.original_net)),
                            ViolationInfo::External(
                                samples[samples.len() - 1]
                                    .2
                                    .fmt(&analyzer.original_net)
                                    .to_string(),
                            ),
                        );
                    }
                }

                violation_times.push(Sample {
                    sample_id: record.execution_timestamp.clone(),
                    violation_times: sample_data,
                });
            }

            // at this point we have a `Vec<Sample>`
            fs::write(
                violation_file_path,
                serde_json::to_string_pretty(&violation_times).unwrap(),
            ).unwrap();
    });

    Ok(())
}
