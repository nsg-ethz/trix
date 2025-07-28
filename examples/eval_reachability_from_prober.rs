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

use trix::{analyzer::CiscoAnalyzerData, experiments::*, Prefix as P};
use bgpsim::formatter::NetworkFormatter;
use bgpsim::prelude::*;

use itertools::Itertools;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let filter_topo = "Path_2";
    let filter_scenario = "FullMesh_Prefix10_WithdrawPrefix0AtR0_Delay";
    // let filter_scenario = "ReflectorsR0R1_Prefix10_WithdrawPrefix0AtR0_Delay3000";
    let filter_scenario_end = "";

    /*
    // manually select a scenario for evaluation
    let scenario = "SinglePrefix_RouteReflection(2)_WithdrawBestRoute(2)_Reachability(None)";
    */
    // get all scenario names from the filtered topologies
    for scenario in fs::read_dir("./experiments/")
        .unwrap()
        .filter(|topo_dir| {
            topo_dir
                .as_ref()
                .unwrap()
                .path()
                .to_string_lossy()
                .contains(filter_topo)
        })
        .flat_map(|topo_dir| fs::read_dir(topo_dir.unwrap().path().display().to_string()).unwrap())
        .map(|s| {
            s.unwrap()
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .unique()
    {
        // hashmap to store unified violation_times data with topology size
        let mut data: HashMap<(String, usize), Vec<f64>> = HashMap::new();

        let topos = fs::read_dir("./experiments/").unwrap();
        for topo_dir in topos {
            let topo_path = topo_dir.unwrap().path();
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            if !topo_path.to_string_lossy().contains(filter_topo)
                || !scenario_path.to_string_lossy().contains(filter_scenario)
                || !scenario_path
                    .to_string_lossy()
                    .ends_with(filter_scenario_end)
            {
                continue;
            }
            scenario_path.push("scenario.json");
            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                continue;
            }

            let analyzer = deserialize_from_file(&scenario_path)?;
            if analyzer.num_routers() > 12 {
                log::trace!(
                    "Skipping scenario from {scenario_path:?} as it won't fit on our hardware."
                );
                continue;
            }

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = scenario_path.parent().unwrap().file_name().unwrap();

            //let data_root = "./data/";
            let data_root = "/media/roschmi-data-hdd/orval-backup/data/";
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

            let mut result = HashMap::new();
            for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record?;
                log::trace!("Reading from CSV:\n{record:#?}");

                // read stuff from the cisco_analyzer.csv
                let mut prober_result_path = data_path.clone();
                prober_result_path.push(&record.prober_result_filename);
                // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`
                let capture_result = serde_json::from_str::<Vec<_>>(&fs::read_to_string(
                    prober_result_path,
                )?)?
                .into_iter()
                .collect::<HashMap<(RouterId, P, Ipv4Addr), Vec<(f64, f64, RouterId, u64)>>>();

                for ((rid, prefix, _), samples) in capture_result.iter() {
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
                        // todo!("fix that more than 100 packets are being discarded!");
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
                    result
                        .entry((*rid, *prefix))
                        .or_insert_with(Vec::new)
                        .push((total_num_samples - len) as f64 / record.capture_frequency as f64);
                }
            }

            // at this point we have a result `HashMap<(RouterId, Prefix), Vec<f64>>` mapping
            // router and prefix to the violation times observed for a set of samples.
            for ((rid, prefix), _violation_times) in result.iter() {
                data.insert(
                    (
                        format!(
                            "{topo_name:?}-{}-{prefix:?}",
                            rid.fmt(&analyzer.original_net)
                        ),
                        analyzer.original_net.internal_routers().count(),
                    ),
                    result.get(&(*rid, *prefix)).unwrap().to_vec(),
                );
            }

            /*
            // collect a vector concatenating all values for all routers and all prefixes
            let full_vec: Vec<_> = result
                .iter()
                .flat_map(|(_, violation_times)| violation_times)
                .map(|x| *x)
                .collect();
            data.insert(
                (
                    format!("{topo_name:?}"),
                    analyzer.original_net.get_routers().len(),
                ),
                full_vec,
            );
            */

            /*
            log::debug!("DESERIALIZED: cisco distribution");
            let keys = result.keys();
            for (rid, prefix) in keys.sorted() {
                let cisco_distribution = result.get(&(*rid, *prefix)).unwrap();
                log::debug!(
                    "{} for {prefix:?} measured:\n{cisco_distribution:?}",
                    rid.fmt(&analyzer.original_net)
                );
            }
            */
        }

        let mut plot = plotly::Plot::new();
        for ((topo_name, topo_size), violation_times) in data.into_iter().sorted_by(|a, b| {
            let result = a.0 .1.cmp(&b.0 .1);
            if result != std::cmp::Ordering::Equal {
                result
            } else {
                a.0 .0.cmp(&b.0 .0)
            }
        }) {
            let trace = plotly::BoxPlot::<f64, f64>::new(violation_times)
                .name(format!("{topo_name}, {topo_size} nodes"));
            plot.add_trace(trace);
        }
        //plot.show();

        let plot_dir = "./plots/";
        log::trace!("creating directory");
        fs::create_dir_all(plot_dir)?;
        plot.write_html(format!(
            "{plot_dir}/{scenario}_{filter_topo}{filter_scenario_end}.html"
        ));
    }

    Ok(())
}
