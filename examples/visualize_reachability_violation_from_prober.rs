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

use trix::{analyzer::CiscoAnalyzerData, experiments::*, Prefix as P};
use bgpsim::formatter::NetworkFormatter;
use bgpsim::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let filter_topo = "Path_12";
    let filter_scenario = "FullMesh_Prefix10_Withdraw";
    // let filter_sample_id = "2023-06-20_15-42-21";
    let filter_sample_id = "";

    // get all (topo, scenario) combinations
    fs::read_dir("./experiments/")
        .unwrap()
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
        })
        .unique()
        .collect_vec()
        //.into_par_iter()
        .into_iter()
        .for_each(|(topo_path, scenario)| {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");

            if !topo_path.display().to_string().contains(filter_topo)
                || !scenario.contains(filter_scenario)
            {
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }

            let analyzer = deserialize_from_file(&scenario_path).unwrap();

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = topo_path.file_name().unwrap();

            let data_root = "/media/roschmi-data-hdd/orval-backup/data/";
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

            for record in csv.deserialize() {
                let record: CiscoAnalyzerData = record.unwrap();
                log::trace!("Reading from CSV:\n{record:#?}");

                if !record.execution_timestamp.contains(filter_sample_id) {
                    continue;
                }

                // read stuff from the cisco_analyzer.csv
                let mut prober_result_path = data_path.clone();
                prober_result_path.push(&record.prober_result_filename);
                // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`
                let capture_result = serde_json::from_str::<Vec<_>>(
                    &fs::read_to_string(prober_result_path).unwrap(),
                )
                .unwrap()
                .into_iter()
                .collect::<HashMap<(RouterId, P, Ipv4Addr), Vec<(f64, f64, RouterId, u64)>>>();

                // Histogram plots for the counters
                let mut plot = plotly::Plot::new();
                for ((rid, prefix, _), samples) in capture_result
                    .iter()
                    // sort by prefix, router id
                    .sorted_by(|((r1, p1, _), _), ((r2, p2, _), _)| p1.cmp(p2).then(r1.cmp(r2)))
                {
                    let processed_prober_packets = samples
                        .iter()
                        .filter(|(_, t_rx, ext, _)| {
                            analyzer
                                .event
                                .collector_filter(&record.event_start, *prefix, t_rx, ext)
                        })
                        .collect_vec();

                    log::trace!(
                        "Discarding {} samples happening after the event_start for router {}",
                        samples.len() - processed_prober_packets.len(),
                        rid.fmt(&analyzer.original_net)
                    );

                    let t_sent_vec = samples
                        .iter()
                        .map(|(t_sent, _, _, _)| *t_sent)
                        .collect_vec();
                    let t_min = t_sent_vec.iter().min_by(|a, b| a.total_cmp(b)).unwrap();
                    let t_sent_normalized = t_sent_vec.iter().map(|x| x - t_min).collect_vec();

                    plot.add_trace(
                        plotly::Histogram::new(t_sent_normalized)
                            .name(&format!("{}-{prefix:?}", rid.fmt(&analyzer.original_net))),
                    );
                }
                // plot.show();

                let plot_dir = "./plots/";
                fs::create_dir_all(plot_dir).unwrap();
                plot.write_html(format!("{plot_dir}/Histogram_Reachability_{scenario}.html"));

                todo!("stop here, process only one scenario");
            }
        });

    Ok(())
}
