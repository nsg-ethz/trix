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
use std::{collections::HashMap, fs, path::PathBuf};

use itertools::Itertools;

use trix::{experiments::*, transient_specification::TransientPolicy};
use bgpsim::{policies::FwPolicy, prelude::*, router::Router};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    // manually select a topo/scenario for evaluation
    let topology = "Path_10";
    //let topology = "Abilene";
    //let scenario = "ExtLosAngelesKansasCity_FullMesh_Prefix100_LinkFailureAtLosAngelesExt_Delay5000";
    //let scenario = "ExtAtEnds_FullMesh_Prefix1_LinkFailureAtR0Ext_Delay5000";
    let scenario = "ExtAtEnds_FullMesh_Prefix10_LinkFailureAtR0Ext_Delay5000";
    //let scenario = "ExtAtEnds_FullMesh_Prefix100_LinkFailureAtR0Ext_Delay5000";
    //let scenario = "ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles";
    /*
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesExt
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesExt_Delay0
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesExt_Delay10000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesExt_Delay3000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesExt_Delay5000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesSunnyvale
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesSunnyvale_Delay0
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesSunnyvale_Delay10000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesSunnyvale_Delay3000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_LinkFailureAtLosAngelesSunnyvale_Delay5000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles_Delay0
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles_Delay10000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles_Delay3000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngeles_Delay5000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngelesKeepOther
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngelesKeepOther_Delay0
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngelesKeepOther_Delay10000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngelesKeepOther_Delay3000
    ExtLosAngelesKansasCity_FullMesh_Prefix1_WithdrawPrefix0AtLosAngelesKeepOther_Delay5000
    */

    // find corresponding paths on the file system
    let topos = fs::read_dir("./experiments_batching_v2/").unwrap();
    for topo_dir in topos {
        let topo_path = topo_dir.unwrap().path();
        let mut scenario_path = topo_path.clone();
        scenario_path.push(scenario);
        if !topo_path.to_string_lossy().ends_with(topology) {
            log::trace!(
                "topology {topology} did not match {}",
                topo_path.to_string_lossy()
            );
            continue;
        }
        scenario_path.push("scenario.json");
        if !scenario_path.exists() {
            log::trace!("Skipping non-existent scenario from {scenario_path:?}");
            continue;
        }

        let mut analyzer = deserialize_from_file(&scenario_path)?;

        log::warn!("redoing the event");
        analyzer.scheduled_net = analyzer.original_net.clone();
        analyzer.scheduled_net.manual_simulation();

        // perform the event
        analyzer.event.trigger(&mut analyzer.scheduled_net)?;

        // get the scheduled forwarding state
        analyzer.scheduled_fw = analyzer.scheduled_net.get_forwarding_state();

        log::trace!("Loaded: {}", scenario_path.to_string_lossy());

        // get the correct output folder name
        scenario_path.pop(); // remove "scenario.json"
        let scenario_name = scenario_path.file_name().unwrap();
        let topo_name = scenario_path.parent().unwrap().file_name().unwrap();
        let topo_size = analyzer.original_net.internal_routers().count();

        // get the correct output folder name
        let eval_root = "./data/";
        //let eval_root = "/media/roschmi-data-hdd/orval-backup/data/";
        let mut eval_path = PathBuf::from(eval_root);
        eval_path.push(format!("{}", topo_name.to_string_lossy()));
        eval_path.push(format!("{}", scenario_name.to_string_lossy()));

        // run analyzer
        analyzer.set_num_samples(1);
        log::info!(
            "Simulating topology {} with scenario {scenario_name:?}... (collecting {} samples)",
            topo_name.to_string_lossy(),
            analyzer.num_samples(),
        );

        let routers = analyzer
            .original_net
            .internal_routers()
            .map(Router::router_id)
            .collect::<Vec<_>>();
        let policies = analyzer
            .original_net
            .get_known_prefixes()
            .filter(|prefix| [0, 49, 99].contains(&prefix.as_num()))
            .flat_map(|prefix| {
                routers
                    .iter()
                    .map(|rid| TransientPolicy::Atomic(FwPolicy::Reachable(*rid, *prefix)))
            })
            .collect_vec();
        log::trace!("policies:\n{policies:?}");
        analyzer.set_policies(policies);

        let violation_times = analyzer.analyze().violation_time_distributions;
        let mut data: HashMap<(String, usize), Vec<f64>> = HashMap::new();
        for (rid, prefix) in violation_times.keys().sorted() {
            let simulated_distribution = violation_times.get(&(*rid, *prefix)).unwrap();
            log::trace!(
                "{} for {prefix:?} simulated (avg: {})\n{simulated_distribution:?}",
                rid.fmt(&analyzer.original_net),
                simulated_distribution.iter().sum::<f64>() / simulated_distribution.len() as f64,
            );
            data.insert(
                (
                    format!("{}-{prefix:?}-sim", rid.fmt(&analyzer.original_net)),
                    topo_size,
                ),
                simulated_distribution.clone(),
            );
        }

        // read HW violation_times from the files
        let mut reachability_violation_file_path = eval_path.clone();
        reachability_violation_file_path.push("violation_reachability.json");
        if reachability_violation_file_path.exists() {
            let serialized_reachability_violation_times =
                fs::read_to_string(&reachability_violation_file_path).unwrap();
            let reachability_violation_times: Vec<Sample> =
                serde_json::from_str(&serialized_reachability_violation_times).unwrap();

            let property_name = "reachability";
            let violation_times = &reachability_violation_times;

            let plot_dir = format!("./plots/{property_name}/");
            log::trace!("ensuring directory {plot_dir:?} exists");
            fs::create_dir_all(&plot_dir).unwrap();

            // HashMap to store a vector of violation times per router and destination prefix.
            let mut result: HashMap<(&str, &str), Vec<f64>> = HashMap::new();

            for sample in violation_times.iter() {
                for (prefix, sample_properties) in sample.violation_times.iter() {
                    for (router_name, violation_info) in sample_properties.iter() {
                        // discard additional information, only add violation times to the plots
                        if let ViolationInfo::Time(violation_time) = violation_info {
                            result
                                .entry((router_name, prefix))
                                .or_default()
                                .push(*violation_time);
                        }
                    }
                }
            }

            // at this point we have a result `HashMap<(&str, &str), Vec<f64>>` mapping router_name and
            // prefix to the violation times observed for a set of samples. Also, `data` contains
            // the data for the simulator already.
            //let mut data: HashMap<(String, usize), Vec<f64>> = HashMap::new();
            for ((router_name, prefix), _violation_times) in result.iter() {
                data.insert(
                    (format!("{router_name}-{prefix:?}-hw"), topo_size),
                    result.get(&(*router_name, *prefix)).unwrap().to_vec(),
                );
            }

            // plot violation data
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

            log::debug!(
                "Plotting {plot_dir}/{}_{scenario}.html",
                topo_name.to_string_lossy(),
            );
            plot.write_html(format!(
                "{plot_dir}/{}_{scenario}.html",
                topo_name.to_string_lossy(),
            ));
        } else {
            log::warn!("no data for the hw experiments found");
        }
    }

    Ok(())
}
