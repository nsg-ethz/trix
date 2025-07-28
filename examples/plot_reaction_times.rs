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

use trix::{serde_generic_hashmap::SerializeHashmap, Prefix as P};
use bgpsim::prelude::*;

mod extract_reaction_times;
use extract_reaction_times::{
    CPReactionTimesMap, DPReactionTimesMap, LastDPReactionTimesMap, ReactionTimesMap,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let filter_topo = "Path_";
    let filter_scenario = "LinkFailureAtR0Ext";
    let filter_scenario_not = "KeepOther";
    let filter_scenario_end = "";
    let _filter_sample_id = "";

    // reaction times based on #withdrawn, #announced, #peers, and prefix
    let mut reaction_times: ReactionTimesMap<P> = HashMap::new();
    // HashMap mapping message size, number of peers, and prefix to control plane reaction times
    let mut cp_reaction_times: CPReactionTimesMap<P> = HashMap::new();
    // HashMap mapping message size to last router's data plane reaction times
    let mut last_dp_reaction_times: LastDPReactionTimesMap = HashMap::new();
    // HashMap mapping message size to data plane reaction times
    let mut dp_reaction_times: DPReactionTimesMap = HashMap::new();

    // get all (topo, scenario) combinations
    fs::read_dir("./experiments/")
        .expect("./experiments/ cannot be read")
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
                .filter(|(topo_path, scenario)| {
                    topo_path.display().to_string().contains(filter_topo)
                        && scenario.contains(filter_scenario)
                        && !scenario.contains(filter_scenario_not)
                        && scenario.ends_with(filter_scenario_end)
                })
        })
        .unique()
        .collect_vec()
        //.into_par_iter()
        // use single-threaded iterater for synchronization!
        .into_iter()
        .for_each(|(topo_path, scenario)| {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");
            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
            }

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = topo_path.file_name().unwrap();

            // path under which to place processed violation times
            let eval_root = "./reaction_times/";
            //let eval_root = "./";
            let mut eval_path = PathBuf::from(eval_root);
            eval_path.push(format!("{}", topo_name.to_string_lossy()));
            eval_path.push(format!("{}", scenario_name.to_string_lossy()));
            fs::create_dir_all(&eval_path).unwrap();

            let mut reaction_file_path = eval_path.clone();
            reaction_file_path.push("reaction_times.json");
            let mut cp_reaction_file_path = eval_path.clone();
            cp_reaction_file_path.push("cp_reaction_times.json");
            let mut dp_reaction_file_path = eval_path.clone();
            dp_reaction_file_path.push("dp_reaction_times.json");
            let mut last_dp_reaction_file_path = eval_path.clone();
            last_dp_reaction_file_path.push("last_dp_reaction_times.json");

            if reaction_file_path.exists() {
                let serialized_reaction_times = fs::read_to_string(&reaction_file_path).unwrap();
                #[allow(unused_variables, unused_assignments)]
                let mut sample_reaction_times = SerializeHashmap::from(ReactionTimesMap::new());
                sample_reaction_times = serde_json::from_str(&serialized_reaction_times).unwrap();
                for (k, v) in sample_reaction_times.0.into_iter() {
                    reaction_times.entry(k).or_default().extend(v);
                }
            }

            if cp_reaction_file_path.exists() {
                let serialized_cp_reaction_times =
                    fs::read_to_string(&cp_reaction_file_path).unwrap();
                #[allow(unused_variables, unused_assignments)]
                let mut sample_cp_reaction_times =
                    SerializeHashmap::from(CPReactionTimesMap::new());
                sample_cp_reaction_times =
                    serde_json::from_str(&serialized_cp_reaction_times).unwrap();
                for (k, v) in sample_cp_reaction_times.0.into_iter() {
                    cp_reaction_times.entry(k).or_default().extend(v);
                }
            }

            if last_dp_reaction_file_path.exists() {
                let serialized_last_dp_reaction_times =
                    fs::read_to_string(&last_dp_reaction_file_path).unwrap();
                #[allow(unused_variables, unused_assignments)]
                let mut sample_last_dp_reaction_times =
                    SerializeHashmap::from(LastDPReactionTimesMap::new());
                sample_last_dp_reaction_times =
                    serde_json::from_str(&serialized_last_dp_reaction_times).unwrap();
                for (k, v) in sample_last_dp_reaction_times.0.into_iter() {
                    last_dp_reaction_times.entry(k).or_default().extend(v);
                }
            }

            if dp_reaction_file_path.exists() {
                let serialized_dp_reaction_times =
                    fs::read_to_string(&dp_reaction_file_path).unwrap();
                #[allow(unused_variables, unused_assignments)]
                let mut sample_dp_reaction_times =
                    SerializeHashmap::from(DPReactionTimesMap::new());
                sample_dp_reaction_times =
                    serde_json::from_str(&serialized_dp_reaction_times).unwrap();
                for (k, v) in sample_dp_reaction_times.0.into_iter() {
                    dp_reaction_times.entry(k).or_default().extend(v);
                }
            }
        });

    // At this point we have the 4 global HashMaps filled with data, ready to plot.

    let plot_dir = "./plots/reaction_times/";
    log::trace!("ensuring directory {plot_dir:?} exists");
    fs::create_dir_all(plot_dir).unwrap();

    // plot cp reaction times
    let mut cp_reaction_times_by_msg_size = HashMap::new();
    let mut cp_reaction_times_by_num_peers = HashMap::new();
    let mut cp_reaction_times_by_prefix = HashMap::new();

    for ((msg_size, num_peers, prefix), times) in cp_reaction_times.into_iter() {
        cp_reaction_times_by_msg_size
            .entry(msg_size)
            .or_insert_with(Vec::new)
            .extend(times.clone());
        cp_reaction_times_by_num_peers
            .entry(num_peers)
            .or_insert_with(Vec::new)
            .extend(times.clone());
        cp_reaction_times_by_prefix
            .entry(prefix)
            .or_insert_with(Vec::new)
            .extend(times.clone());
    }

    // plot last cp reaction times
    let mut first_cp_reaction_times_by_msg_size = HashMap::new();
    let mut first_cp_reaction_times_by_msg_size_and_num_peers = HashMap::new();
    let mut first_cp_reaction_times_by_num_peers = HashMap::new();
    let mut first_cp_reaction_times_by_prefix = HashMap::new();
    let mut last_cp_reaction_times_by_msg_size = HashMap::new();
    let mut last_cp_reaction_times_by_msg_size_and_num_peers = HashMap::new();
    let mut last_cp_reaction_times_by_num_peers = HashMap::new();
    let mut last_cp_reaction_times_by_prefix = HashMap::new();
    let mut cp_reaction_increments_by_msg_size = HashMap::new();
    let mut cp_reaction_increments_by_msg_size_and_num_peers = HashMap::new();
    let mut cp_reaction_increments_by_num_peers = HashMap::new();
    let mut cp_reaction_increments_by_prefix = HashMap::new();
    let mut dp_reaction_times_by_prefix = HashMap::new();

    for ((num_withdrawn, num_advertised, num_peers, prefix), vec_reaction_times) in
        reaction_times.into_iter()
    {
        let msg_size = num_withdrawn + num_advertised;
        for reaction_times in vec_reaction_times {
            if let Some(time) = reaction_times.first_cp_reaction {
                first_cp_reaction_times_by_msg_size
                    .entry(msg_size)
                    .or_insert_with(Vec::new)
                    .push(time);
                first_cp_reaction_times_by_msg_size_and_num_peers
                    .entry(num_peers)
                    .or_insert_with(HashMap::new)
                    .entry(msg_size)
                    .or_insert_with(Vec::new)
                    .push(time);
                first_cp_reaction_times_by_num_peers
                    .entry(num_peers)
                    .or_insert_with(Vec::new)
                    .push(time);
                first_cp_reaction_times_by_prefix
                    .entry(prefix)
                    .or_insert_with(Vec::new)
                    .push(time);
            }
            if let Some(time) = reaction_times.last_cp_reaction {
                last_cp_reaction_times_by_msg_size
                    .entry(msg_size)
                    .or_insert_with(Vec::new)
                    .push(time);
                last_cp_reaction_times_by_msg_size_and_num_peers
                    .entry(num_peers)
                    .or_insert_with(HashMap::new)
                    .entry(msg_size)
                    .or_insert_with(Vec::new)
                    .push(time);
                last_cp_reaction_times_by_num_peers
                    .entry(num_peers)
                    .or_insert_with(Vec::new)
                    .push(time);
                last_cp_reaction_times_by_prefix
                    .entry(prefix)
                    .or_insert_with(Vec::new)
                    .push(time);
            }
            if let Some(time) = reaction_times.cp_reaction_increment {
                cp_reaction_increments_by_msg_size
                    .entry(msg_size)
                    .or_insert_with(Vec::new)
                    .push(time);
                cp_reaction_increments_by_msg_size_and_num_peers
                    .entry(num_peers)
                    .or_insert_with(HashMap::new)
                    .entry(msg_size)
                    .or_insert_with(Vec::new)
                    .push(time);
                cp_reaction_increments_by_num_peers
                    .entry(num_peers)
                    .or_insert_with(Vec::new)
                    .push(time);
                cp_reaction_increments_by_prefix
                    .entry(prefix)
                    .or_insert_with(Vec::new)
                    .push(time);
            }
            if let Some(time) = reaction_times.dp_reaction {
                dp_reaction_times_by_prefix
                    .entry(prefix)
                    .or_insert_with(Vec::new)
                    .push(time);
            }
        }
    }

    // by msg_size
    let mut plot = plotly::Plot::new();
    for (key, times) in cp_reaction_times_by_msg_size {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/all_cp_reaction_times_by_msg_size.html",));
    let mut plot = plotly::Plot::new();
    for (key, times) in first_cp_reaction_times_by_msg_size {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/first_cp_reaction_times_by_msg_size.html",
    ));
    let mut plot = plotly::Plot::new();
    for (key, times) in last_cp_reaction_times_by_msg_size {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/last_cp_reaction_times_by_msg_size.html",
    ));
    let mut plot = plotly::Plot::new();
    for (key, times) in cp_reaction_increments_by_msg_size {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/cp_reaction_increments_by_msg_size.html",
    ));

    // by msg_size and num_peers
    for (num_peers, data) in first_cp_reaction_times_by_msg_size_and_num_peers {
        let mut plot = plotly::Plot::new();
        for (key, times) in data {
            let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
            plot.add_trace(trace);
        }
        plot.write_html(format!(
            "{plot_dir}/first_cp_reaction_times_by_msg_size_{num_peers}_peers.html",
        ));
    }
    for (num_peers, data) in last_cp_reaction_times_by_msg_size_and_num_peers {
        let mut plot = plotly::Plot::new();
        for (key, times) in data {
            let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
            plot.add_trace(trace);
        }
        plot.write_html(format!(
            "{plot_dir}/last_cp_reaction_times_by_msg_size_{num_peers}_peers.html",
        ));
    }
    for (num_peers, data) in cp_reaction_increments_by_msg_size_and_num_peers {
        let mut plot = plotly::Plot::new();
        for (key, times) in data {
            let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
            plot.add_trace(trace);
        }
        plot.write_html(format!(
            "{plot_dir}/cp_reaction_increments_by_msg_size_{num_peers}_peers.html",
        ));
    }

    // by num_peers
    let mut plot = plotly::Plot::new();
    for (key, times) in cp_reaction_times_by_num_peers {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/all_cp_reaction_times_by_num_peers.html",
    ));
    let mut plot = plotly::Plot::new();
    for (key, times) in first_cp_reaction_times_by_num_peers {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/first_cp_reaction_times_by_num_peers.html",
    ));
    let mut plot = plotly::Plot::new();
    for (key, times) in last_cp_reaction_times_by_num_peers {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/last_cp_reaction_times_by_num_peers.html",
    ));
    let mut plot = plotly::Plot::new();
    for (key, times) in cp_reaction_increments_by_num_peers {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!(
        "{plot_dir}/cp_reaction_increments_by_num_peers.html",
    ));

    // by prefix
    let mut plot = plotly::Plot::new();
    for (key, times) in cp_reaction_times_by_prefix
        .into_iter()
        .sorted_by_key(|(prefix, _)| prefix.as_num())
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/all_cp_reaction_times_by_prefix.html",));
    let mut plot = plotly::Plot::new();
    for (key, times) in first_cp_reaction_times_by_prefix
        .into_iter()
        .sorted_by_key(|(prefix, _)| prefix.as_num())
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/first_cp_reaction_times_by_prefix.html",));
    let mut plot = plotly::Plot::new();
    for (key, times) in last_cp_reaction_times_by_prefix
        .into_iter()
        .sorted_by_key(|(prefix, _)| prefix.as_num())
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/last_cp_reaction_times_by_prefix.html",));
    let mut plot = plotly::Plot::new();
    for (key, times) in cp_reaction_increments_by_prefix
        .into_iter()
        .sorted_by_key(|(prefix, _)| prefix.as_num())
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/cp_reaction_increments_by_prefix.html",));

    // plot last router's dp reaction times
    let mut plot = plotly::Plot::new();
    for (key, times) in last_dp_reaction_times.iter() {
        let trace = plotly::BoxPlot::<f64, f64>::new(times.clone()).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/last_dp_reaction_times.html",));

    // plot other dp reaction times
    let mut plot = plotly::Plot::new();
    for (key, times) in dp_reaction_times.iter() {
        let trace = plotly::BoxPlot::<f64, f64>::new(times.clone()).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/dp_reaction_times.html",));

    // plot dp reactions by prefix
    let mut plot = plotly::Plot::new();
    for (key, times) in dp_reaction_times_by_prefix
        .into_iter()
        .sorted_by_key(|(prefix, _)| prefix.as_num())
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/dp_reaction_times_by_prefix.html",));

    // plot all dp reaction times
    // 1. merge dp reaction times
    for (key, times) in last_dp_reaction_times {
        dp_reaction_times.entry(key).or_default().extend(times);
    }
    // 2. plot merged times
    let mut plot = plotly::Plot::new();
    for (key, times) in dp_reaction_times {
        let trace = plotly::BoxPlot::<f64, f64>::new(times).name(key.to_string());
        plot.add_trace(trace);
    }
    plot.write_html(format!("{plot_dir}/all_dp_reaction_times.html",));

    Ok(())
}
