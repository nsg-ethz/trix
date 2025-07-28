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
//! Utility module collection of functions

use std::{
    env, fs,
    num::ParseIntError,
    path::{Path, PathBuf},
};

use itertools::Itertools;
use lazy_static::lazy_static;
use rayon::prelude::*;
use regex::Regex;

use crate::{
    analyzer::Analyzer,
    experiments::{iterate_experiments, Filter},
    prelude::TimingModel,
    Prefix,
};

pub fn init_logging() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
}

pub fn set_conf_dir() -> Result<(), Box<dyn std::error::Error>> {
    let mut conf_dir = env::current_exe()?;
    conf_dir.pop(); // remove filename
    conf_dir.pop(); // move out of `src/`
    conf_dir.pop(); // move out of `target/`
    conf_dir.push("router-lab-config");
    env::set_var("LAB_SETUP_CONFIG", conf_dir.display().to_string());
    Ok(())
}

/// Allows building an `Analyzer` for a specific experiment as defined in
/// `experiments::iterate_experiments`.
pub fn get_analyzer(
    topo_name: impl AsRef<str>,
    scenario_name: impl AsRef<str>,
) -> Result<Analyzer<TimingModel<Prefix>>, Box<dyn std::error::Error>> {
    let topo_name = topo_name.as_ref();
    let scenario_name = scenario_name.as_ref();

    let experiment_filter = Filter {
        topo: topo_name.to_string(),
        scenario: "".to_string(),
        scenario_end: scenario_name.to_string(),
        sample_id: "".to_string(),
    };

    let mut count_experiments = 0;
    let Some((_, analyzer)) = iterate_experiments(experiment_filter)
        .inspect(|_| count_experiments += 1)
        .next()
    else {
        return Err("No experiments found matching the filter!".into());
    };
    // check that there is only one experiment matching the filter
    (count_experiments == 1)
        .then_some(analyzer)
        .ok_or(format!("Found {count_experiments} experiments matching the filter!").into())
}

/// Allows filtering data for all scenarios.
pub fn filter_data(data_root: impl AsRef<Path>, filter: Filter) -> Vec<(String, String, PathBuf)> {
    fs::read_dir(data_root.as_ref())
        .expect("path should exist!")
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
                .filter(|(topo_path, scenario_name)| {
                    topo_path.display().to_string().contains(&filter.topo)
                        && scenario_name.contains(&filter.scenario)
                        && scenario_name.ends_with(&filter.scenario_end)
                })
        })
        .unique()
        .filter_map(|(topo_path, scenario_name)| {
            let topo_name = topo_path.file_name().unwrap().to_string_lossy();
            let mut eval_path = data_root.as_ref().to_path_buf();
            eval_path.push(topo_name.to_string());
            eval_path.push(&scenario_name);

            if eval_path.exists() {
                Some((topo_name.to_string(), scenario_name, eval_path))
            } else {
                None
            }
        })
        .collect_vec()
}

/// Allows processing data for all filtered scenarios in parallel.
pub fn process_data<F>(data_root: impl AsRef<Path>, filter: Filter, f: F)
where
    F: Fn(&str, &str, &Path) + Sync,
{
    filter_data(data_root, filter)
        .into_par_iter()
        //.into_iter()
        .for_each(|(topo_name, scenario_name, eval_path)| {
            f(&topo_name, &scenario_name, &eval_path);
        })
}

/// Allows mapping data for all filtered scenarios.
pub fn map_data<F, T>(data_root: impl AsRef<Path>, filter: Filter, f: F) -> impl Iterator<Item = T>
where
    F: Fn(&str, &str, &Path) -> T,
{
    filter_data(data_root, filter)
        .into_iter()
        .map(move |(topo_name, scenario_name, eval_path)| f(&topo_name, &scenario_name, &eval_path))
}

/// Allows mapping data for all filtered scenarios in parallel.
pub fn par_map_data<F, T>(
    data_root: impl AsRef<Path>,
    filter: Filter,
    f: F,
) -> impl ParallelIterator<Item = T>
where
    F: Fn(&str, &str, &Path) -> T,
    F: Sync + Send,
    T: Send,
{
    filter_data(data_root, filter)
        .into_par_iter()
        .map(move |(topo_name, scenario_name, eval_path)| f(&topo_name, &scenario_name, &eval_path))
}

lazy_static! {
    static ref NUM_PREFIXES: Regex =
        Regex::new(r"^.*Prefix(?P<num_prefixes>[1-9][0-9]*)_.*$").unwrap();
}
/// Extract the number of prefixes for a scenario from a given scenario name string (e.g., the data
/// directory name).
pub fn get_num_prefixes(scenario_name: impl AsRef<str>) -> Result<usize, ParseIntError> {
    NUM_PREFIXES
        .captures(scenario_name.as_ref())
        .unwrap()
        .name("num_prefixes")
        .unwrap()
        .as_str()
        .parse()
}

pub trait PathBufExt: Sized {
    fn then(self, p: impl AsRef<Path>) -> PathBuf;

    fn then_ts(self, p: impl AsRef<str>, ts: &str) -> PathBuf {
        self.then(p.as_ref().replacen("{}", ts, 1))
    }

    fn then_pcap(self, p: impl AsRef<str>, ts: &str) -> PathBuf {
        self.then(p.as_ref().replacen("{}", &format!("pcap_{ts}.pcap.gz"), 1))
    }
}

impl PathBufExt for PathBuf {
    fn then(mut self, p: impl AsRef<Path>) -> PathBuf {
        self.push(p);
        self
    }
}

impl PathBufExt for &Path {
    fn then(self, p: impl AsRef<Path>) -> PathBuf {
        let mut path = self.to_path_buf();
        path.push(p);
        path
    }
}

/// Load the data from the cisco_analyzer.csv
pub fn get_records(eval_path: &Path) -> Option<csv::Reader<std::fs::File>> {
    let mut analyzer_csv_path = eval_path.to_path_buf();
    analyzer_csv_path.push("cisco_analyzer.csv");
    if !analyzer_csv_path.exists() {
        log::trace!("Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet.");
        return None; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
    }
    log::info!("Loading: {analyzer_csv_path:?}");
    let analyzer_csv = fs::File::open(analyzer_csv_path.clone()).unwrap();
    let csv = csv::Reader::from_reader(analyzer_csv);

    Some(csv)
}
