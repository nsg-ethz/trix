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
//! Module that executes the analyzer multiple times and collects all statistics

use std::{
    fmt::Display,
    path::PathBuf,
    time::{Duration, Instant},
};

use indicatif::{HumanDuration, ProgressBar, ProgressStyle};
use itertools::{iproduct, Itertools};
use log::error;

use bgpsim::{topology_zoo::TopologyZoo, types::Prefix};

use super::scenarios::{Scenario, ScenarioError};
use crate::analyzer::{hoeffding, num_workers, AnalysisResult};

pub fn run(out_file: &str, scenarios: Vec<Scenario>, confidences: Vec<f64>, precisions: Vec<f64>) {
    let topos = TopologyZoo::topologies_increasing_nodes()
        .iter()
        .filter(|t| t.num_internals() >= 10)
        .copied()
        .collect_vec();

    let compute_num_samples = |conf: f64, prec: f64| {
        (hoeffding(conf, prec) + (num_workers() - 1)) / num_workers() * num_workers()
    };

    let num_samples_hoeffding: usize = iproduct!(&precisions, &confidences)
        .map(|(prec, conf)| compute_num_samples(*conf, *prec))
        .sum();
    let num_samples = scenarios.len() * topos.len() * num_samples_hoeffding;

    let bar = ProgressBar::new(num_samples as u64);
    bar.set_style(ProgressStyle::with_template("{wide_bar} time: {elapsed}, eta: {msg} ").unwrap());
    bar.tick();

    // check if the file exists. If not, then create the header
    let filename = PathBuf::from(format!(
        "{}_{}.csv",
        out_file,
        chrono::Local::now().format("%Y-%m-%d_%H:%M:%S")
    ));

    let mut csv_writer = csv::Writer::from_path(filename).unwrap();

    csv_writer.write_record(DataPoint::record_title()).unwrap();
    csv_writer.flush().unwrap();

    let start_time = Instant::now();
    let mut scaling: Option<f64> = None;
    bar.set_message("?");

    for (confidence, precision, scenario) in iproduct!(&confidences, &precisions, &scenarios) {
        for topo in topos.iter() {
            let data_point = get_data_point(*topo, scenario.clone(), *confidence, *precision);
            bar.inc(
                data_point
                    .result
                    .as_ref()
                    .map(|r| r.n_samples)
                    .unwrap_or_else(|_| compute_num_samples(*confidence, *precision))
                    as u64,
            );
            if let Some(scaling) = scaling {
                bar.set_message(
                    HumanDuration(Duration::from_secs_f64(
                        bar.length().unwrap().saturating_sub(bar.position()) as f64 * scaling,
                    ))
                    .to_string(),
                );
            } else {
                bar.set_message("?");
            }
            csv_writer.write_record(data_point.record()).unwrap();
            csv_writer.flush().unwrap();
        }
        scaling = Some(start_time.elapsed().as_secs_f64() / bar.position() as f64);
    }
}

pub fn get_data_point(
    topo: TopologyZoo,
    scenario: Scenario,
    confidence: f64,
    precision: f64,
) -> DataPoint {
    let now = Instant::now();
    let net = topo.build(bgpsim::prelude::BasicEventQueue::new());
    let geo_location = topo.geo_location();
    let maybe_analyzer = scenario.build_from(&net, &geo_location);
    let build_time = now.elapsed();
    match maybe_analyzer {
        Ok(mut analyzer) => {
            analyzer.set_precision(precision);
            analyzer.set_confidence(confidence);
            let result = Ok(analyzer.analyze());
            DataPoint {
                topo,
                scenario,
                result,
                build_time,
            }
        }
        Err(error) => {
            if log::log_enabled!(log::Level::Error) {
                eprint!(
                    "{}{}",
                    termion::cursor::Left(1000),
                    termion::clear::CurrentLine
                );
                error!("Could not setup {:?} for {:?}", topo, scenario);
            }
            DataPoint {
                topo,
                scenario,
                result: Err(error),
                build_time,
            }
        }
    }
}

#[derive(Debug)]
pub struct DataPoint {
    pub topo: TopologyZoo,
    pub scenario: Scenario,
    pub result: Result<AnalysisResult, ScenarioError>,
    pub build_time: Duration,
}

const RECORD_SIZE: usize = 22;

impl DataPoint {
    pub fn result(self) -> Option<AnalysisResult> {
        match self.result {
            Ok(r) => Some(r),
            Err(_) => None,
        }
    }

    pub fn record_title() -> [&'static str; RECORD_SIZE] {
        [
            "topology",
            "n_nodes",
            "scenario.num_route_reflectors",
            "scenario.num_routes",
            "scenario.event",
            "scenario.policy_type",
            "scenario.policy_strict",
            "scenario.num_properties",
            "success",
            "confidence",
            "precision",
            "n_samples",
            "n_unique_equiv",
            "p_satisfied",
            "convergence_time",
            "t_build",
            "t_analyze",
            "t_simulate",
            "t_check",
            "t_clone",
            "t_collect",
            "dist_violation_times",
        ]
    }

    pub fn record(&self) -> [String; RECORD_SIZE] {
        let n = self.topo.num_internals();
        let s = &self.scenario;
        let r = &self.result;
        [
            format!("{:?}", self.topo),                      // topology
            self.topo.num_internals().to_string(),           // n_nodes
            s.config.num_rrs().unwrap_or(n).to_string(),     // scenario.num_route_reflectors
            (1 + 2 * s.event.num_routes()).to_string(),      // scenario.num_routes
            s.event.name().to_string(),                      // scenario.event
            s.policy.name().to_string(),                     // scenario.policy_type
            false.to_string(),                               // scenario.policy_strict
            s.policy.num_routers().unwrap_or(n).to_string(), // scenario.num_properties
            r.is_ok().to_string(),                           // success
            r_str(r, |r| r.confidence),                      // confidence
            r_str(r, |r| r.precision),                       // precision
            r_str(r, |r| r.n_samples),                       // n_samples
            r_str(r, |r| r.n_unique_equiv),                  // n_unique_equiv
            r_str(r, |r| r.p_satisfied),                     // p_satisfied
            r_str(r, |r| r.convergence_time),                // convergence_time
            self.build_time.as_secs_f64().to_string(),       // t_build
            r_str(r, |r| r.t_wall.as_secs_f64()),            // t_analyze
            r_str(r, |r| r.t_simulate.as_secs_f64()),        // t_simulate
            r_str(r, |r| r.t_checking.as_secs_f64()),        // t_check
            r_str(r, |r| r.t_cloning.as_secs_f64()),         // t_clone
            r_str(r, |r| r.t_collect.as_secs_f64()),         // t_collect
            "".to_string(), //lol_str(r, |r| &r.violation_time_distributions), // dist_violation_times
        ]
    }
}

pub fn r_str<T, F>(r: &Result<AnalysisResult, ScenarioError>, f: F) -> String
where
    T: Display,
    F: FnOnce(&AnalysisResult) -> T,
{
    r.as_ref().map(f).map(|x| x.to_string()).unwrap_or_default()
}

/// encodes a list of values separated by a `;`
pub fn list_str<T, F>(r: &Result<AnalysisResult, ScenarioError>, f: F) -> String
where
    T: Display,
    F: FnOnce(&AnalysisResult) -> &[T],
{
    r.as_ref().map(f).unwrap_or(&Vec::new()).iter().join(";")
}

/// encodes a list of lists separated by an `@` between lists and a `;` between elements
pub fn lol_str<T, F>(r: &Result<AnalysisResult, ScenarioError>, f: F) -> String
where
    T: Display,
    F: FnOnce(&AnalysisResult) -> &[Vec<T>] + Copy,
{
    r.as_ref()
        .map(f)
        .unwrap_or(&Vec::new())
        .iter()
        .enumerate()
        .map(|(i, _)| list_str(r, |r| &f(r)[i])) // apply function list_str to each element of the list and
        .join("@") // concatenate with the `@` sign
}

impl std::fmt::Display for DataPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.result.as_ref() {
            Ok(r) => write!(
                f,
                "{:>25}, network size: {:>3}, total time: {:>8.2?} ({:>8.2}us / sample), with {:>7.3}% violations ({} iterations, confidence={:.1}%, precision={:.3}%)\n\n{}\n\n{}",
                format!("{:?}", self.topo),
                self.topo.num_internals(),
                r.t_wall,
                (r.t_wall.as_micros() as f64 / r.n_samples as f64),
                (1.0 - r.p_satisfied) * 100.0,
                r.n_samples,
                (1.0 - r.confidence) * 100.0,
                r.precision * 100.0,
                // simulated violation times: avg over routers, Vec<individual_violations>
                r.violation_time_distributions
                .iter()
                .sorted_by_key(|x| x.0.1.as_num())
                .group_by(|x| x.0.1)
                .into_iter()
                .map(|(prefix, group)| {
                    let mut row = prefix.to_string();
                    row.push_str(" simulated [ms]: ");
                    let samples = group.flat_map(|((_rid, _prefix), samples)| samples.iter())
                        .collect_vec();
                    row.push_str(&(samples.iter().map(|x| **x).sum::<f64>() / samples.len() as f64 * 1000.0).to_string());
                    row.push_str(" (avg), [");
                    row.push_str(&samples
                        .iter()
                        .map(|s| format!("{:.2}", *s * 1000.0))
                        .collect::<Vec<String>>()
                        .join(", ")
                        );
                    row.push(']');

                    row
                })
                .collect::<Vec<String>>()
                .join("\n"),
                r.cisco_violation_time_distributions
                .iter()
                .sorted_by(|a, b| a.0.cmp(b.0))
                .map(|((rid, prefix), samples)| {
                    let mut row = rid.index().to_string();
                    row.push_str(" for ");
                    row.push_str(&prefix.to_string());
                    row.push_str(" measured [ms]: ");
                    let items: String = samples
                        .iter()
                        .sorted_by(|a, b| a.partial_cmp(b).unwrap())
                        .map(|s| format!("{:.2}", s * 1000.0))
                        .collect::<Vec<String>>()
                        .join(", ");
                    row.push_str(&items);

                    row
                })
                .collect::<Vec<String>>()
                .join("\n"),
            ),
            Err(e) => write!(
                f,
                "{:>25}, network size: {:>3}, error: {}",
                format!("{:?}", self.topo),
                self.topo.num_internals(),
                e
            ),
        }
    }
}
