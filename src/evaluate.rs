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
//! Evaluate a time series of forwarding updates collected from hardware experiments using the
//! interval algorithm.

use std::{
    collections::{HashMap, HashSet},
    fs,
    iter::once,
    path::Path,
    str::FromStr,
};

use clap::Parser;
use itertools::Itertools;
use rand::thread_rng;
use rand_distr::{Distribution, Normal};

use bgpsim::{
    formatter::NetworkFormatter, forwarding_state::ForwardingState, policies::Policy,
    types::RouterId,
};

use trix::{
    analyzer::{Analyzer, CiscoAnalyzerData},
    experiments::Filter,
    records::{EvaluationRecord, FWRecord, PathRecord, Router},
    timing_model::TimingModel,
    transient_specification::{
        check_path_updates, compute_baseline, compute_violation_times, EvaluationError,
        TransientPolicy,
    },
    util::{self, PathBufExt},
    MultiPrefixConvergenceTrace, Prefix,
};

/// Loads a file `fw_updates_path`, and applies normally-distributed de-synchronization errors up
/// to `delay_ms` to each router. Uses one fixed offset for each router for an entire experiment.
/// Writes the result to `modified_fw_updates_path`.
fn modify_fw_updates(
    fw_updates_path: impl AsRef<Path>,
    modified_fw_updates_path: impl AsRef<Path>,
    delay_ms: usize,
) -> Result<(), EvaluationError> {
    // load `fw_updates_path`
    let mut rdr = csv::ReaderBuilder::new()
        .from_path(fw_updates_path.as_ref())
        .map_err(|_| EvaluationError::NoData)?;

    let records = rdr
        .deserialize()
        .collect::<Result<Vec<FWRecord>, _>>()
        .unwrap();

    // write to `modified_fw_updates_path`
    let mut csv = csv::WriterBuilder::new().has_headers(true).from_writer(
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(modified_fw_updates_path.as_ref())
            .unwrap(),
    );

    // keep note of fixed offset per node
    let mut offsets: HashMap<RouterId, f64> = HashMap::new();

    for record in records
        .into_iter()
        .map(|mut record| {
            record.time += *offsets
                .entry(record.src)
                .or_insert_with(|| sample_normal_with_bound(delay_ms as f64 / 2_000.0));
            record
        })
        // restore sort after modifications take effect
        .sorted_by(|a, b| a.time.total_cmp(&b.time))
    {
        csv.serialize(&record).unwrap();
    }

    csv.flush().unwrap();

    Ok(())
}

/// Samples a normally-distributed value within [-bound, bound]. Standard deviation is bound / 2.0
fn sample_normal_with_bound(bound: f64) -> f64 {
    // init normal distribution
    let normal = Normal::new(0.0, bound / 2.0).unwrap();

    // try sampling until within bounds
    loop {
        let sample = normal.sample(&mut thread_rng());
        if sample.abs() <= bound {
            return sample;
        }
    }
}

/// Build a time series of forwarding updates from a csv of `FWRecord`s.
fn build_trace_from_fw_updates(
    analyzer: &Analyzer<TimingModel<Prefix>>,
    event_start: f64,
    prefixes: &HashSet<Prefix>,
    fw_updates_path: impl AsRef<Path>,
    fw_state: &mut ForwardingState<Prefix>,
) -> Result<MultiPrefixConvergenceTrace, EvaluationError> {
    let mut rdr = csv::ReaderBuilder::new()
        .from_path(fw_updates_path.as_ref())
        .map_err(|_| EvaluationError::NoData)?;
    // FwDelta = (rid: RouterId, old_nhs: Vec<RouterId>, new_nhs: Vec<RouterId>)
    // prefix -> Vec<(Vec<FwDelta>, AlwaysEq<Option<f64>>)>
    let mut trace = MultiPrefixConvergenceTrace::new();

    // sort FW updates just in case...
    let records = rdr
        .deserialize()
        .collect::<Result<Vec<FWRecord>, _>>()
        .unwrap();

    for record in records
        .into_iter()
        .filter(|r| prefixes.contains(&r.prefix.into()))
        .sorted_by(|a, b| a.time.total_cmp(&b.time))
    {
        if record.time < event_start - 1.0 {
            log::trace!("skipping pre-event changes: {record:?}");
            continue;
        }

        let prefix = Prefix::from(record.prefix);
        let prefix_trace = trace.entry(prefix).or_default();

        // fix event start if necessary
        if let Some(first) = prefix_trace.first() {
            let t = first.1.into_inner().unwrap();
            if record.time < t && t == event_start {
                prefix_trace[0].1 = Some(record.time).into()
            }
        }

        // for all other updates, ensure we are going in chronological order
        if let Some(last) = prefix_trace.last() {
            assert!(record.time >= last.1.into_inner().unwrap());
        }

        let old_nhs = prefix_trace
            .iter()
            .rev()
            // check if nhs have been changed already
            .find_map(|(fw_deltas, _time)| {
                fw_deltas.iter().find_map(|(rid, _old_nhs, new_nhs)| {
                    (*rid == record.src).then_some(new_nhs.clone())
                })
            })
            // or query the original fw_state
            .unwrap_or(fw_state.get_next_hops(record.src, prefix).to_vec());
        let new_nhs: Vec<_> = record.next_hop.into_iter().collect();
        if old_nhs == new_nhs {
            log::trace!(
                "skipping because old nhs {} == new nhs {} at router {}",
                old_nhs.fmt(&analyzer.original_net),
                new_nhs.fmt(&analyzer.original_net),
                record.src.fmt(&analyzer.original_net),
            );
            continue;
        }
        let fw_delta = (record.src, old_nhs, new_nhs);

        prefix_trace.push((vec![fw_delta], Some(record.time).into()));
    }

    Ok(trace)
}

/// Evaluate forwarding updates of one sample with the baseline and the interval algorithm. Also
/// computes the total convergence time.
#[allow(clippy::type_complexity)]
fn evaluate_time_series_of_fw_updates(
    analyzer: &Analyzer<TimingModel<Prefix>>,
    event_start: f64,
    evaluated_prefixes: &HashSet<Prefix>,
    transient_policies: &HashMap<(RouterId, Prefix), Vec<TransientPolicy>>,
    eval_path: &Path,
    fw_updates_path: impl AsRef<Path>,
) -> Result<
    (HashMap<TransientPolicy, f64>, HashMap<TransientPolicy, f64>),
    Box<dyn std::error::Error>,
> {
    // original forwarding state
    let mut fw_state = analyzer.original_fw.clone();

    // read the time series of forwarding states from the csv
    let trace = build_trace_from_fw_updates(
        analyzer,
        event_start,
        evaluated_prefixes,
        &fw_updates_path,
        &mut fw_state,
    )?;

    let mut queue = analyzer.build_queue();

    let intervals_csv_path = fw_updates_path
        .as_ref()
        .file_name()
        .map(|fw_updates_filename| {
            let mut path = eval_path.to_path_buf();
            path.push("intervals");
            fs::create_dir_all(&path).unwrap();
            path.push(
                fw_updates_filename
                    .to_string_lossy()
                    .replace("fw_updates_", "path_intervals_"),
            );
            path
        });

    Ok((
        // call the baseline algorithm
        compute_baseline(
            &analyzer.original_net,
            &mut queue,
            &mut fw_state,
            &trace,
            transient_policies,
        ),
        // call the interval algorithm
        compute_violation_times(
            &analyzer.original_net,
            &mut queue,
            &mut fw_state,
            &trace,
            transient_policies,
            intervals_csv_path,
        ),
    ))
}

/// Evaluate forwarding updates for all samples of a scenario.
fn evaluate_fw_updates(
    topo_name: &str,
    scenario_name: &str,
    eval_path: &Path,
    sample_id: &str,
    replace: bool,
) {
    let Ok(analyzer) = util::get_analyzer(topo_name, scenario_name) else {
        log::trace!("Could not build `Analyzer` for experiment in {topo_name}/{scenario_name}.");
        return; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
    };

    for record in util::get_records(eval_path).unwrap().deserialize() {
        let record: CiscoAnalyzerData = record.unwrap();
        log::trace!("Reading from CSV:\n{record:#?}");

        if !record.execution_timestamp.contains(sample_id) {
            log::trace!(
                "skipping sample {topo_name}/{scenario_name} -> {} due to filter on sample_id",
                record.pcap_filename
            );
            continue;
        }

        if eval_path
            .then(format!("skip_{}", record.pcap_filename))
            .exists()
        {
            log::debug!("skipping sample {topo_name}/{scenario_name} -> {} due to errors parsing prober packets", record.pcap_filename);
            continue;
        }

        if eval_path
            .then(format!("bgp_updates_{}.skip", record.pcap_filename))
            .exists()
        {
            log::debug!("skipping sample {topo_name}/{scenario_name} -> {} due to errors parsing BGP messages", record.pcap_filename);
            continue;
        }

        let eval_skip_file = eval_path.then(format!("eval_{}.skip", record.pcap_filename));
        if eval_skip_file.exists() {
            if replace {
                fs::remove_file(&eval_skip_file).unwrap();
            } else {
                log::debug!(
                    "skipping sample {topo_name}/{scenario_name} -> {} due to errors in evaluation",
                    record.pcap_filename
                );
                continue;
            }
        }

        let csv_path = eval_path.then(format!("eval_{}.csv", record.pcap_filename));
        if csv_path.exists() && !replace {
            log::trace!(
                "skipping {topo_name}/{scenario_name} -> {} as it has been processed already",
                record.pcap_filename
            );
            continue;
        }

        let path_updates_path =
            eval_path.then(format!("path_updates_new_{}.csv", record.pcap_filename));
        if !path_updates_path.exists() {
            log::trace!(
                "skipping {topo_name}/{scenario_name} -> {} due to missing data",
                record.pcap_filename
            );
            continue;
        }

        // Create / overwrite eval data for this sample
        let mut csv = csv::WriterBuilder::new()
            .has_headers(true)
            .delimiter(b';')
            .from_writer(
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&csv_path)
                    .unwrap(),
            );

        // read evaluated prefixes from the path updates
        let path_updates: Vec<_> = csv::ReaderBuilder::new()
            .delimiter(b';')
            .from_path(&path_updates_path)
            .unwrap()
            .deserialize::<PathRecord>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let total_convergence_time = path_updates
            .iter()
            .max_by(|a, b| a.time.total_cmp(&b.time))
            .unwrap()
            .time
            - path_updates
                .iter()
                .min_by(|a, b| a.time.total_cmp(&b.time))
                .unwrap()
                .time;
        let evaluated_prefixes: HashSet<_> = path_updates
            .iter()
            .map(|path_record| Prefix::from(path_record.prefix))
            .unique()
            .collect();

        // reduce considered transient policies to the probed prefixes
        let transient_policies: HashMap<(RouterId, Prefix), Vec<TransientPolicy>> = analyzer
            .policies
            .iter()
            .cloned()
            .into_group_map_by(|p| (p.router(), p.prefix()))
            .into_iter()
            .filter_map(|(k, v)| match k {
                (Some(r), Some(p)) => Some(((r, p), v)),
                _ => None,
            })
            .filter(|((_, p), _)| evaluated_prefixes.contains(p))
            .collect();

        log::debug!("Computing the ground truth from {path_updates_path:?}");

        // get ground truth violation times from path updates
        let violations_from_path_updates = match check_path_updates(
            &path_updates,
            &transient_policies,
        ) {
            Ok(violations) => violations,
            Err(EvaluationError::PersistentViolation(violated_policy)) => {
                let err = format!("skipping sample {topo_name}/{scenario_name} -> {} due to persistently violated policy {violated_policy:?}", record.pcap_filename);
                log::warn!("{err}");
                std::fs::write(eval_skip_file, err.into_bytes()).unwrap();
                if csv_path.exists() {
                    fs::remove_file(&csv_path).unwrap();
                }

                continue;
            }
            Err(EvaluationError::NoData) => {
                log::warn!("skipping sample {topo_name}/{scenario_name} -> {} due to missing data in {path_updates_path:?}", record.pcap_filename);
                continue;
            }
        };

        // load each time series of fw states and write `EvaluationRecord`s to a new csv
        let path = eval_path.then(format!(
            "time_series_of_forwarding_states_{}",
            record.execution_timestamp
        ));
        let fw_file = eval_path.then(format!("fw_updates_new_{}.csv", record.pcap_filename));
        if !fw_file.exists() {
            log::debug!(
                "skipping sample {topo_name}/{scenario_name} -> {} due to missing {fw_file:?}",
                record.pcap_filename
            );
            continue;
        }
        let sources: Vec<_> = if path.exists() {
            fs::read_dir(path)
                .unwrap()
                .map(|x| x.unwrap().path())
                .collect()
        } else {
            Vec::new()
        };
        let robustness: Vec<_> = if fw_file.exists() {
            [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
                .map(|delay_ms| {
                    let path = fw_file
                        .file_name()
                        .map(|fw_updates_filename| {
                            let mut path = eval_path.to_path_buf();
                            path.push(
                                fw_updates_filename
                                    .to_string_lossy()
                                    .replace("fw_updates_new_", "robustness_")
                                    .replace(".pcap.gz.csv", ""),
                            );
                            fs::create_dir_all(&path).unwrap();
                            path.push(format!("fw_modified_{delay_ms}.csv"));
                            path
                        })
                        .expect("fw_file should have a filename");

                    if !path.exists() || replace {
                        modify_fw_updates(&fw_file, &path, delay_ms).unwrap();
                    }

                    path
                })
                .to_vec()
        } else {
            Vec::new()
        };
        for fw_file in once(fw_file)
            .chain(sources.into_iter())
            .chain(robustness.into_iter())
        {
            log::trace!("evaluating fw_file: {fw_file:?}");
            let filename = fw_file.file_name().unwrap().to_string_lossy().to_string();

            let Ok((baseline_violations, interval_alg_violations)) =
                evaluate_time_series_of_fw_updates(
                    &analyzer,
                    record.event_start,
                    &evaluated_prefixes,
                    &transient_policies,
                    eval_path,
                    fw_file,
                )
            else {
                log::trace!(
                    "skipping {} because forwarding updates could not be processed properly ...",
                    record.pcap_filename
                );
                continue;
            };

            for ((rid, prefix), policy) in transient_policies
                .iter()
                .flat_map(|(k, policies)| policies.iter().map(|policy| (*k, policy)))
            {
                let measured = violations_from_path_updates
                    .get(policy)
                    .copied()
                    .unwrap_or_default();
                let baseline = baseline_violations.get(policy).copied().unwrap_or_default();
                let computed = interval_alg_violations
                    .get(policy)
                    .copied()
                    .unwrap_or_default();

                // compute errors
                let err_baseline = measured - baseline;
                let err = measured - computed;
                let abs_err_baseline = err_baseline.abs();
                let abs_err = err.abs();
                let rel_err_baseline = abs_err_baseline
                                // compute with the mean of measured and computed, to avoid "infty"
                                // values if measured is 0
                                / ((measured + baseline) / 2.0)
                        // remove NANs
                        .max(0.0);
                let rel_err = abs_err
                                // compute with the mean of measured and computed, to avoid "infty"
                                // values if measured is 0
                                / ((measured + computed) / 2.0)
                        // remove NANs
                        .max(0.0);
                let rel_err_total_baseline = abs_err_baseline / total_convergence_time;
                let rel_err_total = abs_err / total_convergence_time;

                csv.serialize(EvaluationRecord {
                    model: if filename.starts_with("fw_updates_") {
                        "fw_updates".to_string()
                    } else {
                        filename.clone()
                    },
                    sample_id: record.execution_timestamp.clone(),
                    num_prefixes: util::get_num_prefixes(scenario_name).unwrap(),
                    scenario: scenario_name.to_string(),
                    rid,
                    router: Router::from_str(rid.fmt(&analyzer.original_net)).ok(),
                    prefix,
                    measured,
                    baseline,
                    computed,
                    err_baseline,
                    err,
                    rel_err_baseline,
                    rel_err,
                    abs_err_baseline,
                    abs_err,
                    rel_err_total_baseline,
                    rel_err_total,
                })
                .unwrap();
            }
            csv.flush().unwrap();
        }
    }
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Overwrite the input path for data.
    #[arg(short, long, default_value = "./data/")]
    data_root: String,
    /// Overwrite the topology filter for extracting BGP updates.
    #[arg(short, long, default_value = "Abilene")]
    topo: String,
    /// Overwrite the scenario filter for extracting BGP updates.
    #[arg(short, long, default_value = "")]
    scenario: String,
    /// Overwrite the scenario_end filter for extracting BGP updates.
    #[arg(short = 'e', long = "scenario-end", default_value = "")]
    scenario_end: String,
    /// Overwrite the scenario_id filter for extracting BGP updates.
    #[arg(short = 'i', long = "sample", default_value = "")]
    sample_id: String,
    /// Replace all files, instead of skipping those that already exist
    #[arg(long)]
    replace: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    util::init_logging();

    let args = Args::parse();

    util::process_data(
        args.data_root,
        Filter {
            topo: args.topo,
            scenario: args.scenario,
            scenario_end: args.scenario_end,
            sample_id: "".to_string(),
        },
        |topo_name, scenario_name, eval_path| {
            evaluate_fw_updates(
                topo_name,
                scenario_name,
                eval_path,
                &args.sample_id,
                args.replace,
            )
        },
    );

    Ok(())
}
