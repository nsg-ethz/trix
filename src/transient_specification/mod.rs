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
use std::{collections::HashMap, fs, net::Ipv4Addr, str::FromStr};

use bgpsim::{
    event::{EventQueue, FmtPriority},
    forwarding_state::ForwardingState,
    policies::Policy,
    prelude::*,
};

use crate::{
    records::{PathRecord, Router},
    timing_model::TimingModel,
    MultiPrefixConvergenceTrace, Prefix, PrefixTrace,
};

mod path;
mod policy;

use path::*;
pub use policy::TransientPolicy;

/// maximum number of hops considered for data-plane packets
const MAX_HOPS: usize = 25;

pub type Interval = (f64, f64, Path);

/// Performs a data-plane simulation based on the global-perspective time-series of forwarding
/// states. In other words, this algorithm computes the transient violation times enountered by a
/// network during convergence, if traffic would traverse the network at infinite speed.
pub fn compute_baseline<Q>(
    net: &Network<Prefix, Q>,
    queue: &mut TimingModel<Prefix>,
    fw_state: &mut ForwardingState<Prefix>,
    trace: &MultiPrefixConvergenceTrace,
    transient_policies: &HashMap<(RouterId, Prefix), Vec<TransientPolicy>>,
) -> HashMap<TransientPolicy, f64>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
{
    // Initialize a list of violation times to return at the end
    let mut violation_times = HashMap::new();

    // traverse all concerned prefixes
    for (prefix, prefix_trace) in trace {
        let route_intervals = compute_baseline_for_prefix(
            &mut IAParams {
                net,
                queue,
                fw_state,
            },
            prefix,
            prefix_trace,
        );

        check_route_intervals(
            prefix,
            &route_intervals,
            &mut violation_times,
            transient_policies,
        );
    }

    log::trace!(
        "[transient-analyzer] violation_times:\n{:#?}",
        violation_times
    );

    violation_times
}

/// Performs a data-plane simulation based on the global-perspective time-series of forwarding
/// states for the given prefix. In other words, this algorithm computes the transient violation
/// times encountered by a network during convergence, if traffic would traverse the network at
/// infinite speed.
fn compute_baseline_for_prefix<Q>(
    params: &mut IAParams<'_, Q>,
    prefix: &Prefix,
    prefix_trace: &PrefixTrace,
) -> HashMap<RouterId, Vec<Interval>>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
{
    // get the first and last event's time from the `MultiPrefixConvergenceTrace`
    assert!(!prefix_trace.is_empty());
    let t_first_event = prefix_trace[0].1.into_inner().unwrap();

    // init all route_intervals as t_first with the initial path
    let mut route_intervals: HashMap<RouterId, Vec<(f64, Path)>> =
        HashMap::from_iter(params.net.internal_routers().flat_map(|r| {
            let paths = params.fw_state.get_paths(r.router_id(), *prefix).unwrap();
            if paths.len() > 1 {
                todo!("extend algorithm for load-balancing!");
            }
            let mut intervals = Vec::new();
            for path in paths.iter() {
                intervals.push((
                    r.router_id(),
                    vec![(t_first_event, Path::Route(path.clone()))],
                ));
            }
            intervals
        }));

    // traverse the time series of forwarding states and split the route_intervals as required
    for (fw_deltas, time) in prefix_trace.iter() {
        // assume single updates per step
        assert_eq!(fw_deltas.len(), 1);
        let (affected_router, _, new_nh) = fw_deltas.first().unwrap();
        // assume no multi-path
        assert!(new_nh.len() <= 1);

        log::trace!(
            "\n[t = {}] FW-UPDATE at {}: new_nh: {}",
            time.as_ref().unwrap(),
            affected_router.fmt(params.net),
            new_nh.fmt(params.net),
        );

        params
            .fw_state
            .update(*affected_router, *prefix, new_nh.clone());

        for r in params.net.internal_indices() {
            let path = get_path_from_fw_state(&r, prefix, params.fw_state);
            let intervals = route_intervals.get_mut(&r).unwrap();
            if intervals.last().unwrap().1 != path {
                intervals.push((time.as_ref().unwrap(), path));
            }
        }
    }

    // reset the `ForwardingState` after handling each prefix
    for (fw_deltas, _) in prefix_trace.iter().rev() {
        for (affected_router, old_nh, _) in fw_deltas {
            params
                .fw_state
                .update(*affected_router, *prefix, old_nh.clone());
        }
    }
    route_intervals
        .into_iter()
        .map(|(rid, updates)| {
            let t_ends: Vec<_> = updates.iter().map(|(t, _)| *t).skip(1).collect();
            let intervals = updates
                .into_iter()
                .zip(t_ends)
                .map(|((t_start, path), t_end)| (t_start, t_end, path))
                .collect();
            (rid, intervals)
        })
        .collect()
}

/// Compute the propagation delay experienced on a given path.
///
/// TODO: implement caching, potentially spanning multiple runs as this only depends on the path
/// taken.
fn propagation_delay(queue: &mut TimingModel<Prefix>, path: &[RouterId]) -> f64 {
    if path.len() <= 1 {
        return 0.0;
    }
    queue.get_delay(path[0], path[1]) + propagation_delay(queue, &path[1..])
}

/// Performs a time-interval based data-plane simulation, computing along which route(s) traffic
/// sent at time t from any router is forwarded towards the destination.
///
/// This works as we know that traffic sent from a router before time `t_first_event` minus the
/// propagation delay of the router's initial path, and traffic sent after `t_last_event` may not
/// experience any violation.
///
/// Note that the paths taken through the network may not necessarily coincide with paths observed
/// in any of the forwarding states. This may be caused by convergence updates during a packet's
/// network traversal.
pub fn compute_violation_times<Q, PathRef>(
    net: &Network<Prefix, Q>,
    queue: &mut TimingModel<Prefix>,
    fw_state: &mut ForwardingState<Prefix>,
    trace: &MultiPrefixConvergenceTrace,
    transient_policies: &HashMap<(RouterId, Prefix), Vec<TransientPolicy>>,
    log_intervals_path: Option<PathRef>,
) -> HashMap<TransientPolicy, f64>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
    PathRef: AsRef<std::path::Path>,
{
    // Initialize a list of violation times to return at the end
    let mut violation_times = HashMap::new();

    // Initialize logger to write computed path intervals if `log_intervals_path` is given.
    let mut csv = log_intervals_path.map(|csv_path| {
        log::trace!(
            "[transient-analyzer] writing intervals to {:?}...",
            csv_path.as_ref()
        );
        csv::WriterBuilder::new()
            .has_headers(true)
            .delimiter(b';')
            .from_writer(
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(csv_path)
                    .unwrap(),
            )
    });

    // traverse all concerned prefixes
    for (prefix, prefix_trace) in trace {
        log::debug!(
            "Running intervall algorithm for prefix {} with {} updates",
            Ipv4Addr::from(*prefix),
            prefix_trace.len()
        );
        let route_intervals = compute_violation_times_for_prefix(
            &mut IAParams {
                net,
                queue,
                fw_state,
            },
            prefix,
            prefix_trace,
        );

        check_route_intervals(
            prefix,
            &route_intervals,
            &mut violation_times,
            transient_policies,
        );

        if let Some(ref mut csv) = csv {
            // write computed path updates to a file
            for (src, intervals) in route_intervals {
                for (time, _t_end, path) in intervals {
                    csv.serialize(PathRecord {
                        time,
                        src,
                        src_name: Router::from_str(src.fmt(net)).ok(),
                        prefix: Ipv4Addr::from(*prefix),
                        path: path.get_rid_vec(),
                        seq: None,
                        path_names: path
                            .get_rid_vec()
                            .into_iter()
                            .map(|rid| Router::from_str(rid.fmt(net)).ok())
                            .collect(),
                    })
                    .unwrap();
                }
            }
            csv.flush().unwrap();
        }
    }

    log::trace!(
        "[transient-analyzer] violation_times:\n{:#?}",
        violation_times
    );

    violation_times
}

struct IAParams<'a, Q> {
    net: &'a Network<Prefix, Q>,
    queue: &'a mut TimingModel<Prefix>,
    fw_state: &'a mut ForwardingState<Prefix>,
}

/// Performs a time-interval based data-plane simulation, computing along which route(s) traffic
/// sent at time t from any router is forwarded towards the given destination prefix.
///
/// This works as we know that traffic sent from a router before time `t_first_event` minus the
/// propagation delay of the router's initial path, and traffic sent after `t_last_event` may not
/// experience any violation.
///
/// Note that the paths taken through the network may not necessarily coincide with paths observed
/// in any of the forwarding states. This may be caused by convergence updates during a packet's
/// network traversal.
fn compute_violation_times_for_prefix<Q>(
    params: &mut IAParams<'_, Q>,
    prefix: &Prefix,
    prefix_trace: &PrefixTrace,
) -> HashMap<RouterId, Vec<Interval>>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
{
    // get the first and last event's time from the `MultiPrefixConvergenceTrace`
    assert!(!prefix_trace.is_empty());
    let t_first_event = prefix_trace[0].1.into_inner().unwrap();
    let t_last_event = prefix_trace[prefix_trace.len() - 1].1.into_inner().unwrap();

    // init all route_intervals as (t_first - propagation_delay(path), t_last)
    let mut route_intervals = HashMap::from_iter(params.net.internal_routers().flat_map(|r| {
        let paths = params.fw_state.get_paths(r.router_id(), *prefix).unwrap();
        if paths.len() > 1 {
            todo!("extend algorithm for load-balancing!");
        }
        let mut intervals = Vec::new();
        for path in paths.iter() {
            intervals.push((
                r.router_id(),
                vec![(
                    t_first_event - propagation_delay(params.queue, path),
                    t_last_event,
                    Path::Route(path.clone()),
                )],
            ));
        }
        intervals
    }));

    // traverse the time series of forwarding states and split the route_intervals as required
    for (fw_deltas, time) in prefix_trace.iter() {
        // assume single updates per step
        assert_eq!(fw_deltas.len(), 1);
        let (affected_router, _, new_nh) = fw_deltas.first().unwrap();
        // assume no multi-path
        assert!(new_nh.len() <= 1);

        log::trace!(
            "\n[t = {}] FW-UPDATE at {}: new_nh: {}",
            time.as_ref().unwrap(),
            affected_router.fmt(params.net),
            new_nh.fmt(params.net),
        );

        params
            .fw_state
            .update(*affected_router, *prefix, new_nh.clone());

        // get new path slice that will be experienced by the traffic from the
        // `affected_router` onwards
        let path_suffix = get_path_from_fw_state(affected_router, prefix, params.fw_state);

        for r in params.net.internal_routers() {
            let intervals = route_intervals.get_mut(&r.router_id()).unwrap();
            *intervals = split_intervals(
                params,
                time.as_ref().unwrap(),
                affected_router,
                &path_suffix,
                std::mem::take(intervals),
            );
        }
    }

    // reset the `ForwardingState` after handling each prefix
    for (fw_deltas, _) in prefix_trace.iter().rev() {
        for (affected_router, old_nh, _) in fw_deltas {
            params
                .fw_state
                .update(*affected_router, *prefix, old_nh.clone());
        }
    }
    route_intervals
}

/// Find the interval(s) which are affected by a forwarding change at `affected_router`.
///
/// Note that:
/// - we traverse the series of forwarding states in chronological order, so no interval can
/// have a starting time larger than the given time thus far --> no need to filter these out
/// - we have to consider intervals even when their ending time has passed already, since
/// traffic may still be in-flight
///
/// TODO: consider optimizing by moving completed flows to a different data structure
/// keep the modified intervals separately
fn split_intervals<Q>(
    params: &mut IAParams<'_, Q>,
    time: f64,
    affected_router: &RouterId,
    path_suffix: &Path,
    route_intervals: Vec<Interval>,
) -> Vec<Interval>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
{
    route_intervals
        .into_iter()
        .flat_map(|x| {
            split_interval(
                time,
                affected_router,
                |p| propagation_delay(params.queue, p),
                path_suffix,
                x.clone(),
            )
        })
        .collect()
}

/// Apply a forwarding change at `affected_router` to a specific given interval, if necessary.
fn split_interval<F>(
    t_fw_change: f64,
    affected_router: &RouterId,
    mut prop_delay: F,
    path_suffix: &Path,
    (t_start, t_end, path): Interval,
) -> Vec<Interval>
where
    F: FnMut(&[RouterId]) -> f64,
{
    let mut intervals = Vec::new();
    let mut t_end_remaining = t_end;

    // iterate over all potential path prefixes, in increasing length
    for path_prefix in path.all_splits_bounded(affected_router, MAX_HOPS) {
        let prop = prop_delay(&path_prefix);
        let new_path = Path::Route(path_prefix).combine_with(path_suffix);

        // if traffic would have passed before the fw change,
        if t_end_remaining + prop <= t_fw_change {
            // do nothing and try a longer prefix.
            continue;
        }

        // if traffic would have passed after the fw change,
        if t_start + prop >= t_fw_change {
            // entire remaining interval is affected
            intervals.push((t_start, t_end_remaining, new_path));
            t_end_remaining = t_start;
            break;
        }

        // otherwise, split the interval
        let t_split = t_fw_change - prop;
        // - traffic from t_split to t_end_remaining already reaches the new path
        intervals.push((t_split, t_end_remaining, new_path));
        // - traffic from t_start to t_split still follows the old path
        t_end_remaining = t_split;
    }

    if t_start != t_end_remaining {
        // either some (or all!) traffic of this interval remains on the original path
        intervals.push((t_start, t_end_remaining, path));
    }
    intervals.reverse();
    intervals
}

/// Checks a given csv file with `PathRecord`s for violations with the given `transient_policies`.
/// Uses the router_names property and `Router::is_external()` to determine whether a route is
/// reaching the destination, or not and adequately generating a `Path::Route` or `Path::BlackHole`.
pub fn check_path_updates(
    path_updates: &[PathRecord],
    transient_policies: &HashMap<(RouterId, Prefix), Vec<TransientPolicy>>,
) -> Result<HashMap<TransientPolicy, f64>, EvaluationError> {
    let mut violation_times = HashMap::new();
    let mut last_records: HashMap<(RouterId, Ipv4Addr), (f64, Path)> = HashMap::new();
    for PathRecord {
        time,
        src,
        path,
        path_names,
        prefix,
        ..
    } in path_updates
    {
        // Remove and process last interval for this flow
        if let Some((last_time, path)) = last_records.remove(&(*src, *prefix)) {
            assert!(time - last_time >= 0.0);

            if let Some(policies) = transient_policies.get(&(*src, Prefix::from(*prefix))) {
                for policy in policies {
                    // check and add violation times
                    if !policy.check_path(&path) {
                        *violation_times.entry(policy.clone()).or_default() += time - last_time;
                    }
                }
            }
        }

        // Store new path for this flow
        let is_route = path_names
            .last()
            .cloned()
            .flatten()
            .map(|last_hop| last_hop.is_external())
            .unwrap_or(false);
        let path = if is_route {
            Path::Route(path.clone())
        } else {
            Path::BlackHole(path.clone())
        };
        last_records.insert((*src, *prefix), (*time, path));
    }

    // check that the policies are satisfied in the end
    for ((src, prefix), (_, path)) in last_records.into_iter() {
        log::debug!("checking path {path:?}...");

        // ensure there is no persistent violation
        if let Some(policies) = transient_policies.get(&(src, Prefix::from(prefix))) {
            if let Some(violated_policy) = policies.iter().find(|policy| !policy.check_path(&path))
            {
                log::error!("FAILED! path {path:?} violates {violated_policy:?}");
                return Err(EvaluationError::PersistentViolation(
                    violated_policy.clone(),
                ));
            }
        }
        log::trace!("success.");
    }

    Ok(violation_times)
}

/// Error type thrown while evaluating forwarding updates.
#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    /// Error when no csv file path was given.
    #[error("No data was given to the evaluation function")]
    NoData,
    /// Error when the last forwarding state doesn't satisfy all policies
    #[error("The violation of policy {0:?} did not end, but ended up being persistend instead!")]
    PersistentViolation(TransientPolicy),
}

/// Check all route intervals for violations of each transient_policy
fn check_route_intervals(
    prefix: &Prefix,
    route_intervals: &HashMap<RouterId, Vec<Interval>>,
    violation_times: &mut HashMap<TransientPolicy, f64>,
    transient_policies: &HashMap<(RouterId, Prefix), Vec<TransientPolicy>>,
) {
    transient_policies
        .iter()
        .filter(|((_, p), _)| p == prefix)
        .for_each(|(_, policies)| {
            for policy in policies.iter() {
                let rid = policy
                    .router()
                    .expect("Did not expect a policy that doesn't concern a dedicated router!");
                for (t_start, t_end, path) in route_intervals.get(&rid).unwrap().iter() {
                    // check and add violation times
                    if !policy.check_path_no_loops_of_length_2(path) {
                        assert!(t_end - t_start >= 0.0);
                        *violation_times.entry(policy.clone()).or_default() += t_end - t_start;
                    }
                }
            }
        });
}

fn get_path_from_fw_state(
    affected_router: &RouterId,
    prefix: &Prefix,
    fw_state: &mut ForwardingState<Prefix>,
) -> Path {
    match fw_state.get_paths(*affected_router, *prefix) {
        Ok(paths) => {
            if paths.len() > 1 {
                todo!("extend algorithm for load-balancing!");
            }
            Path::Route(paths[0].clone())
        }
        Err(NetworkError::ForwardingBlackHole(path)) => Path::BlackHole(path),
        Err(NetworkError::ForwardingLoop {
            mut to_loop,
            first_loop,
        }) => {
            to_loop.push(first_loop[0]);
            Path::Loop(to_loop, first_loop)
        }
        _ => unreachable!("Other errors should not occur!"),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn prop(p: &[RouterId]) -> f64 {
        (p.len() - 1) as f64
    }

    #[test]
    fn split_loop() {
        #[allow(non_snake_case)]
        let (A, B, C, D) = (
            RouterId::from(1),
            RouterId::from(2),
            RouterId::from(3),
            RouterId::from(4),
        );
        assert_eq!(
            split_interval(
                0.0,
                &B,
                prop,
                &Path::Loop(vec![B], vec![B, C]),
                (-5.0, 8.0, Path::Route(vec![A, B, D])),
            ),
            vec![
                (-5.0, -1.0, Path::Route(vec![A, B, D])),
                (-1.0, 8.0, Path::Loop(vec![A, B], vec![B, C])),
            ]
        );
        assert_eq!(
            split_interval(
                9.0,
                &B,
                prop,
                &Path::Route(vec![B, D]),
                (1.0, 5.0, Path::Loop(vec![A, B], vec![B, C])),
            ),
            vec![
                (1.0, 2.0, Path::Route(vec![A, B, C, B, C, B, C, B, C, B, D])),
                (2.0, 4.0, Path::Route(vec![A, B, C, B, C, B, C, B, D])),
                (4.0, 5.0, Path::Route(vec![A, B, C, B, C, B, D])),
            ]
        );
    }

    #[test]
    fn prev_fw_change() {
        #[allow(non_snake_case)]
        let (A, B, C, D) = (
            RouterId::from(1),
            RouterId::from(2),
            RouterId::from(3),
            RouterId::from(4),
        );
        assert_eq!(
            split_interval(
                0.0,
                &B,
                prop,
                &Path::Route(vec![B, D]),
                (0.0, 5.0, Path::BlackHole(vec![A, B])),
            ),
            vec![(0.0, 5.0, Path::Route(vec![A, B, D]))]
        );
        assert_eq!(
            split_interval(
                0.0,
                &B,
                prop,
                &Path::Route(vec![B, D]),
                (0.0, 5.0, Path::Loop(vec![A, B], vec![B, C])),
            ),
            vec![(0.0, 5.0, Path::Route(vec![A, B, D]))]
        );
    }
}
