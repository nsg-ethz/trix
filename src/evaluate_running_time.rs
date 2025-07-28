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
#![allow(clippy::type_complexity)]

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use trix::{
    prelude::{TimingModel, TransientPolicy},
    transient_specification::{compute_baseline, compute_violation_times},
    MultiPrefixConvergenceTrace,
};
use bgpsim::{
    builder::{k_random_nodes_seeded, uniform_link_weight_seeded},
    forwarding_state::ForwardingState,
    interactive::InteractiveNetwork,
    policies::FwPolicy,
    prelude::*,
    topology_zoo::TopologyZoo,
    types::StepUpdate,
};
use geoutils::Location;
use indicatif::{MultiProgress, ParallelProgressIterator, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use itertools::{iproduct, Itertools, MinMaxResult};
use rand::prelude::*;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
enum Event {
    Withdraw,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Scenario {
    topo: TopologyZoo,
    seed: u64,
    keep_other: bool,
    event: Event,
    num_prefixes: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Record {
    topo: TopologyZoo,
    num_nodes: usize,
    num_edges: usize,
    seed: u64,
    keep_other: bool,
    event: Event,
    num_prefixes: usize,
    trigger: String,
    backup: String,
    time_baseline: f64,
    time_alg: f64,
}

type Prefix = SimplePrefix;
type Net<Q> = Network<Prefix, Q, GlobalOspf>;

fn main() -> Result<()> {
    let logger = pretty_env_logger::formatted_builder().build();
    let multi = MultiProgress::new();
    LogWrapper::new(multi.clone(), logger).try_init().unwrap();

    let topos = TopologyZoo::topologies_increasing_nodes()
        .iter()
        .copied()
        .filter(|t| t.num_internals() > 10);
    let scenarios: Vec<Scenario> = iproduct!(
        [1, 10, 100, 1000], // num_prefixes
        topos,              // topo
        [1, 2, 3, 4, 5],    // seed
        [true, false],      // keep other
        [Event::Withdraw]   // event
    )
    .map(|(num_prefixes, topo, seed, keep_other, event)| Scenario {
        topo,
        seed,
        keep_other,
        event,
        num_prefixes,
    })
    .collect();

    log::info!(
        "Evaluating the running-time on {} scenarios",
        scenarios.len()
    );

    let writer = Arc::new(Mutex::new(
        csv::Writer::from_path("eval_running_time.csv").unwrap(),
    ));

    let pb = multi.add(
        ProgressBar::new(scenarios.len() as u64)
            .with_style(ProgressStyle::with_template("[{bar:80}] iter: {pos:>7}/{len:7}, elapsed: {elapsed}, eta: {eta}, speed: {per_sec}").unwrap().progress_chars("##-")),
    );

    scenarios
        .into_par_iter()
        .progress_with(pb)
        .map_with(writer, |writer, s| {
            process_scenario_wrapper(s, writer.clone())
        })
        .collect::<Vec<Result<()>>>()
        .into_iter()
        .collect::<Result<Vec<_>>>()?;

    Ok(())
}

fn process_scenario_wrapper<W: std::io::Write>(
    scenario: Scenario,
    writer: Arc<Mutex<csv::Writer<W>>>,
) -> Result<()> {
    match process_scenario(scenario, writer) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::warn!("Cannot process {scenario:?}\n{e:?}");
            Err(e.context(format!("Error processing {scenario:?}")))
        }
    }
}

fn process_scenario<W: std::io::Write>(
    scenario: Scenario,
    writer: Arc<Mutex<csv::Writer<W>>>,
) -> Result<()> {
    log::info!("Processing {scenario:?}");
    // set the seed
    let mut rng = StdRng::seed_from_u64(scenario.seed);

    // setup the network
    let (net, trigger, trigger_name, _backup, backup_name, transient_policies) =
        establish_initial_state(scenario, &mut rng)
            .context("Error while creating the network and the intial state")?;
    // generate the queue
    let geo_location = get_geo_location(scenario, &net, &mut rng);
    let mut queue = TimingModel::from_geo_location(&geo_location);

    // trigger the event
    let initial_net = net.clone();
    let mut net = net.swap_queue(queue.clone()).unwrap();
    let mut fw_state = net.get_forwarding_state();
    if check_fw_state(&net, &mut fw_state).is_err() {
        log::warn!("Skipping {scenario:?} due to missing connectivity");
        return Ok(());
    }
    prepare_event(scenario, &mut net, trigger).context("Cannot trigger the event")?;

    // generate the sequence of forwarding states
    let trace = build_trace(&mut net);

    // analyze the trace
    let start = Instant::now();
    let _ = compute_violation_times(
        &initial_net,
        &mut queue,
        &mut fw_state.clone(),
        &trace,
        &transient_policies,
        None::<&Path>,
    );
    let time_alg = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let _ = compute_baseline(
        &initial_net,
        &mut queue,
        &mut fw_state.clone(),
        &trace,
        &transient_policies,
    );
    let time_baseline = start.elapsed().as_secs_f64();

    let record = Record {
        topo: scenario.topo,
        num_nodes: scenario.topo.num_internals(),
        num_edges: scenario.topo.num_internal_edges(),
        seed: scenario.seed,
        keep_other: scenario.keep_other,
        event: scenario.event,
        num_prefixes: scenario.num_prefixes,
        trigger: trigger_name,
        backup: backup_name,
        time_baseline,
        time_alg,
    };

    // store the results
    {
        let mut csv = writer.lock().unwrap();
        csv.serialize(record)
            .context("Cannot write the record to file")?;
        csv.flush().context("Error writing the record to file")?;
    }

    Ok(())
}

fn establish_initial_state(
    scenario: Scenario,
    rng: &mut StdRng,
) -> Result<(
    Net<BasicEventQueue<Prefix>>,
    RouterId,
    String,
    RouterId,
    String,
    HashMap<(RouterId, Prefix), Vec<TransientPolicy>>,
)> {
    // generate the network
    let mut net: Net<BasicEventQueue<_>> = scenario.topo.build(Default::default());
    net.build_link_weights_seeded(rng, uniform_link_weight_seeded, (1.0, 10.0))?;
    net.build_ibgp_full_mesh()?;
    let externals = net.build_external_routers(k_random_nodes_seeded, (rng, 2))?;
    net.build_ebgp_sessions()?;

    let trigger = externals[0];
    let backup = externals[1];

    let mut policies = HashMap::new();

    // generate the initial state of the network
    for p in 0..scenario.num_prefixes {
        let p = Prefix::from(p);
        let trigger_path = vec![100];
        net.advertise_external_route(trigger, p, vec![100], None, None)?;

        let backup_path = if scenario.keep_other {
            vec![200, 200]
        } else {
            vec![200]
        };
        net.advertise_external_route(trigger, p, trigger_path, None, None)?;
        net.advertise_external_route(backup, p, backup_path, None, None)?;

        for r in net.internal_indices() {
            policies.insert(
                (r, p),
                vec![TransientPolicy::Atomic(FwPolicy::Reachable(r, p))],
            );
        }
    }

    let trigger_name = net
        .ospf_network()
        .external_neighbors(trigger)
        .next()
        .unwrap()
        .int
        .fmt(&net)
        .to_string();
    let backup_name = net
        .ospf_network()
        .external_neighbors(backup)
        .next()
        .unwrap()
        .int
        .fmt(&net)
        .to_string();

    Ok((net, trigger, trigger_name, backup, backup_name, policies))
}

fn check_fw_state<Q>(net: &Net<Q>, fw_state: &mut ForwardingState<Prefix>) -> Result<()> {
    for source in net.internal_indices() {
        for prefix in net.get_known_prefixes().copied() {
            fw_state
                .get_paths(source, prefix)
                .with_context(|| format!("{} cannot reach {prefix}.", source.fmt(net)))?;
        }
    }
    Ok(())
}

fn prepare_event<Q: EventQueue<Prefix>>(
    scenario: Scenario,
    net: &mut Net<Q>,
    trigger: RouterId,
) -> Result<()> {
    net.manual_simulation();
    for p in 0..scenario.num_prefixes {
        let p = Prefix::from(p);
        net.withdraw_external_route(trigger, p)?;
    }
    Ok(())
}

fn get_geo_location<Q>(
    scenario: Scenario,
    net: &Net<Q>,
    rng: &mut StdRng,
) -> HashMap<RouterId, Location> {
    let mut geo = scenario.topo.geo_location();

    // get the range of latitude, longitude
    let lat_range = match geo
        .values()
        .map(|loc| loc.latitude())
        .minmax_by(f64::total_cmp)
    {
        MinMaxResult::NoElements => -60.0..60.0,
        MinMaxResult::OneElement(lat) => {
            let lat = f64::max(lat, 20.0);
            -lat..lat
        }
        MinMaxResult::MinMax(min, max) => min..max,
    };
    let lon_range = match geo
        .values()
        .map(|loc| loc.longitude())
        .minmax_by(f64::total_cmp)
    {
        MinMaxResult::NoElements => -30.0..30.0,
        MinMaxResult::OneElement(lon) => {
            let lon = f64::max(lon, 20.0);
            -lon..lon
        }
        MinMaxResult::MinMax(min, max) => min..max,
    };

    for r in net.internal_indices() {
        let lat_range = lat_range.clone();
        let lon_range = lon_range.clone();
        geo.entry(r)
            .or_insert_with(|| Location::new(rng.gen_range(lat_range), rng.gen_range(lon_range)));
    }

    geo
}

pub fn build_trace(net: &mut Net<TimingModel<Prefix>>) -> MultiPrefixConvergenceTrace {
    let mut trace = MultiPrefixConvergenceTrace::new();

    while let Some((step, event)) = net.simulate_step().unwrap() {
        match step {
            StepUpdate::Unchanged => {}
            StepUpdate::Single(delta) => {
                let time = net.queue().get_time();
                let prefix = delta.prefix;
                let prefix_trace = trace.entry(prefix).or_default();
                // handle conflicts of forwarding updates after sampling the processing time
                prefix_trace.push((vec![(event.router(), delta.old, delta.new)], time.into()));
            }
            StepUpdate::Multiple => {
                unreachable!("not sure if this is expected. ignoring step update making multiple fw state changes at once");
            }
        }
    }
    trace
}
