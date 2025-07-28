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
use std::collections::HashMap;

use trix::{prelude::*, MultiPrefixConvergenceTrace, Prefix as P};
use bgpsim::{event::EventQueue, prelude::*};

use geoutils::Location;
use rand::prelude::*;
use statrs::distribution::Empirical;

#[cfg(feature = "router_lab")]
mod generate_experiments;
#[cfg(feature = "router_lab")]
use generate_experiments::set_conf_dir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    #[cfg(feature = "router_lab")]
    set_conf_dir()?;

    let prefixes = MultiPrefix(3).prefixes();
    let first_prefix = prefixes[0];

    let e1_aspath: Vec<AsId> = vec![100.into(), 100.into(), 100.into(), 1000.into()];
    let e2_aspath: Vec<AsId> = vec![200.into(), 200.into(), 1000.into()];

    #[allow(unused_variables)]
    let (mut net, (r0, r1, r2, e1, e2)) = net! {
        Prefix = P;
        links = {
            r0 -> r1: 1;
            r1 -> r2: 1;
        };
        sessions = {
            // external routers
            e1!(100) -> r0;
            e2!(200) -> r2;
            // iBGP full mesh
            r0 -> r1: peer;
            r0 -> r2: peer;
            r1 -> r2: peer;
        };
        routes = {
            // create both links and sessions for external routers and advertise first_prefix
            e1 -> first_prefix as {path: &e1_aspath};
            e2 -> first_prefix as {path: &e2_aspath};
        };
        return (r0, r1, r2, e1, e2)
    };

    // advertise other prefixes
    for &prefix in prefixes.iter() {
        if prefix != first_prefix {
            net.advertise_external_route(e1, prefix, &e1_aspath, None, [])
                .unwrap();
            net.advertise_external_route(e2, prefix, &e2_aspath, None, [])
                .unwrap();
        }
    }

    let geo_locations = HashMap::from([
        (e1, Location::new(10.0, 0.0)),
        (r0, Location::new(10.0, 0.0)),
        (r1, Location::new(20.0, 0.0)),
        (r2, Location::new(30.0, 0.0)),
        (e2, Location::new(30.0, 0.0)),
    ]);

    let timing_model = TimingModel::<P>::from_geo_location(&geo_locations);
    let additive_fw_plane_params: Vec<f64> = include_str!("../timing-model/data.csv")
        .lines()
        .map(|line| {
            let parts: Vec<f64> = line.split(',').map(|x| x.parse().unwrap()).collect();
            (parts[1] - parts[0]).max(0.0) / 1000.0
        })
        .collect();
    let _fw_timing_dist = Empirical::from_vec(additive_fw_plane_params);
    let mut _rng = thread_rng();

    let net = net.swap_queue(timing_model).unwrap();

    let original_fw = net.get_forwarding_state();

    let mut scheduled_net = net.clone();
    scheduled_net.manual_simulation();

    // perform the event
    //event.trigger(&mut scheduled_net)?;
    for prefix in prefixes.iter() {
        //scheduled_net.advertise_external_route(e2, *prefix, &e2_aspath, None, None)?;
        scheduled_net.withdraw_external_route(e2, *prefix)?;
    }

    // get the scheduled forwarding state
    let scheduled_fw = scheduled_net.get_forwarding_state();

    // compute the difference and prepare the trace
    let diff = original_fw.diff(&scheduled_fw);
    let initial_time = scheduled_net.queue().get_time().unwrap_or_default();
    let mut _trace: MultiPrefixConvergenceTrace =
        HashMap::from_iter(prefixes.iter().map(|prefix| {
            (
                *prefix,
                vec![(diff.get(prefix).unwrap().clone(), Some(initial_time).into())],
            )
        }));

    // Store the index of the last update for a given router and prefix
    let mut _last_fw_update_index: HashMap<(RouterId, P), usize> = HashMap::new();

    todo!("adapt to new bgpsim event structs");
    /*
    while let Some((step, event)) = scheduled_net.simulate_step().unwrap() {
        match event {
            Bgp(time, from, to, ref bgpevent) => {
                println!(
                    "[{:.5}; {} -> {}] BGP {:?}",
                    *time,
                    from.fmt(&net),
                    to.fmt(&net),
                    bgpevent
                );
                if step.changed() {
                    // determine the time the forwarding state has changed (which happens with an offset from
                    // the control-plane reaction of the routers
                    let time = scheduled_net
                        .queue()
                        .get_time()
                        .map(|x| x + fw_timing_dist.sample(&mut rng) - initial_time);

                    let prefix = step
                        .prefix
                        .expect("All BGP events causing a change should have a known prefix!");

                    println!(
                        "[{:.5}; {}] FW Update on {prefix:?}: {} -> {:?} (prev: {:?})!",
                        time.unwrap(),
                        to.fmt(&net),
                        to.fmt(&net),
                        step.new.iter().map(|x| x.fmt(&net)).collect::<Vec<_>>(),
                        step.old.iter().map(|x| x.fmt(&net)).collect::<Vec<_>>(),
                    );

                    let prefix_trace = trace.entry(prefix).or_insert_with(Vec::new);
                    // handle conflicts of forwarding updates after sampling the processing time
                    match last_fw_update_index.entry((event.router(), prefix)) {
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            let last_index = e.get_mut();
                            if prefix_trace
                                .get(*last_index)
                                .map(|x| x.1)
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                < time.unwrap()
                            {
                                // previous update was earlier, just insert and store the index
                                *last_index = prefix_trace.len();
                                prefix_trace.push((
                                    vec![(event.router(), step.old, step.new)],
                                    time.into(),
                                ));
                            } else {
                                // conflicting update found!
                                let overwrite = prefix_trace.get_mut(*last_index).unwrap();
                                // check that there is only one update
                                assert!(overwrite.0.len() == 1);
                                // overwrite the resulting next hops of the update as if the
                                // intermediate update had never happened
                                overwrite.0[0].2 = step.new;
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            // no previous update, just insert and store the index
                            e.insert(prefix_trace.len());
                            prefix_trace
                                .push((vec![(event.router(), step.old, step.new)], time.into()));
                        }
                    }
                }
            }
        }
    }

    // build policies
    let mut policies = vec![];
    for &prefix in prefixes.iter() {
        policies.push(TransientPolicy::Atomic(FwPolicy::Reachable(r0, prefix)));
        policies.push(TransientPolicy::Atomic(FwPolicy::Reachable(r1, prefix)));
        policies.push(TransientPolicy::Atomic(FwPolicy::Reachable(r2, prefix)));
    }

    #[allow(unused_mut)]
    let mut analyzer = Analyzer::new(
        net.clone(),
        geo_locations,
        AnalyzerEvent::WithdrawRoute(prefixes, e2, vec![200.into(), 200.into(), 1000.into()]),
        policies,
        0.95,
        0.05,
    )?;

    let result = analyzer.analyze();

    println!("{}", result);

    let keys = result.violation_time_distributions.keys();
    for (rid, prefix) in keys.sorted() {
        let simulated_distribution = result
            .violation_time_distributions
            .get(&(*rid, *prefix))
            .unwrap();
        log::debug!(
            "{} for {prefix:?} simulated (avg: {})\n{simulated_distribution:?}",
            rid.fmt(&net),
            simulated_distribution.iter().sum::<f64>() / simulated_distribution.len() as f64
        );
        #[cfg(feature = "router_lab")]
        {
            let cisco_distribution = result
                .cisco_violation_time_distributions
                .get(&(*rid, *prefix))
                .unwrap();
            log::debug!(
                "{} for {prefix:?} measured:\n{cisco_distribution:?}",
                rid.fmt(&net)
            );
            let mut evaluations: Vec<_> = cisco_distribution
                .iter()
                .map(|s| {
                    match simulated_distribution.binary_search_by(|v| v.partial_cmp(&(s)).unwrap())
                    {
                        Ok(x) => x,
                        Err(x) => x,
                    }
                })
                .collect();
            evaluations.sort();
            log::debug!(
                "Router {:?}: {} (out of {}), avg: {:.2}",
                rid,
                evaluations.iter().map(|e| e.to_string()).join(", "),
                simulated_distribution.len(),
                evaluations.iter().sum::<usize>() as f64 / evaluations.len() as f64
            );
        }
    }

    Ok(())
    */
}
