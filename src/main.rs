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
#![allow(unused)]
use std::time::Instant;

use rayon::{iter::ParallelIterator, prelude::IntoParallelIterator};

use trix::{
    experiments::{
        build_analyzer_from_experiment_description,
        //runner::get_data_point,
        scenarios::{Scenario, ScenarioConfig, ScenarioEvent, ScenarioPolicy, ScenarioPrefix},
        DataPoint,
        ExperimentDescription,
    },
    prelude::AnalyzerEvent,
    routing_inputs::RoutingInputs,
    topology::{LinkDelayBuilder, Topology},
    util,
};
use bgpsim::topology_zoo::TopologyZoo;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    util::init_logging();
    util::set_conf_dir()?;

    [
        1, //2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000,
          //250_000, 500_000, 1_000_000,
    ]
    .into_par_iter()
    .for_each(|num_prefixes| {
        let topo = Topology::TopologyZoo(TopologyZoo::Abilene);

        // AS paths: globally e1 > e2 > e3.
        let e1_aspath = vec![100.into(), 100.into(), 1000.into()];
        let e1_worse_aspath = vec![100.into(), 100.into(), 100.into(), 100.into(), 1000.into()];
        let e2_aspath = vec![200.into(), 200.into(), 200.into(), 1000.into()];
        //let e2_equal_aspath = vec![200.into(), 200.into(), 1000.into()];
        //let e2_worse_aspath = vec![200.into(), 200.into(), 200.into(), 200.into(), 1000.into()];
        //let e3_aspath = vec![300.into(), 300.into(), 300.into(), 300.into(), 1000.into()];

        // withdraw all prefixes at r0
        #[allow(unused)]
        let inputs = RoutingInputs::MultiPrefix(vec![
            vec![
                ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                ("KansasCity_ext".to_string(), e2_aspath.clone()),
            ];
            num_prefixes // advertise multiple equivalent prefixes
        ]);
        #[allow(unused)]
        let la_inputs = inputs
            .clone()
            .filter(|_, router, _| router == "LosAngeles_ext");
        #[allow(unused)]
        let kc_inputs = inputs
            .clone()
            .filter(|_, router, _| router == "KansasCity_ext");
        #[allow(unused)]
        let worse_inputs = RoutingInputs::MultiPrefix(vec![
            vec![
                ("LosAngeles_ext".to_string(), e1_worse_aspath.clone()),
            ];
            num_prefixes // advertise multiple equivalent prefixes
        ]);

        let experiment = ExperimentDescription {
            topo,
            topo_name: topo.fmt(),
            scenario_name: format!(
                //"ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles" // Withdraw
                //"ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles" // UpdateWorse
                "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles" // Announce
            ),
            config: ScenarioConfig::FullMesh,
            delays: LinkDelayBuilder::new(),
            //static_routing_inputs: inputs.clone(), // Withdraw
            //static_routing_inputs: inputs.clone(), // UpdateWorse
            static_routing_inputs: kc_inputs.clone(), // Announce
            //event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(la_inputs.clone()), // Withdraw
            //event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(worse_inputs.clone()), // UpdateWorse
            event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(la_inputs.clone()), // Announce
        };

        let now = Instant::now();
        let (
            ExperimentDescription {
                topo: _,
                topo_name,
                scenario_name,
                config: _,
                delays: _,
                static_routing_inputs: _,
                event: _,
            },
            analyzer,
        ) = build_analyzer_from_experiment_description(experiment).unwrap();
        let build_time = now.elapsed();

        //log::info!("running scenario {topo_name}/{scenario_name}");
        let result = analyzer.analyze();
        //log::debug!("result: {result:?}");

        let mut samples: Vec<f64> = result
            .violation_time_distributions
            .iter()
            .flat_map(|((_rid, _prefix), samples)| samples.iter())
            .cloned()
            .collect();
        samples.sort_by(f64::total_cmp);

        let percentiles = [
            samples[0],
            samples[samples.len() / 100],
            samples[5 * samples.len() / 100],
            samples[10 * samples.len() / 100],
            samples[25 * samples.len() / 100],
            samples[45 * samples.len() / 100],
            samples[50 * samples.len() / 100],
            samples[55 * samples.len() / 100],
            samples[75 * samples.len() / 100],
            samples[90 * samples.len() / 100],
            samples[95 * samples.len() / 100],
            samples[99 * samples.len() / 100],
            samples[samples.len() - 1],
            samples.iter().sum::<f64>() / samples.len() as f64,
        ];
        println!(
            "{num_prefixes},{}",
            percentiles
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );

        /*
        let data_point = DataPoint {
            topo: TopologyZoo::Abilene,
            scenario: Scenario {
                prefix: ScenarioPrefix::SinglePrefix,
                config: ScenarioConfig::FullMesh,
                event: ScenarioEvent::WithdrawBestRoute(1),
                policy: ScenarioPolicy::Reachability(None),
            },
            Ok(result),
            build_time,
        };
        println!("{}", data_point);
        */
    });

    Ok(())
}
