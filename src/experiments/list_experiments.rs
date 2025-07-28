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
use bgpsim::policies::FwPolicy;
#[allow(unused_imports)]
use bgpsim::{prelude::*, topology_zoo::TopologyZoo, types::Prefix};

use crate::{
    experiments::*,
    prelude::*,
    routing_inputs::RoutingInputs,
    topology::{LinkDelayBuilder, Topology},
    Prefix as P,
};

pub fn list_experiments(filter_topo: impl AsRef<str>) -> Vec<ExperimentDescription<String>> {
    let mut experiments = Vec::new();

    // AS paths: globally e1 > e2 > e3.
    let e1_aspath = vec![100.into(), 100.into(), 1000.into()];
    let e1_worse_aspath = vec![100.into(), 100.into(), 100.into(), 100.into(), 1000.into()];
    let e2_aspath = vec![200.into(), 200.into(), 200.into(), 1000.into()];
    let e2_equal_aspath = vec![200.into(), 200.into(), 1000.into()];
    let e2_worse_aspath = vec![200.into(), 200.into(), 200.into(), 200.into(), 1000.into()];
    let e3_aspath = vec![300.into(), 300.into(), 300.into(), 300.into(), 1000.into()];

    // groups of 1, 2, 5, 10, and 100 prefixes
    for num_prefixes in [1, 10, 100, 1_000, 10_000] {
        // delays of 3000, 5000 and 10000us (= 3, 5 and 10ms)
        for delay in [0.0, 10_000.0] {
            // Abilene constant delay experiments
            {
                let topo = Topology::TopologyZoo(TopologyZoo::Abilene);
                if !topo.fmt().contains(filter_topo.as_ref()) {
                    log::trace!("Skipping topology {}...", topo.fmt());
                    continue;
                }

                let inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("KansasCity_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let equal_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("KansasCity_ext".to_string(), e2_equal_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };

                // withdraw all prefixes at r0
                let event_inputs = inputs
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                let equal_event_inputs = equal_inputs
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                // Remove link to external
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_LinkFailureAtLosAngelesExt_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::RemoveLink(
                        inputs.get_prefixes(),
                        "LosAngeles_ext".to_string(),
                        "LosAngeles".to_string(),
                    ),
                });

                // route-reflection
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["NewYork".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string(), "NewYork".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                // full-mesh with backup still advertised
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngelesKeepOther_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: equal_inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(equal_event_inputs.clone()),
                });
                /*
                // route reflection with backup still advertised
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngelesKeepOther_Delay{delay}"
                    ),
                    config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: equal_inputs.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(equal_event_inputs.clone()),
                });
                */

                // vary distance from event & backup
                let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("Sunnyvale_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = inputs_1_hop
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesSunnyvale_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs_1_hop.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("Houston_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = inputs_1_hop
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesHouston_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs_1_hop.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                let inputs_2_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("Denver_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = inputs_2_hop
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesDenver_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs_2_hop.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                let inputs_3_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("Indianapolis_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = inputs_3_hop
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesIndianapolis_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs_3_hop.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("Chicago_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = inputs_4_hop
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesChicago_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs_4_hop.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                        ("NewYork_ext".to_string(), e3_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = inputs_4_hop
                    .clone()
                    .filter_route(|router, _| router == "LosAngeles_ext");
                experiments.push(ExperimentDescription {
                    topo,
                    topo_name: topo.fmt(),
                    scenario_name: format!(
                        "ExtLosAngelesNewYork_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles_Delay{delay}"
                    ),
                    config: ScenarioConfig::FullMesh,
                    delays: LinkDelayBuilder::new().default_delay(delay),
                    static_routing_inputs: inputs_4_hop.clone(),
                    event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
                });

                // announce new best route
                let inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![("KansasCity_ext".to_string(), e2_aspath.clone())],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let equal_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![("KansasCity_ext".to_string(), e2_equal_aspath.clone())],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![("LosAngeles_ext".to_string(), e1_aspath.clone())],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngelesKeepOther_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });

                // update better route
                let inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_worse_aspath.clone()),
                        ("KansasCity_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let equal_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_worse_aspath.clone()),
                        ("KansasCity_ext".to_string(), e2_worse_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![("LosAngeles_ext".to_string(), e1_aspath.clone())],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngelesKeepOther_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });

                // update worse route
                let inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("KansasCity_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let equal_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("KansasCity_ext".to_string(), e2_equal_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![("LosAngeles_ext".to_string(), e1_worse_aspath.clone())],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                // UpdateWorse + KeepOther
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                // UpdateWorse + RR
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                // UpdateWorse + RR + KeepOther
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther_Delay{delay}",
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                // update worse + vary distance from event & backup
                let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("Sunnyvale_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                let event_inputs = RoutingInputs::RepeatedPrefix {
                    inner: vec![("LosAngeles_ext".to_string(), e1_worse_aspath.clone())],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesSunnyvale_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs_1_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("Houston_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesHouston_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs_1_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                let inputs_2_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("Denver_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesDenver_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs_2_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                let inputs_3_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("Indianapolis_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesIndianapolis_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs_3_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("Chicago_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesChicago_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs_4_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

                let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                    inner: vec![
                        ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                        ("NewYork_ext".to_string(), e2_aspath.clone()),
                    ],
                    num: num_prefixes, // advertise multiple equivalent prefixes
                };
                experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesNewYork_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles_Delay{delay}",
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new().default_delay(delay),
                static_routing_inputs: inputs_4_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            }
        }

        // Abilene geo_location experiments
        {
            let topo = Topology::TopologyZoo(TopologyZoo::Abilene);
            if !topo.fmt().contains(filter_topo.as_ref()) {
                log::trace!("Skipping topology {}...", topo.fmt());
                continue;
            }

            let inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("KansasCity_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let equal_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("KansasCity_ext".to_string(), e2_equal_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };

            let event_inputs = inputs
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            let equal_event_inputs = equal_inputs
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");

            // withdraw all prefixes at r0
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            // Remove link to external
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_LinkFailureAtLosAngelesExt"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::RemoveLink(
                    inputs.get_prefixes(),
                    "LosAngeles_ext".to_string(),
                    "LosAngeles".to_string(),
                ),
            });

            // route-reflection
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            // full-mesh with backup still advertised
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(equal_event_inputs.clone()),
            });

            // route reflection with backup still advertised
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(equal_event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(equal_event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(equal_event_inputs.clone()),
            });

            // vary distance from event & backup
            let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("Sunnyvale_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = inputs_1_hop
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesSunnyvale_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_1_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("Houston_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = inputs_1_hop
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesHouston_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_1_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            let inputs_2_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("Denver_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = inputs_2_hop
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesDenver_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_2_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            let inputs_3_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("Indianapolis_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = inputs_3_hop
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesIndianapolis_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_3_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("Chicago_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = inputs_4_hop
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesChicago_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_4_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e2_aspath.clone()),
                    ("NewYork_ext".to_string(), e3_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = inputs_4_hop
                .clone()
                .filter_route(|router, _| router == "LosAngeles_ext");
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesNewYork_FullMesh_Prefix{num_prefixes}_PhysicalExternalWithdrawAllPrefixesAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_4_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(event_inputs.clone()),
            });

            // announce new best route
            let inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![("KansasCity_ext".to_string(), e2_aspath.clone())],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let equal_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![("KansasCity_ext".to_string(), e2_equal_aspath.clone())],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![("LosAngeles_ext".to_string(), e1_aspath.clone())],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalAnnounceAllNewBestAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(event_inputs.clone()),
            });

            // update better route
            let inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_worse_aspath.clone()),
                    ("KansasCity_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let equal_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_worse_aspath.clone()),
                    ("KansasCity_ext".to_string(), e2_worse_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![("LosAngeles_ext".to_string(), e1_aspath.clone())],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllBetterAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(event_inputs.clone()),
            });

            // update worse route
            let inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("KansasCity_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let equal_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("KansasCity_ext".to_string(), e2_equal_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![("LosAngeles_ext".to_string(), e1_worse_aspath.clone())],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            // UpdateWorse + KeepOther
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            // UpdateWorse + RR
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            // UpdateWorse + RR + KeepOther
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Atlanta".to_string(), "Seattle".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngelesKeepOther"
                ),
                config: ScenarioConfig::RouteReflectors(vec!["Seattle".to_string(), "NewYork".to_string()]),
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: equal_inputs.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            // update worse + vary distance from event & backup
            let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("Sunnyvale_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            let event_inputs = RoutingInputs::RepeatedPrefix {
                inner: vec![("LosAngeles_ext".to_string(), e1_worse_aspath.clone())],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesSunnyvale_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_1_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            let inputs_1_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("Houston_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesHouston_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_1_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            let inputs_2_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("Denver_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesDenver_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_2_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            let inputs_3_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("Indianapolis_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesIndianapolis_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_3_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("Chicago_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesChicago_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_4_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });

            let inputs_4_hop = RoutingInputs::RepeatedPrefix {
                inner: vec![
                    ("LosAngeles_ext".to_string(), e1_aspath.clone()),
                    ("NewYork_ext".to_string(), e2_aspath.clone()),
                ],
                num: num_prefixes, // advertise multiple equivalent prefixes
            };
            experiments.push(ExperimentDescription {
                topo,
                topo_name: topo.fmt(),
                scenario_name: format!(
                    "ExtLosAngelesNewYork_FullMesh_Prefix{num_prefixes}_PhysicalExternalUpdateAllWorseAtLosAngeles"
                ),
                config: ScenarioConfig::FullMesh,
                delays: LinkDelayBuilder::new(),
                static_routing_inputs: inputs_4_hop.clone(),
                event: AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(event_inputs.clone()),
            });
        }
    }

    experiments
}

pub fn build_analyzer_from_experiment_description(
    ExperimentDescription {
        topo,
        topo_name,
        scenario_name,
        config,
        delays,
        static_routing_inputs,
        event,
    }: ExperimentDescription<String>,
) -> Option<(ExperimentDescription<RouterId>, Analyzer<TimingModel<P>>)> {
    // build topology
    let Ok(mut net) = topo.build_network(&static_routing_inputs, &event) else {
        return None;
    };

    // TODO: Handle the errors properly! Could error if the scenario was built incorrectly
    // (e.g., wrong router name)
    let Ok(static_routing_inputs) = static_routing_inputs.build(&net) else {
        let error_message =
            format!("Skipping {topo:?}/{scenario_name:?} due to invalid static_routing_inputs!");
        log::error!("{error_message}");
        return None;
    };
    let Ok(event) = event.build(&net) else {
        let error_message = format!("Skipping {topo:?}/{scenario_name:?} due to invalid event!");
        log::error!("{error_message}");
        return None;
    };
    let Ok(delays) = delays.build(&net) else {
        let error_message = format!("Skipping {topo:?}/{scenario_name:?} due to invalid delays!");
        log::error!("{error_message}");
        return None;
    };

    if net.internal_routers().count() > 12 {
        log::debug!("Skipping experiment on topology {topo_name} as it won't fit on our hardware.");
        return None;
    }

    let net_delays = delays.generate_delays(&net, &topo);

    // apply configuration, e.g., full mesh or route reflectors
    match config.apply_to(&mut net) {
        Ok(_) => {}
        Err(NetworkError::DeviceNameNotFound(name)) => {
            panic!("Error: device {name} not found in topology {topo_name}!")
        }
        Err(e) => panic!("{}", e.to_string()),
    }

    // advertise stable routing inputs
    static_routing_inputs.advertise_to(&mut net);

    // create timing_model from geo_locations and swap out the network's queue
    let timing_model = TimingModel::<P>::from_delays(&net_delays);
    let net = net.swap_queue(timing_model).unwrap();

    // build reachability policy
    let policies: Vec<_> = static_routing_inputs
        .get_prefixes()
        .iter()
        .flat_map(|prefix| {
            net.internal_indices()
                .map(|r| TransientPolicy::Atomic(FwPolicy::Reachable(r, *prefix)))
        })
        .collect();

    // TODO handle the errors properly!
    let mut analyzer = Analyzer::new(net, event.clone(), policies, 0.95, 0.01).unwrap();

    // configure the delays
    analyzer.set_delays(net_delays);

    Some((
        ExperimentDescription {
            topo,
            topo_name,
            scenario_name,
            config,
            delays,
            static_routing_inputs,
            event,
        },
        analyzer,
    ))
}

pub fn iterate_experiments(
    filter: Filter,
) -> impl Iterator<Item = (ExperimentDescription<RouterId>, Analyzer<TimingModel<P>>)> {
    list_experiments(filter.topo)
        .into_iter()
        .filter_map(move |experiment_description| {
            if !experiment_description
                .scenario_name
                .contains(&filter.scenario)
                || !experiment_description
                    .scenario_name
                    .ends_with(&filter.scenario_end)
            {
                log::trace!(
                    "Skipping {}/{} due to filters!",
                    experiment_description.topo_name,
                    experiment_description.scenario_name
                );
                return None;
            }

            build_analyzer_from_experiment_description(experiment_description)
        })
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[ignore]
    fn list_all_experiments() {
        for ExperimentDescription {
            topo: _,
            topo_name,
            scenario_name,
            config: _,
            delays: _,
            static_routing_inputs: _,
            event: _,
        } in list_experiments("")
        {
            println!("{topo_name}/{scenario_name}");
        }
    }

    #[test]
    #[ignore]
    fn generate_experiments() {
        for (
            ExperimentDescription {
                topo: _,
                topo_name,
                scenario_name,
                config: _,
                delays: _,
                static_routing_inputs: _,
                event: _,
            },
            _,
        ) in iterate_experiments(Filter::default())
        {
            println!("{topo_name}/{scenario_name}");
        }
    }
}
