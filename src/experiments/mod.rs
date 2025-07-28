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
//! Module facilitating to run experiments using the probabilistic transient analyzer for BGP events.

pub mod experiment_serde;
pub mod list_custom_topologies;
pub mod list_experiments;
pub mod list_path_scenarios;
pub mod list_scenarios;
pub mod runner;
pub mod sample;
pub mod scenarios;

pub use experiment_serde::*;
pub use list_custom_topologies::*;
pub use list_experiments::*;
pub use list_path_scenarios::*;
pub use list_scenarios::*;
pub use runner::*;
pub use sample::*;
pub use scenarios::*;

use bgpsim::types::RouterId;

use crate::{
    prelude::AnalyzerEvent,
    routing_inputs::RoutingInputs,
    topology::{LinkDelayBuilder, Topology},
};

/// Describes an experiment that can be executed on the routing testbed.
pub struct ExperimentDescription<R = RouterId> {
    pub topo: Topology,
    pub topo_name: String,
    pub scenario_name: String,
    pub config: ScenarioConfig,
    pub delays: LinkDelayBuilder<R>,
    pub static_routing_inputs: RoutingInputs<R>,
    pub event: AnalyzerEvent<R>,
}

/// allows filtering experiment data to be processed
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub topo: String,
    pub scenario: String,
    pub scenario_end: String,
    pub sample_id: String,
}
