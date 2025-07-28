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
//! Library for performing probabilistic transient analysis of BGP events.
use std::collections::HashMap;

use bgpsim::record::{AlwaysEq, FwDelta};

/// Selected bgpsim `Prefix` for this crate
pub type Prefix = bgpsim::types::SimplePrefix;

/// Type for the multi-prefix convergence trace
pub type FwUpdate = (Vec<FwDelta>, AlwaysEq<Option<f64>>);
pub type PrefixTrace = Vec<FwUpdate>;
pub type MultiPrefixConvergenceTrace = HashMap<Prefix, PrefixTrace>;

pub mod analyzer;
pub mod event;
pub mod experiments;
pub mod fib_queuing;
pub mod records;
pub mod routing_inputs;
pub mod timing_model;
pub mod topology;
pub mod transient_specification;
pub mod util;

// pub use to keep dependencies working where stuff was originally defined in this file
pub use trix_utils::serde::generic_hashmap as serde_generic_hashmap;

pub mod prelude {
    pub use super::{
        analyzer::{AnalysisResult, Analyzer, AnalyzerPrefix::*},
        event::AnalyzerEvent,
        timing_model::{TimingModel, TimingModelVariants},
        transient_specification::TransientPolicy,
        Prefix,
    };
}
