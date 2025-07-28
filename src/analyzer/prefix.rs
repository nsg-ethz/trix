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
//! Describes different prefix scenarios used by the `Analyzer`.

use serde::{Deserialize, Serialize};

use crate::Prefix;

/// Choose how to setup the advertised prefixes in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalyzerPrefix {
    /// Run the experiment with a single prefix.
    SinglePrefix,
    /// Create `k` equivalently configured prefixes. Will perform the event on all prefixes.
    MultiPrefix(usize),
}

impl AnalyzerPrefix {
    /// Instantiate the prefixes.
    pub fn prefixes(&self) -> Vec<Prefix> {
        match self {
            Self::SinglePrefix => vec![Prefix::from(0)],
            Self::MultiPrefix(k) => (0..*k).map(Prefix::from).collect::<Vec<_>>(),
        }
    }

    /// Get the number of prefixes
    pub fn num_prefixes(&self) -> usize {
        match self {
            Self::SinglePrefix => 1,
            Self::MultiPrefix(k) => *k,
        }
    }

    /// Return a human-readable name of each `AnalyzerPrefix`
    pub fn name(&self) -> &'static str {
        match self {
            Self::SinglePrefix => "SinglePrefix",
            Self::MultiPrefix(_) => "MultiPrefix",
        }
    }
}
