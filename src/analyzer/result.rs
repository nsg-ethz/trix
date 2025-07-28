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
//! Describes an experiment result.

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use bgpsim::prelude::*;

use crate::Prefix;

/// Result of the analysis including the different wall times.
#[derive(Clone, Debug, Default)]
pub struct AnalysisResult {
    /// Probability of the policies being satisfied.
    pub p_satisfied: f64,
    /// Mean time it took to converge, in seconds
    pub convergence_time: f64,
    /// confidence of the collected result
    pub confidence: f64,
    /// precision of the collected result
    pub precision: f64,
    /// Number of samples collected
    pub n_samples: usize,
    /// Number of unique forwarding state equivalence classes.
    pub n_unique_equiv: usize,
    /// Time it took for simulating the network in total (if it would have been executed on a single
    /// thread)
    pub t_simulate: Duration,
    /// Time it took for checking properties in total (if it would have been executed on a single
    /// thread)
    pub t_checking: Duration,
    /// Time it took for cloning the network in total (if it would have been executed on a single
    /// thread)
    pub t_cloning: Duration,
    /// Time to collect all stats
    pub t_collect: Duration,
    /// Time to measure the time, from start to finish, using all k workers.
    pub t_wall: Duration,
    /// distribution of violation times per forwarding policy
    pub violation_time_distributions: HashMap<(RouterId, Prefix), Vec<f64>>,
    /// distribution of violation times per forwarding policy as measured on the hardware routers
    pub cisco_violation_time_distributions: HashMap<(RouterId, Prefix), Vec<f64>>,
}

impl std::fmt::Display for AnalysisResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "prob satisfied: {:>7.3}%, {} iterations (alpha={:.1}%, precision={:.3}%), time: {:>8.2?} ({:>8.2}us / sample)",
            self.p_satisfied * 100.0,
            self.n_samples,
            (1.0 - self.confidence) * 100.0,
            self.precision * 100.0,
            self.t_wall,
            (self.t_wall.as_micros() as f64) / self.n_samples as f64,
        )
    }
}

/// Struct used to (de-)serialize the `Analyzer`'s collected data for a single simulated sample.
#[derive(Debug, Deserialize, Serialize)]
#[allow(unused)]
pub struct AnalyzerData {
    pub execution_timestamp: f64,
    pub execution_duration: f64,
    /// Time it took for simulating the network in total (if it would have been executed on a single
    /// thread)
    pub t_simulate: Duration,
    /// Time it took for checking properties in total (if it would have been executed on a single
    /// thread)
    pub t_checking: Duration,
    /// Time it took for cloning the network in total (if it would have been executed on a single
    /// thread)
    pub t_cloning: Duration,
    /// Time to collect all stats from the different thread-local caches into a global cache
    pub t_collect: Duration,
}
