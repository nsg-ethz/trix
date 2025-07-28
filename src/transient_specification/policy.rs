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
//! Policies to extend `FwPolicy` to transient scenarios.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use bgpsim::{
    forwarding_state::ForwardingState,
    policies::{FwPolicy, PathCondition, Policy, PolicyError},
    prelude::*,
};

use crate::Prefix;

use super::path::*;

/// Extendable trait for transient policies. Each type that implements `TransientPolicy` is
/// something that can be evaluated by the Reverse Reachability / Interval Algorithm.
#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum TransientPolicy {
    Atomic(FwPolicy<Prefix>),
    Strict(FwPolicy<Prefix>),
    Experimental(FwPolicy<Prefix>),
}

impl Policy<Prefix> for TransientPolicy {
    type Err = PolicyError<Prefix>;

    /// Check that a forwarding state satisfies the policy.
    fn check(&self, fw_state: &mut ForwardingState<Prefix>) -> Result<(), Self::Err> {
        match self {
            Self::Atomic(fw_policy) | Self::Strict(fw_policy) | Self::Experimental(fw_policy) => {
                fw_policy.check(fw_state)
            }
        }
    }

    /// Return the router for which the policy should apply.
    fn router(&self) -> Option<RouterId> {
        match self {
            Self::Atomic(fw_policy) | Self::Strict(fw_policy) | Self::Experimental(fw_policy) => {
                fw_policy.router()
            }
        }
    }

    /// Return the prefix for which the policy should apply.
    fn prefix(&self) -> Option<Prefix> {
        match self {
            Self::Atomic(fw_policy) | Self::Strict(fw_policy) | Self::Experimental(fw_policy) => {
                fw_policy.prefix()
            }
        }
    }
}

impl TransientPolicy {
    /// Check that a forwarding path satisfies the policy.
    pub fn check_path(&self, path: &Path) -> bool {
        match self {
            Self::Atomic(fw_policy) => match fw_policy {
                FwPolicy::Reachable(_, _) => path.is_route(),
                FwPolicy::NotReachable(_, _) => !path.is_route(),
                FwPolicy::LoopFree(_, _) => !path.is_loop(),
                FwPolicy::PathCondition(_, _, PathCondition::Node(w)) => match path {
                    Path::Route(p) => p.contains(w),
                    _ => true,
                },
                _ => todo!("implement remaining FwPolicy checks"),
            },
            Self::Strict(_fw_policy) | Self::Experimental(_fw_policy) => {
                todo!("implement remaining FwPolicy checks")
            }
        }
    }

    /// Check that a forwarding path satisfies the policy, but also counting any loop of length 2
    /// as a reachability violation.
    pub fn check_path_no_loops_of_length_2(&self, path: &Path) -> bool {
        match self {
            Self::Atomic(fw_policy) => match fw_policy {
                FwPolicy::Reachable(_, _) => {
                    path.is_route() && {
                        // check that there was no loop of length 2
                        let path_nodes = path.get_rid_vec();
                        let p1 = path_nodes.iter();
                        let p2 = path_nodes.iter().skip(2);

                        // check that all of these are different
                        !p1.zip(p2).any(|(x, y)| x == y)
                    }
                }
                FwPolicy::NotReachable(_, _) => !path.is_route(),
                FwPolicy::LoopFree(_, _) => !path.is_loop(),
                FwPolicy::PathCondition(_, _, PathCondition::Node(w)) => match path {
                    Path::Route(p) => p.contains(w),
                    _ => true,
                },
                _ => todo!("implement remaining FwPolicy checks"),
            },
            Self::Strict(_fw_policy) | Self::Experimental(_fw_policy) => {
                todo!("implement remaining FwPolicy checks")
            }
        }
    }

    /// Check that a forwarding path satisfies the policy, but also counting a loop that is run
    /// only once as a reachability violation.
    pub fn check_path_strict(&self, path: &Path) -> bool {
        match self {
            Self::Atomic(fw_policy) => match fw_policy {
                FwPolicy::Reachable(_, _) => {
                    path.is_route() && {
                        // check that there was no loop
                        let mut frequencies = HashMap::new();
                        for rid in path.get_rid_vec() {
                            *frequencies.entry(rid).or_insert(0) += 1;
                        }
                        // by checking maximum occurrence of each router is 1
                        *frequencies.values().max().unwrap_or(&0) <= 1
                    }
                }
                FwPolicy::NotReachable(_, _) => !path.is_route(),
                FwPolicy::LoopFree(_, _) => !path.is_loop(),
                FwPolicy::PathCondition(_, _, PathCondition::Node(w)) => match path {
                    Path::Route(p) => p.contains(w),
                    _ => true,
                },
                _ => todo!("implement remaining FwPolicy checks"),
            },
            Self::Strict(_fw_policy) | Self::Experimental(_fw_policy) => {
                todo!("implement remaining FwPolicy checks")
            }
        }
    }
}
