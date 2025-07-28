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
use bgpsim::prelude::*;

use crate::{event::AnalyzerEvent, Prefix as P};

/// Collection of individually crafted scenarios to compare on a path as found in the module
/// `list_custom_topologies`.
pub fn list_path_scenarios(
    net: &Network<P>,
    prefixes: &[P],
    external_routers: &[(RouterId, Vec<AsId>)],
) -> [(&'static str, AnalyzerEvent<RouterId>); 4] {
    let first_prefix = prefixes[0];
    let (e1, e1_aspath) = external_routers[0].clone();
    let (e2, e2_aspath) = external_routers[1].clone();
    let mut routers = net.internal_routers().collect::<Vec<_>>();
    routers.sort_by(|a, b| a.name().cmp(b.name()));
    let r0 = routers[0].router_id();

    [
        (
            "WithdrawE1",
            AnalyzerEvent::WithdrawRoute(vec![first_prefix], e1, e1_aspath.clone()),
        ),
        (
            "MultiWithdrawE1",
            AnalyzerEvent::WithdrawRoute(prefixes.to_owned(), e1, e1_aspath.clone()),
        ),
        (
            "WithdrawE2",
            AnalyzerEvent::WithdrawRoute(vec![first_prefix], e2, e2_aspath.clone()),
        ),
        (
            "LinkFailureE1R0",
            AnalyzerEvent::RemoveLink(prefixes.to_owned(), e1, r0),
        ),
    ]
}
