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
use super::scenarios::*;

/// verify transient network behavior using the bgpsim simulator
pub const fn list_scenarios() -> [Scenario; 13] {
    [
        // Best route in the network disappears, check that there is no transient loop.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // Best route in the network disappears, check that there is no transient loop.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::FullMesh,
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // Best route in the network disappears, check that there is no transient loop
        // for the route reflectors.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::LoopFreedom(Some(2)),
        },
        // Best route in the network disappears, check that reachability is preserved.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::Reachability(None),
        },
        // Best route in the network disappears, check that reachability is preserved.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::FullMesh,
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::Reachability(None),
        },
        // One of the best routes in the network disappears, check that reachability is preserved.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::WithdrawSimilarRoute(2),
            policy: ScenarioPolicy::Reachability(None),
        },
        // If the best route disappears from the network, check that the worst route is not
        // used instead.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::IgnoreWorstRoute(None),
        },
        // If the best route disappears from the network, check that the worst route is not
        // used instead.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::FullMesh,
            event: ScenarioEvent::WithdrawBestRoute(2),
            policy: ScenarioPolicy::IgnoreWorstRoute(None),
        },
        // When a new best route appears in the network, it should not cause any forwarding loops.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::NewBestRoute(2),
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // When a new best route appears in the network, it should not cause any forwarding loops.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::FullMesh,
            event: ScenarioEvent::NewBestRoute(2),
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // When a new similar route appears in the network, it should not cause any forwarding loops.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::NewSimilarRoute(2),
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // Increasing the route preference should not affect reachability at all, since the
        // new best route could have been selected before the event already.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::IncreaseRoutePreference(2),
            policy: ScenarioPolicy::Reachability(None),
        },
        // Decreasing the route preference should not affect reachability at all, since the
        // previous best route may still be selected after the event.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::DecreaseRoutePreference(2),
            policy: ScenarioPolicy::Reachability(None),
        },
        /*
        // When a link disappears from the network, check that there is no forwarding loop introduced.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::RemoveLink,
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // When a link reappears in the network, check that there is no forwarding loop introduced.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::AddLink,
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // When an external session disappears from the network, check that there are no forwarding loops introduced.
        Scenario {
            prefix: ScenarioPrefix::SinglePrefix,
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::RemoveSession,
            policy: ScenarioPolicy::LoopFreedom(None),
        },
        // When an external session disappears from the network, check that reachability is preserved.
        Scenario {
            prefix: ScenarioPrefix::MultiPrefix(3),
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::RemoveSession,
            policy: ScenarioPolicy::Reachability(None),
        },
        // When an external session re-appears in the network, check that reachability is preserved.
        Scenario {
            prefix: ScenarioPrefix::MultiPrefix(3),
            config: ScenarioConfig::RouteReflection(2),
            event: ScenarioEvent::AddSession,
            policy: ScenarioPolicy::Reachability(None),
        },
        */
    ]
}
