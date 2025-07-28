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
//! Module containing common and reasonable scenarios of network events.
#![allow(dead_code)]

use std::{collections::HashMap, iter::zip};

use geoutils::Location;
use itertools::Itertools;
use rand::prelude::*;
use thiserror::Error;

use bgpsim::{
    builder::{uniform_link_weight, NetworkBuilder},
    ospf::LinkWeight,
    policies::{FwPolicy, PathCondition},
    prelude::*,
    route_map::{RouteMapBuilder, RouteMapDirection},
    router::Router,
};

pub use crate::analyzer::AnalyzerPrefix as ScenarioPrefix;
use crate::{prelude::*, Prefix as P};

/// Simple interface to build a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scenario {
    /// How many equivalently configured prefixes to consider
    pub prefix: ScenarioPrefix,
    /// How to configure the network
    pub config: ScenarioConfig,
    /// The event that we will measure
    pub event: ScenarioEvent,
    /// Policy to analyze
    pub policy: ScenarioPolicy,
}

impl Scenario {
    /// Return a human-readable name for this scenario.
    pub fn name(&self) -> String {
        format!(
            "{:?}_{:?}_{:?}_{:?}",
            self.prefix, self.config, self.event, self.policy
        )
    }

    /// Build the scenario from the given topology, and return an analyzer.
    pub fn build_from(
        &self,
        net: &Network<P, BasicEventQueue<P>>,
        geo_location: &HashMap<RouterId, Location>,
    ) -> Result<Analyzer<TimingModel<P>>, ScenarioError> {
        for _ in 0..100 {
            // get the rng
            let mut rng = thread_rng();

            // get a mutable network
            let mut net = net.clone();

            // get the number of external routers needed for the simulation
            let num_external_routers = 1 + (self.event.num_routes() * 2);
            // extend the number of external routers
            let mut external_routers = net.build_external_routers(
                |net, _| {
                    let mut routers = net.internal_routers().map(Router::router_id).collect_vec();
                    routers.shuffle(&mut rng);
                    std::iter::repeat(&routers)
                        .flat_map(|x| x.iter())
                        .take(num_external_routers)
                        .copied()
                        .collect_vec()
                },
                (),
            )?;
            external_routers.shuffle(&mut rng);
            external_routers.truncate(num_external_routers);

            // prepare the list of routers, sorted by their degree
            let mut routers = net.internal_routers().map(Router::router_id).collect_vec();
            let g = net.get_topology();
            routers.shuffle(&mut rng);
            routers.sort_by_cached_key(|r| -(g.neighbors(*r).count() as i64));

            // build the configuration
            self.config.build(&mut net, &routers)?;

            // build the route maps
            self.event.build_route_maps(&mut net, &external_routers)?;

            // build advertisements
            self.event
                .build_advertisements(&self.prefix, &mut net, &external_routers)?;

            // build policies
            let policies = self
                .policy
                .build(&self.prefix, &net, &routers, &external_routers);

            // prepare the event
            if let Some(event) =
                self.event
                    .prepare(&self.prefix, &mut net, &routers, &external_routers)?
            {
                // create the queue
                let queue = TimingModel::<P>::from_geo_location(geo_location);
                let net = net.swap_queue(queue).unwrap();

                #[allow(unused_mut)]
                let mut analyzer = Analyzer::new(net, event, policies, 0.95, 0.01)?;
                analyzer.set_geo_location(geo_location.clone());

                return Ok(analyzer);
            };

            // otherwise, repeat
        }

        Err(ScenarioError::GenerationError)
    }
}

/// Configuration for how to setup the network configuration
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScenarioConfig {
    /// Create an iBGP full-mesh
    FullMesh,
    /// Create a route reflection topology with `k` route reflectors, that are chosen to be the `k`
    /// highest degree nodes.
    RouteReflection(usize),
    /// Create a topology with the given nodes as route reflectors, all others are route reflector
    /// clients to all route reflectors.
    RouteReflectors(Vec<String>),
}

impl ScenarioConfig {
    /// Create the configuration. The routers parameter is a list of all internal routers, sorted by
    /// their degree
    pub fn build(
        &self,
        net: &mut Network<P, BasicEventQueue<P>>,
        routers: &[RouterId],
    ) -> Result<(), NetworkError> {
        // add link weights
        net.build_link_weights(uniform_link_weight, (10.0, 100.0))?;
        // build the ebgp sessions
        net.build_ebgp_sessions()?;
        // build ibgp topology
        match self {
            ScenarioConfig::FullMesh => {
                net.build_ibgp_full_mesh()?;
            }
            ScenarioConfig::RouteReflection(k) => {
                net.build_ibgp_route_reflection(|_, _| routers.iter().take(*k).copied(), ())?;
            }
            ScenarioConfig::RouteReflectors(reflectors) => {
                let reflectors = reflectors
                    .iter()
                    .map(|name| net.get_router_id(name))
                    .collect::<Result<Vec<RouterId>, NetworkError>>()?;
                net.build_ibgp_route_reflection(|_, _| reflectors, ())?;
            }
        }

        Ok(())
    }

    /// Get the number of route reflectors
    pub fn num_rrs(&self) -> Option<usize> {
        match self {
            ScenarioConfig::FullMesh => None,
            ScenarioConfig::RouteReflection(n) => Some(*n),
            ScenarioConfig::RouteReflectors(reflectors) => Some(reflectors.len()),
        }
    }

    /// Apply the config to a given network (assuming it hasn't got and iBGP configured yet).
    pub fn apply_to(&self, net: &mut Network<P>) -> Result<(), NetworkError> {
        match self {
            ScenarioConfig::FullMesh => net.build_ibgp_full_mesh()?,
            ScenarioConfig::RouteReflection(k) => {
                // prepare the list of routers, sorted by their degree
                let mut routers = net.internal_routers().map(Router::router_id).collect_vec();
                let g = net.get_topology();
                routers.shuffle(&mut thread_rng());
                routers.sort_by_cached_key(|r| -(g.neighbors(*r).count() as i64));
                net.build_ibgp_route_reflection(|_, _| routers.iter().take(*k).copied(), ())?;
            }
            ScenarioConfig::RouteReflectors(reflectors) => {
                let reflectors = reflectors
                    .iter()
                    .map(|name| net.get_router_id(name))
                    .collect::<Result<Vec<RouterId>, NetworkError>>()?;
                net.build_ibgp_route_reflection(|_, _| reflectors, ())?;
            }
        }

        Ok(())
    }
}

/// Enumeration of several events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScenarioEvent {
    /// Withdraw the best route in the network, and fall back to `k` other, equally preferred,
    /// routes.
    WithdrawBestRoute(usize),
    /// Withdraw one of the `(k + 1)` best routes. The parameter stores the number of *other*
    /// routes in the network.
    WithdrawSimilarRoute(usize),
    /// A new route appears that is better than all previous routes. Previously, there are `k`
    /// equally preferred routes in the network.
    NewBestRoute(usize),
    /// A new route appears that is better than all previous routes. Previously, there are `k`
    /// equally preferred routes in the network.
    NewSimilarRoute(usize),
    /// Update one of `(k + 1)` equally preferred routes to have a higher preference than all
    /// others.
    IncreaseRoutePreference(usize),
    /// Update the most preferred route in the network to have equal preference as `k` other
    /// routes.
    DecreaseRoutePreference(usize),
    /// Simulate a link failure on a link, which will cause (at least) the router with highest
    /// degree to change its preferred route.
    RemoveLink,
    /// Simulate the re-appearence of a link, which will cause (at least) the router with highest
    /// degree to change its preferred route.
    AddLink,
    /// Simulate an external BGP session to disappear, which will cause (at least) the router with
    /// highest degree to change its preferred route on each advertised prefix.
    RemoveExternalLink,
    /// Simulate the re-appearance of an external session, which will cause (at least) the router
    /// with highest degree to change its preferred route on each advertised prefix.
    AddExternalLink,
}

impl ScenarioEvent {
    pub fn num_routes(&self) -> usize {
        match self {
            ScenarioEvent::WithdrawBestRoute(k)
            | ScenarioEvent::WithdrawSimilarRoute(k)
            | ScenarioEvent::NewBestRoute(k)
            | ScenarioEvent::NewSimilarRoute(k)
            | ScenarioEvent::IncreaseRoutePreference(k)
            | ScenarioEvent::DecreaseRoutePreference(k) => *k,
            ScenarioEvent::RemoveLink
            | ScenarioEvent::AddLink
            | ScenarioEvent::RemoveExternalLink
            | ScenarioEvent::AddExternalLink => 2,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ScenarioEvent::WithdrawBestRoute(_) => "WithdrawBestRoute",
            ScenarioEvent::WithdrawSimilarRoute(_) => "WithdrawSimilarRoute",
            ScenarioEvent::NewBestRoute(_) => "NewBestRoute",
            ScenarioEvent::NewSimilarRoute(_) => "NewSimilarRoute",
            ScenarioEvent::IncreaseRoutePreference(_) => "IncreaseRoutePreference",
            ScenarioEvent::DecreaseRoutePreference(_) => "DecreaseRoutePreference",
            ScenarioEvent::RemoveLink => "RemoveLink",
            ScenarioEvent::AddLink => "AddLink",
            ScenarioEvent::RemoveExternalLink => "RemoveExternalLink",
            ScenarioEvent::AddExternalLink => "AddExternalLink",
        }
    }

    pub fn build_route_maps(
        &self,
        net: &mut Network<P, BasicEventQueue<P>>,
        ext: &[RouterId],
    ) -> Result<(), NetworkError> {
        let k = (ext.len() - 1) / 2;

        for (i, e) in ext.iter().enumerate() {
            let r = net.get_topology().neighbors(*e).next().unwrap();
            net.set_bgp_route_map(
                r,
                *e,
                RouteMapDirection::Incoming,
                RouteMapBuilder::new()
                    .allow()
                    .order(i as u16)
                    .set_local_pref(if i <= k { 100 } else { 50 })
                    .build(),
            )?;
        }

        Ok(())
    }

    pub fn build_advertisements(
        &self,
        scenario_prefix: &ScenarioPrefix,
        net: &mut Network<P, BasicEventQueue<P>>,
        ext: &[RouterId],
    ) -> Result<(), NetworkError> {
        for (i, e) in ext.iter().enumerate() {
            for prefix in scenario_prefix.prefixes().iter() {
                let asid = net.get_device(*e)?.unwrap_external().as_id();
                let best_path = vec![asid, asid, 1000.into()];
                let same_path = vec![asid, asid, asid, 1000.into()];
                if i == 0 {
                    if let Some(path) = match self {
                        ScenarioEvent::WithdrawBestRoute(_)
                        | ScenarioEvent::DecreaseRoutePreference(_)
                        | ScenarioEvent::RemoveExternalLink
                        | ScenarioEvent::AddExternalLink => Some(best_path.clone()),
                        ScenarioEvent::WithdrawSimilarRoute(_)
                        | ScenarioEvent::IncreaseRoutePreference(_)
                        | ScenarioEvent::RemoveLink
                        | ScenarioEvent::AddLink => Some(same_path.clone()),
                        ScenarioEvent::NewBestRoute(_) | ScenarioEvent::NewSimilarRoute(_) => None,
                    } {
                        net.advertise_external_route(
                            *e,
                            *prefix,
                            path,
                            None,
                            vec![prefix.as_num()],
                        )?;
                    }
                } else {
                    net.advertise_external_route(
                        *e,
                        *prefix,
                        same_path,
                        None,
                        vec![prefix.as_num()],
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Prepare the event by returning a prepared event, or nothing if it could not prepare the event.
    fn prepare(
        &self,
        scenario_prefix: &ScenarioPrefix,
        net: &mut Network<P, BasicEventQueue<P>>,
        routers: &[RouterId],
        external_routers: &[RouterId],
    ) -> Result<Option<AnalyzerEvent<RouterId>>, ScenarioError> {
        let e = *external_routers.first().unwrap();
        let asid = net.get_device(e)?.external_or_err()?.as_id();
        let best_path = vec![asid, asid, 1000.into()];
        let same_path = vec![asid, asid, asid, 1000.into()];

        Ok(match self {
            ScenarioEvent::WithdrawSimilarRoute(_) => Some(AnalyzerEvent::WithdrawRoute(
                scenario_prefix.prefixes(),
                e,
                same_path,
            )),
            ScenarioEvent::WithdrawBestRoute(_) => Some(AnalyzerEvent::WithdrawRoute(
                scenario_prefix.prefixes(),
                e,
                best_path,
            )),
            ScenarioEvent::NewSimilarRoute(_) | ScenarioEvent::DecreaseRoutePreference(_) => Some(
                AnalyzerEvent::AnnounceRoute(scenario_prefix.prefixes(), e, same_path),
            ),
            ScenarioEvent::NewBestRoute(_) | ScenarioEvent::IncreaseRoutePreference(_) => Some(
                AnalyzerEvent::AnnounceRoute(scenario_prefix.prefixes(), e, best_path),
            ),
            ScenarioEvent::RemoveLink => get_relevant_link(net, *routers.first().unwrap())?
                .map(|(a, b)| AnalyzerEvent::RemoveLink(scenario_prefix.prefixes(), a, b)),
            ScenarioEvent::AddLink => {
                if let Some((a, b)) = get_relevant_link(net, *routers.first().unwrap())? {
                    let w_a = net.set_link_weight(a, b, LinkWeight::INFINITY).unwrap();
                    let w_b = net.set_link_weight(b, a, LinkWeight::INFINITY).unwrap();
                    Some(AnalyzerEvent::AddLink(
                        scenario_prefix.prefixes(),
                        a,
                        b,
                        w_a,
                        w_b,
                    ))
                } else {
                    None
                }
            }
            ScenarioEvent::RemoveExternalLink => get_relevant_external_link(net, e)?
                .map(|(a, b)| AnalyzerEvent::RemoveLink(scenario_prefix.prefixes(), a, b)),
            ScenarioEvent::AddExternalLink => unimplemented!(),
        })
    }
}

#[allow(unreachable_code)]
#[allow(unused)]
fn get_relevant_link(
    net: &Network<P, BasicEventQueue<P>>,
    source: RouterId,
) -> Result<Option<(RouterId, RouterId)>, ScenarioError> {
    todo!("update to multi-prefix mode!");
    let mut fw_state = net.get_forwarding_state();
    let original_nh = net
        .get_device(source)?
        .unwrap_internal()
        .bgp
        .get_rib()
        .get(&P::from(0))
        .map(|r| r.route.next_hop)
        .unwrap_or(source);

    let original_path = fw_state
        .get_paths(source, P::from(0))
        .map_err(|_| ScenarioError::NotConnected)?
        .pop()
        .unwrap();

    let mut links = zip(
        &original_path[0..original_path.len() - 2],
        &original_path[1..original_path.len() - 1],
    )
    .map(|(a, b)| {
        if a.index() < b.index() {
            (*a, *b)
        } else {
            (*b, *a)
        }
    })
    .unique()
    .collect_vec();

    links.shuffle(&mut thread_rng());

    let mut t = net.clone();
    t.manual_simulation();

    // go through links and make sure removal will change at least this router's next hop
    for (a, b) in links {
        let w_a = t.set_link_weight(a, b, LinkWeight::INFINITY)?;
        let w_b = t.set_link_weight(b, a, LinkWeight::INFINITY)?;
        t.simulate()?;
        let new_nh = t
            .get_device(source)?
            .unwrap_internal()
            .bgp
            .get_rib()
            .get(&P::from(0))
            .map(|r| r.route.next_hop)
            .unwrap_or(source);
        if new_nh != original_nh {
            return Ok(Some((a, b)));
        }

        let _ = t.set_link_weight(a, b, w_a)?;
        let _ = t.set_link_weight(b, a, w_b)?;
        t.simulate()?;
    }

    Ok(None)
}

fn get_relevant_external_link(
    net: &Network<P, BasicEventQueue<P>>,
    ext: RouterId,
) -> Result<Option<(RouterId, RouterId)>, ScenarioError> {
    let external = net.get_device(ext)?.unwrap_external();
    let mut peers: Vec<RouterId> = external.get_bgp_sessions().iter().copied().collect();

    peers.shuffle(&mut thread_rng());

    let route_map_order = 99;
    let route_map = RouteMapBuilder::new().order(route_map_order).deny().build();

    let mut t = net.clone();
    t.manual_simulation();

    // go through peers and make sure removal will change at least some router's next hop
    for rid in peers.iter() {
        let original_nh = net
            .get_device(*rid)?
            .unwrap_internal()
            .bgp
            .get_rib()
            .get(&P::from(0))
            .map(|r| r.route.next_hop)
            .unwrap_or(*rid);

        let _ = t.set_bgp_route_map(*rid, ext, RouteMapDirection::Incoming, route_map.clone());
        t.simulate()?;

        let new_nh = t
            .get_device(*rid)?
            .unwrap_internal()
            .bgp
            .get_rib()
            .get(&P::from(0))
            .map(|r| r.route.next_hop)
            .unwrap_or(*rid);
        if new_nh != original_nh {
            return Ok(Some((*rid, ext)));
        }

        let _ = t.remove_bgp_route_map(
            *rid,
            ext,
            RouteMapDirection::Incoming,
            route_map_order.try_into().unwrap(),
        );
        t.simulate()?;
    }

    Ok(None)
}

/// Policies that one may want to verify / analyze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScenarioPolicy {
    /// Require the network to be free of loops. If the argument is `Some(k)`, then only require
    /// this property on the `k` highest degree nodes. If the boolean is `true`, then use strict
    /// transient constraints instead of atomic ones.
    LoopFreedom(Option<usize>),
    /// Require the network to have neither black holes nor forwarding loops. In other words,
    /// require that every router is able to reach the prefix. This ignores strictly transient
    /// loops (but it still requires strictly transient black holes)! If the argument is `Some(k)`,
    /// then only require this property on the `k` highest degree nodes. If the boolean is `true`,
    /// then use strict transient constraints instead of atomic ones.
    Reachability(Option<usize>),
    /// Require that all routers in the network will choose one of the most preferred rotues (before
    /// and after), but never a route that no router will ever choose in the initial or in the final
    /// state. This property will add waypoint properties. If the argument is `Some(k)`, then
    /// require this property only on the `k` routers with highest degree. If the boolean is `true`,
    /// then use strict transient constraints instead of atomic ones.
    IgnoreWorstRoute(Option<usize>),
}

impl ScenarioPolicy {
    pub fn num_routers(&self) -> Option<usize> {
        match self {
            ScenarioPolicy::LoopFreedom(k)
            | ScenarioPolicy::Reachability(k)
            | ScenarioPolicy::IgnoreWorstRoute(k) => *k,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ScenarioPolicy::LoopFreedom(_) => "LoopFreedom",
            ScenarioPolicy::Reachability(_) => "Reachability",
            ScenarioPolicy::IgnoreWorstRoute(_) => "IgnoreWorstRoute",
        }
    }

    fn build<Q>(
        &self,
        scenario_prefix: &ScenarioPrefix,
        net: &Network<P, Q>,
        routers: &[RouterId],
        external_routers: &[RouterId],
    ) -> Vec<TransientPolicy> {
        let k_ext = (external_routers.len() - 1) / 2;
        match self {
            ScenarioPolicy::LoopFreedom(k) => {
                let k = k.unwrap_or_else(|| net.internal_routers().count());
                scenario_prefix
                    .prefixes()
                    .iter()
                    .flat_map(|prefix| {
                        routers
                            .iter()
                            .take(k)
                            .map(|r| TransientPolicy::Atomic(FwPolicy::LoopFree(*r, *prefix)))
                    })
                    .collect()
            }
            ScenarioPolicy::Reachability(k) => {
                let k = k.unwrap_or_else(|| net.internal_routers().count());
                scenario_prefix
                    .prefixes()
                    .iter()
                    .flat_map(|prefix| {
                        routers
                            .iter()
                            .take(k)
                            .map(|r| TransientPolicy::Atomic(FwPolicy::Reachable(*r, *prefix)))
                    })
                    .collect()
            }
            ScenarioPolicy::IgnoreWorstRoute(k) => {
                let k = k.unwrap_or_else(|| net.internal_routers().count());
                scenario_prefix
                    .prefixes()
                    .iter()
                    .flat_map(|prefix| {
                        routers.iter().take(k).map(|r| {
                            TransientPolicy::Atomic(FwPolicy::PathCondition(
                                *r,
                                *prefix,
                                // Any of the better paths
                                PathCondition::Not(Box::new(PathCondition::Or(
                                    external_routers[(k_ext + 1)..]
                                        .iter()
                                        .map(|r| PathCondition::Node(*r))
                                        .collect(),
                                ))),
                            ))
                        })
                    })
                    .collect()
            }
        }
    }
}

/// Error thrown when the scenario could not be built.
#[derive(Debug, Error)]
pub enum ScenarioError {
    /// Network error thrown
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),
    /// Could not generate an interesting scenario after 10 tries!
    #[error("Could not generate an interesting scenario after 10 tries!")]
    GenerationError,
    /// The topology seems to be not connected.
    #[error("The topology seems to be not connected.")]
    NotConnected,
}
