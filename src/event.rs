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
use std::{hash::Hash, time::Duration};

use serde::{Deserialize, Serialize};

use bgpsim::{
    event::{EventQueue, FmtPriority},
    export::cisco_frr_generators::{RouteMapItem, Target},
    ospf::LinkWeight,
    prelude::*,
    route_map::{RouteMapBuilder, RouteMapDirection},
};
use router_lab::{Active, RouterLab, Inactive};
use itertools::Itertools;

use crate::{routing_inputs::RoutingInputs, Prefix};

/// The prepared event to be executed.
///
/// The type `R` can either be `String` (to refer to the name of a router), or `RouterId`
/// referring to the ID of the router.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AnalyzerEvent<R> {
    AddLink(Vec<Prefix>, R, R, LinkWeight, LinkWeight),
    RemoveLink(Vec<Prefix>, R, R),
    LowerLocalPref(Vec<Prefix>, R, R),
    AnnounceRoute(Vec<Prefix>, R, Vec<AsId>),
    WithdrawRoute(Vec<Prefix>, R, Vec<AsId>),
    AnnounceRoutingInputs(RoutingInputs<R>),
    WithdrawRoutingInputs(RoutingInputs<R>),
    PhysicalExternalAnnounceRoute(Vec<Prefix>, R, Vec<AsId>),
    PhysicalExternalWithdrawRoute(Vec<Prefix>, R, Vec<AsId>),
    PhysicalExternalAnnounceRoutingInputs(RoutingInputs<R>),
    PhysicalExternalWithdrawRoutingInputs(RoutingInputs<R>),
    PhysicalExternalUpdateBetterRoutingInputs(RoutingInputs<R>),
    PhysicalExternalUpdateWorseRoutingInputs(RoutingInputs<R>),
}

impl<R> AnalyzerEvent<R> {
    /// Return the set of prefixes touched by this event
    pub fn prefixes(&self) -> Vec<Prefix> {
        match self {
            Self::AddLink(prefixes, _, _, _, _)
            | Self::RemoveLink(prefixes, _, _)
            | Self::LowerLocalPref(prefixes, _, _)
            | Self::AnnounceRoute(prefixes, _, _)
            | Self::WithdrawRoute(prefixes, _, _)
            | Self::PhysicalExternalAnnounceRoute(prefixes, _, _)
            | Self::PhysicalExternalWithdrawRoute(prefixes, _, _) => prefixes.clone(),
            Self::AnnounceRoutingInputs(inputs)
            | Self::WithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalAnnounceRoutingInputs(inputs)
            | Self::PhysicalExternalWithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(inputs) => inputs.get_prefixes(),
        }
    }
}

impl<R> AnalyzerEvent<R>
where
    R: Clone,
{
    /// Get a set of external routers configured for that event. The same router may appear multiple times.
    pub fn external_routers(&self) -> Vec<(R, AsId)> {
        match self {
            Self::AddLink(_prefixes, _, _, _, _)
            | Self::RemoveLink(_prefixes, _, _)
            | Self::LowerLocalPref(_prefixes, _, _) => Default::default(),
            Self::AnnounceRoute(_, r, path)
            | Self::WithdrawRoute(_, r, path)
            | Self::PhysicalExternalAnnounceRoute(_, r, path)
            | Self::PhysicalExternalWithdrawRoute(_, r, path) => {
                Some((r.clone(), path[0])).into_iter().collect()
            }
            Self::AnnounceRoutingInputs(inputs)
            | Self::WithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalAnnounceRoutingInputs(inputs)
            | Self::PhysicalExternalWithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(inputs) => inputs.external_routers(),
        }
    }
}

impl<R> AnalyzerEvent<R>
where
    R: Clone + Eq + Hash,
{
    pub(crate) fn get_triggering_external(&self) -> Option<R> {
        match self {
            Self::PhysicalExternalAnnounceRoute(_prefixes, external_router, _as_path)
            | Self::PhysicalExternalWithdrawRoute(_prefixes, external_router, _as_path) => {
                Some(external_router.clone())
            }
            Self::PhysicalExternalAnnounceRoutingInputs(inputs)
            | Self::PhysicalExternalWithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(inputs) => {
                let external_routers = inputs.external_routers();
                assert_eq!(external_routers.iter().unique().count(), 1);
                Some(external_routers[0].0.clone())
            }
            _ => None,
        }
    }
}

impl<R> AnalyzerEvent<R>
where
    R: AsRef<str>,
{
    /// Lookup the router names and generate a `RoutingInputs<RouterId>` from a
    /// `RoutingInputs<String>` or `RoutingInputs<&str>`.
    pub fn build<Q>(
        self,
        net: &Network<Prefix, Q>,
    ) -> Result<AnalyzerEvent<RouterId>, NetworkError> {
        Ok(match self {
            AnalyzerEvent::AddLink(prefixes, a, b, w1, w2) => AnalyzerEvent::AddLink(
                prefixes,
                net.get_router_id(a)?,
                net.get_router_id(b)?,
                w1,
                w2,
            ),
            AnalyzerEvent::RemoveLink(prefixes, a, b) => {
                AnalyzerEvent::RemoveLink(prefixes, net.get_router_id(a)?, net.get_router_id(b)?)
            }
            AnalyzerEvent::LowerLocalPref(prefixes, a, b) => AnalyzerEvent::LowerLocalPref(
                prefixes,
                net.get_router_id(a)?,
                net.get_router_id(b)?,
            ),
            AnalyzerEvent::AnnounceRoute(prefixes, r, path) => {
                AnalyzerEvent::AnnounceRoute(prefixes, net.get_router_id(r)?, path)
            }
            AnalyzerEvent::WithdrawRoute(prefixes, r, path) => {
                AnalyzerEvent::WithdrawRoute(prefixes, net.get_router_id(r)?, path)
            }
            AnalyzerEvent::AnnounceRoutingInputs(i) => {
                AnalyzerEvent::AnnounceRoutingInputs(i.build(net)?)
            }
            AnalyzerEvent::WithdrawRoutingInputs(i) => {
                AnalyzerEvent::WithdrawRoutingInputs(i.build(net)?)
            }
            AnalyzerEvent::PhysicalExternalAnnounceRoute(prefixes, r, path) => {
                AnalyzerEvent::PhysicalExternalAnnounceRoute(prefixes, net.get_router_id(r)?, path)
            }
            AnalyzerEvent::PhysicalExternalWithdrawRoute(prefixes, r, path) => {
                AnalyzerEvent::PhysicalExternalWithdrawRoute(prefixes, net.get_router_id(r)?, path)
            }
            AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(i) => {
                AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(i.build(net)?)
            }
            AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(i) => {
                AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(i.build(net)?)
            }
            AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(i) => {
                AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(i.build(net)?)
            }
            AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(i) => {
                AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(i.build(net)?)
            }
        })
    }
}

impl AnalyzerEvent<RouterId> {
    /// Prepares initial advertisements for use with a physical external router
    pub fn prepare_initial_advertisements<Q, Ospf: OspfImpl>(
        &self,
        lab: &mut RouterLab<Prefix, Q, Ospf, Inactive>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::PhysicalExternalAnnounceRoute(prefixes, r, path) => {
                // announce routes that can be uncovered by removing the route-map. see
                // `setup_cisco_direct` for the setup of the route-map.
                for prefix in prefixes.iter() {
                    lab.advertise_route(
                        *r,
                        &BgpRoute::new(
                            *r,
                            *prefix,
                            path,
                            None,
                            vec![bgpsim::types::Prefix::as_num(prefix)],
                        ),
                    )?;
                }
            }
            Self::PhysicalExternalAnnounceRoutingInputs(inputs) => {
                // announce routes that can be uncovered by removing the route-map. see
                // `setup_cisco_direct` for the setup of the route-map.
                for (router, route) in inputs.all_routes() {
                    lab.advertise_route(router, &route)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn setup_cisco_direct<Q: EventQueue<Prefix> + Clone, Ospf: OspfImpl>(
        &self,
        lab: &mut RouterLab<'_, Prefix, Q, Ospf, Active>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::AddLink(_, _, _, _, _) => {
                unimplemented!("AddLink not supported yet on the RouterLab!")
            }
            Self::RemoveLink(_, _, _) => {}
            Self::LowerLocalPref(_, _, _) => {
                unimplemented!("LowerLocalPref not supported yet on the RouterLab!")
            }
            Self::AnnounceRoute(_, _, _)
            | Self::WithdrawRoute(_, _, _)
            | Self::AnnounceRoutingInputs(_)
            | Self::WithdrawRoutingInputs(_) => {}
            Self::PhysicalExternalAnnounceRoute(_, _, _)
            | Self::PhysicalExternalAnnounceRoutingInputs(_) => {
                // make sure route is not actually advertised by the physical external router
                self.revert_cisco_direct(lab).await?;
            }
            Self::PhysicalExternalWithdrawRoute(_, _, _)
            | Self::PhysicalExternalWithdrawRoutingInputs(_)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(_)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(_) => {}
        }
        Ok(())
    }

    /// Triggers the specified event on the bgpsim simulator.
    pub fn trigger<Q>(&self, net: &mut Network<Prefix, Q>) -> Result<(), NetworkError>
    where
        Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
        Q::Priority: Default + FmtPriority + Clone,
    {
        match self {
            Self::AddLink(_, a, b, w_a, w_b) => {
                net.add_link(*a, *b)?;
                net.set_link_weight(*a, *b, *w_a)?;
                net.set_link_weight(*b, *a, *w_b)?;
            }
            Self::RemoveLink(_, a, b) => {
                net.remove_link(*a, *b)?;
            }
            Self::LowerLocalPref(_, r, ext) => {
                net.set_bgp_route_map(
                    *r,
                    *ext,
                    RouteMapDirection::Incoming,
                    RouteMapBuilder::new()
                        .order(0)
                        .allow()
                        .set_local_pref(1)
                        .build(),
                )?;
            }
            Self::AnnounceRoute(prefixes, r, path)
            | Self::PhysicalExternalAnnounceRoute(prefixes, r, path) => {
                for prefix in prefixes.iter() {
                    net.advertise_external_route(
                        *r,
                        *prefix,
                        path,
                        None,
                        vec![bgpsim::types::Prefix::as_num(prefix)],
                    )?;
                }
            }
            Self::WithdrawRoute(prefixes, r, _)
            | Self::PhysicalExternalWithdrawRoute(prefixes, r, _) => {
                for prefix in prefixes.iter() {
                    net.withdraw_external_route(*r, *prefix)?;
                }
            }
            Self::AnnounceRoutingInputs(inputs)
            | Self::PhysicalExternalAnnounceRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(inputs)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(inputs) => {
                inputs.advertise_to(net);
            }
            Self::WithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalWithdrawRoutingInputs(inputs) => {
                inputs.retract_from(net);
            }
        }
        Ok(())
    }

    /// Triggers the specified event on the disconnected router_lab.
    pub fn trigger_cisco_exabgp<Q, Ospf: OspfImpl>(
        &self,
        lab: &mut RouterLab<Prefix, Q, Ospf, Inactive>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::AddLink(_, _, _, _, _) | Self::RemoveLink(_, _, _) => {}
            Self::LowerLocalPref(_, _, _) => {
                unimplemented!("LowerLocalPref not supported yet on the RouterLab!")
            }
            Self::AnnounceRoute(prefixes, r, path) => {
                for prefix in prefixes.iter() {
                    lab.advertise_route(
                        *r,
                        &BgpRoute::new(
                            *r,
                            *prefix,
                            path,
                            None,
                            vec![bgpsim::types::Prefix::as_num(prefix)],
                        ),
                    )?;
                }
            }
            Self::WithdrawRoute(prefixes, r, _) => {
                for prefix in prefixes.iter() {
                    lab.withdraw_route(*r, *prefix)?;
                }
            }
            Self::AnnounceRoutingInputs(inputs) => {
                for (router, route) in inputs.all_routes() {
                    lab.advertise_route(router, &route)?;
                }
            }
            Self::WithdrawRoutingInputs(inputs) => {
                for (router, route) in inputs.all_routes() {
                    lab.withdraw_route(router, route.prefix)?;
                }
            }
            Self::PhysicalExternalAnnounceRoute(_, _, _)
            | Self::PhysicalExternalWithdrawRoute(_, _, _)
            | Self::PhysicalExternalAnnounceRoutingInputs(_)
            | Self::PhysicalExternalWithdrawRoutingInputs(_)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(_)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(_) => {}
        };
        Ok(())
    }

    /// Reverts the specified event on the disconnected router_lab.
    pub fn revert_cisco_exabgp<Q, Ospf: OspfImpl>(
        &self,
        lab: &mut RouterLab<Prefix, Q, Ospf, Inactive>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::AddLink(_, _, _, _, _) | Self::RemoveLink(_, _, _) => {}
            Self::LowerLocalPref(_, _, _) => {
                unimplemented!("LowerLocalPref not supported yet on the RouterLab!")
            }
            Self::AnnounceRoute(prefixes, r, _) => {
                for prefix in prefixes.iter() {
                    lab.withdraw_route(*r, *prefix)?;
                }
            }
            Self::WithdrawRoute(prefixes, r, path) => {
                for prefix in prefixes.iter() {
                    lab.advertise_route(
                        *r,
                        &BgpRoute::new(
                            *r,
                            *prefix,
                            path,
                            None,
                            vec![bgpsim::types::Prefix::as_num(prefix)],
                        ),
                    )?;
                }
            }
            Self::AnnounceRoutingInputs(inputs) => {
                for (router, route) in inputs.all_routes() {
                    lab.withdraw_route(router, route.prefix)?;
                }
            }
            Self::WithdrawRoutingInputs(inputs) => {
                for (router, route) in inputs.all_routes() {
                    lab.advertise_route(router, &route)?;
                }
            }
            Self::PhysicalExternalAnnounceRoute(_, _, _)
            | Self::PhysicalExternalWithdrawRoute(_, _, _)
            | Self::PhysicalExternalAnnounceRoutingInputs(_)
            | Self::PhysicalExternalWithdrawRoutingInputs(_)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(_)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(_) => {}
        };
        Ok(())
    }

    /// Triggers the specified event on the connected router_lab.
    pub async fn trigger_cisco_direct<Q: EventQueue<Prefix> + Clone, Ospf: OspfImpl>(
        &self,
        lab: &mut RouterLab<'_, Prefix, Q, Ospf, Active>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::AddLink(_, _a, _b, _, _) => {
                unimplemented!("AddLink not supported yet on the RouterLab!")
            }
            Self::RemoveLink(_, a, b) => {
                lab.disable_link(*a, *b).await?;
            }
            Self::LowerLocalPref(_, _, _) => {
                unimplemented!("LowerLocalPref not supported yet on the RouterLab!")
            }
            Self::AnnounceRoute(_, _, _)
            | Self::WithdrawRoute(_, _, _)
            | Self::AnnounceRoutingInputs(_)
            | Self::WithdrawRoutingInputs(_) => {}
            Self::PhysicalExternalAnnounceRoute(_, _, _)
            | Self::PhysicalExternalAnnounceRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        RouteMapItem::new("neighbor-out", 10, false).no(Target::CiscoNexus7000),
                    )
                    .await?;
            }
            Self::PhysicalExternalWithdrawRoute(_, _, _)
            | Self::PhysicalExternalWithdrawRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        RouteMapItem::new("neighbor-out", 10, false).build(Target::CiscoNexus7000),
                    )
                    .await?;
            }
            Self::PhysicalExternalUpdateBetterRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        "\
route-map neighbor-out permit 10
    set as-path replace 666 with none
",
                    )
                    .await?;
            }
            Self::PhysicalExternalUpdateWorseRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                let as_id = lab
                    .external_routers()
                    .get(&physical_ext)
                    .expect("router should exist")
                    .try_get_exabgp_info()
                    .expect("should be a cisco router")
                    .router_as;
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        RouteMapItem::new("neighbor-out", 10, true)
                            .prepend_as_path([as_id, as_id])
                            .build(Target::CiscoNexus7000),
                    )
                    .await?;
            }
        };
        Ok(())
    }

    /// Reverts the specified event on the connected router_lab.
    pub async fn revert_cisco_direct<Q: EventQueue<Prefix> + Clone, Ospf: OspfImpl>(
        &self,
        lab: &mut RouterLab<'_, Prefix, Q, Ospf, Active>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::AddLink(_, _, _, _, _) => {
                unimplemented!("AddLink not supported yet on the RouterLab!")
            }
            Self::RemoveLink(_, a, b) => {
                lab.enable_link(*a, *b).await?;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Self::LowerLocalPref(_, _, _) => {
                unimplemented!("LowerLocalPref not supported yet on the RouterLab!")
            }
            Self::AnnounceRoute(_, _, _)
            | Self::WithdrawRoute(_, _, _)
            | Self::AnnounceRoutingInputs(_)
            | Self::WithdrawRoutingInputs(_) => {}
            Self::PhysicalExternalAnnounceRoute(_, _, _)
            | Self::PhysicalExternalAnnounceRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        RouteMapItem::new("neighbor-out", 10, false).build(Target::CiscoNexus7000),
                    )
                    .await?;
            }
            Self::PhysicalExternalWithdrawRoute(_, _, _)
            | Self::PhysicalExternalWithdrawRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        RouteMapItem::new("neighbor-out", 10, false).no(Target::CiscoNexus7000),
                    )
                    .await?;
            }
            Self::PhysicalExternalUpdateBetterRoutingInputs(_)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(_) => {
                let physical_ext = self.get_triggering_external().unwrap();
                // manipulate route-map "neighbor-out" to control routes advertised to the network
                lab.get_router_session(physical_ext)
                    .unwrap()
                    .shell()
                    .configure(
                        RouteMapItem::new("neighbor-out", 10, true).no(Target::CiscoNexus7000),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Filter the collected packets, returns true if the packet should be retained.
    pub fn collector_filter(
        &self,
        event_start: &f64,
        prefix: Prefix,
        t_rx: &f64,
        ext: &RouterId,
    ) -> bool {
        match self {
            Self::AddLink(_, _, _, _, _)
            | Self::RemoveLink(_, _, _)
            | Self::LowerLocalPref(_, _, _)
            | Self::AnnounceRoute(_, _, _)
            | Self::AnnounceRoutingInputs(_)
            | Self::PhysicalExternalAnnounceRoute(_, _, _)
            | Self::PhysicalExternalAnnounceRoutingInputs(_)
            | Self::PhysicalExternalUpdateBetterRoutingInputs(_)
            | Self::PhysicalExternalUpdateWorseRoutingInputs(_) => true,
            Self::WithdrawRoute(prefixes, r, _path)
            | Self::PhysicalExternalWithdrawRoute(prefixes, r, _path) => {
                *t_rx < *event_start || ext != r || !prefixes.contains(&prefix)
            }
            Self::WithdrawRoutingInputs(inputs)
            | Self::PhysicalExternalWithdrawRoutingInputs(inputs) => {
                *t_rx < *event_start || !inputs.contains(prefix, *ext)
            }
        }
    }
}

#[allow(unused)]
impl<R: std::fmt::Debug + Clone> std::fmt::Display for AnalyzerEvent<R> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match self {
            Self::AddLink(_, a, b, w1, w2) => format!("AddLink({a:?}, {b:?}, {w1}, {w2})"),
            Self::RemoveLink(_, a, b) => format!("RemoveLink({a:?}, {b:?})"),
            Self::LowerLocalPref(_, a, b) => format!("LowerLocalPref({a:?}, {b:?})"),
            Self::AnnounceRoute(_, x, aspath) => format!("AnnounceRoute({x:?}, {aspath:?})"),
            Self::WithdrawRoute(_, x, aspath) => format!("Withdrawroute({x:?}, {aspath:?})"),
            Self::AnnounceRoutingInputs(inputs) => format!(
                "AnnounceRoutingInputs({})",
                inputs
                    .unroll()
                    .map(|(prefix, router, path)| format!("({router:?}, {prefix:?}, {path:?})"))
                    .join(", ")
            ),
            Self::WithdrawRoutingInputs(inputs) => format!(
                "WithdrawRoutingInputs({})",
                inputs
                    .unroll()
                    .map(|(prefix, router, path)| format!("({router:?}, {prefix:?}, {path:?})"))
                    .join(", ")
            ),
            Self::PhysicalExternalAnnounceRoute(_, x, aspath) => {
                format!("PhysAnnounceRoute({x:?}, {aspath:?})")
            }
            Self::PhysicalExternalWithdrawRoute(_, x, aspath) => {
                format!("PhysWithdrawroute({x:?}, {aspath:?})")
            }
            Self::PhysicalExternalAnnounceRoutingInputs(inputs) => format!(
                "PhysAnnounceRoutingInputs({})",
                inputs
                    .unroll()
                    .map(|(prefix, router, path)| format!("({router:?}, {prefix:?}, {path:?})"))
                    .join(", ")
            ),
            Self::PhysicalExternalWithdrawRoutingInputs(inputs) => format!(
                "PhysWithdrawRoutingInputs({})",
                inputs
                    .unroll()
                    .map(|(prefix, router, path)| format!("({router:?}, {prefix:?}, {path:?})"))
                    .join(", ")
            ),
            Self::PhysicalExternalUpdateBetterRoutingInputs(inputs) => format!(
                "PhysUpdateBetterRoutingInputs({})",
                inputs
                    .unroll()
                    .map(|(prefix, router, path)| format!("({router:?}, {prefix:?}, {path:?})"))
                    .join(", ")
            ),
            Self::PhysicalExternalUpdateWorseRoutingInputs(inputs) => format!(
                "PhysUpdateWorseRoutingInputs({})",
                inputs
                    .unroll()
                    .map(|(prefix, router, path)| format!("({router:?}, {prefix:?}, {path:?})"))
                    .join(", ")
            ),
        };
        fmt.write_str(&name);
        Ok(())
    }
}

impl<'a, 'n, Q, Ospf: OspfImpl> bgpsim::formatter::NetworkFormatter<'a, 'n, Prefix, Q, Ospf>
    for AnalyzerEvent<RouterId>
{
    type Formatter = String;

    fn fmt(&'a self, net: &'n Network<Prefix, Q, Ospf>) -> Self::Formatter {
        match self {
            Self::AddLink(_, a, b, _, _) => format!("AddLink_{}_{}", a.fmt(net), b.fmt(net)),
            Self::RemoveLink(_, a, b) => format!("RemoveLink_{}_{}", a.fmt(net), b.fmt(net)),
            Self::LowerLocalPref(_, a, b) => {
                format!("LowerLocalPref_{}_{}", a.fmt(net), b.fmt(net))
            }
            Self::AnnounceRoute(_, x, _) => format!("AnnounceRoute_{}", x.fmt(net)),
            Self::WithdrawRoute(_, x, _) => format!("Withdrawroute_{}", x.fmt(net)),
            Self::AnnounceRoutingInputs(i) => format!("AnnounceRoutingInputs_{}", i.simple_fmt()),
            Self::WithdrawRoutingInputs(i) => format!("WithdrawRoutingInputs_{}", i.simple_fmt()),
            Self::PhysicalExternalAnnounceRoute(_, x, _) => {
                format!("PhysAnnounceRoute_{}", x.fmt(net))
            }
            Self::PhysicalExternalWithdrawRoute(_, x, _) => {
                format!("PhysWithdrawroute_{}", x.fmt(net))
            }
            Self::PhysicalExternalAnnounceRoutingInputs(i) => {
                format!("PhysAnnounceRoutingInputs_{}", i.simple_fmt())
            }
            Self::PhysicalExternalWithdrawRoutingInputs(i) => {
                format!("PhysWithdrawRoutingInputs_{}", i.simple_fmt())
            }
            Self::PhysicalExternalUpdateBetterRoutingInputs(i) => {
                format!("PhysUpdateBetterRoutingInputs_{}", i.simple_fmt())
            }
            Self::PhysicalExternalUpdateWorseRoutingInputs(i) => {
                format!("PhysUpdateWorseRoutingInputs_{}", i.simple_fmt())
            }
        }
    }
}
