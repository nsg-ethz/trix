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
use std::iter::zip;

//use itertools::Itertools;
use serde::{Deserialize, Serialize};

use bgpsim::{event::EventQueue, prelude::*, types::AsId};

use crate::{analyzer::AnalyzerPrefix, Prefix as P};

/// Describes a (sub-)set of jointly controlled external routing inputs.
///
/// The type `R` can either be `String` (to refer to the name an external router), or `RouterId`
/// referring to the ID of the external router.
///
/// Note: To allow for experiments on a subset of prefixes, use the `filter()` function.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum RoutingInputs<R> {
    /// Single prefix advertised at the given internal routers by name and AS path.
    SinglePrefix(Vec<(R, Vec<AsId>)>),
    /// Multiple Prefixes, each advertised to a separate set of internal routers given by name and
    /// AS path.
    MultiPrefix(Vec<Vec<(R, Vec<AsId>)>>),
    /// Same as `MultiPrefixes`, but the `inner` is repeated `num` times.
    RepeatedPrefix {
        inner: Vec<(R, Vec<AsId>)>,
        num: usize,
    },
}

impl<R> RoutingInputs<R> {
    pub fn get_prefixes(&self) -> Vec<P> {
        match self {
            Self::SinglePrefix(_) => AnalyzerPrefix::SinglePrefix,
            Self::MultiPrefix(routers_per_prefix) => {
                AnalyzerPrefix::MultiPrefix(routers_per_prefix.len())
            }
            Self::RepeatedPrefix { num, .. } => AnalyzerPrefix::MultiPrefix(*num),
        }
        .prefixes()
    }

    pub fn simple_fmt(&self) -> &'static str {
        match self {
            RoutingInputs::SinglePrefix(_) => "SinglePrefix",
            RoutingInputs::MultiPrefix(_) => "MultiPrefix",
            RoutingInputs::RepeatedPrefix { .. } => "MultiPrefix",
        }
    }
}

impl<R> RoutingInputs<R>
where
    R: Clone,
{
    pub fn filter<F>(&self, mut f: F) -> Self
    where
        F: FnMut(&P, &R, &[AsId]) -> bool,
    {
        match self {
            RoutingInputs::SinglePrefix(routes) => {
                let prefix = self.get_prefixes()[0];
                RoutingInputs::SinglePrefix(
                    routes
                        .iter()
                        .filter(|(router, path)| f(&prefix, router, path))
                        .map(|(router, path)| (router.clone(), path.clone()))
                        .collect(),
                )
            }
            RoutingInputs::MultiPrefix(routes_for_prefix) => RoutingInputs::MultiPrefix(
                zip(self.get_prefixes(), routes_for_prefix)
                    .map(|(prefix, routes)| {
                        routes
                            .iter()
                            .filter(|(router, path)| f(&prefix, router, path))
                            .map(|(router, path)| (router.clone(), path.clone()))
                            .collect()
                    })
                    .collect(),
            ),
            RoutingInputs::RepeatedPrefix { inner, .. } => RoutingInputs::MultiPrefix(
                zip(self.get_prefixes(), std::iter::repeat(inner))
                    .map(|(prefix, routes)| {
                        routes
                            .iter()
                            .filter(|(router, path)| f(&prefix, router, path))
                            .map(|(router, path)| (router.clone(), path.clone()))
                            .collect()
                    })
                    .collect(),
            ),
        }
    }

    pub fn filter_route<F>(&self, mut f: F) -> Self
    where
        F: FnMut(&R, &[AsId]) -> bool,
    {
        match self {
            RoutingInputs::SinglePrefix(routes) => RoutingInputs::SinglePrefix(
                routes
                    .iter()
                    .filter(|(router, path)| f(router, path))
                    .map(|(router, path)| (router.clone(), path.clone()))
                    .collect(),
            ),
            RoutingInputs::MultiPrefix(routes_for_prefix) => RoutingInputs::MultiPrefix(
                routes_for_prefix
                    .iter()
                    .map(|routes| {
                        routes
                            .iter()
                            .filter(|(router, path)| f(router, path))
                            .map(|(router, path)| (router.clone(), path.clone()))
                            .collect()
                    })
                    .collect(),
            ),
            RoutingInputs::RepeatedPrefix { inner, num } => RoutingInputs::RepeatedPrefix {
                inner: inner
                    .iter()
                    .filter(|(router, path)| f(router, path))
                    .map(|(router, path)| (router.clone(), path.clone()))
                    .collect(),
                num: *num,
            },
        }
    }

    /// Get a list of all defined external routers. Routers may appear multiple times!
    pub fn external_routers(&self) -> Vec<(R, AsId)> {
        match self {
            RoutingInputs::SinglePrefix(routes) => routes
                .iter()
                .map(|(r, path)| (r.clone(), path[0]))
                .collect(),
            RoutingInputs::MultiPrefix(routes_per_prefix) => routes_per_prefix
                .iter()
                .flatten()
                .map(|(r, path)| (r.clone(), path[0]))
                .collect(),
            RoutingInputs::RepeatedPrefix { inner, num } => std::iter::repeat(inner)
                .take(*num)
                .flatten()
                .map(|(r, path)| (r.clone(), path[0]))
                .collect(),
        }
    }

    fn iter(&self) -> impl Iterator<Item = (P, Vec<(R, Vec<AsId>)>)> {
        match self {
            Self::SinglePrefix(routers) => zip(self.get_prefixes(), vec![routers.clone()]),
            Self::MultiPrefix(routers_per_prefix) => {
                zip(self.get_prefixes(), routers_per_prefix.to_vec())
            }
            Self::RepeatedPrefix { inner, num } => {
                zip(self.get_prefixes(), vec![inner.clone(); *num])
            }
        }
    }

    pub fn unroll(&self) -> impl Iterator<Item = (P, R, Vec<AsId>)> {
        self.iter().flat_map(|(prefix, routers_and_aspaths)| {
            routers_and_aspaths
                .into_iter()
                .map(move |(router, aspath)| (prefix, router, aspath))
        })
    }
}

impl<R> RoutingInputs<R>
where
    R: AsRef<str>,
{
    /// Lookup the router names and generate a `RoutingInputs<RouterId>` from a
    /// `RoutingInputs<String>` or `RoutingInputs<&str>`.
    pub fn build<Q>(self, net: &Network<P, Q>) -> Result<RoutingInputs<RouterId>, NetworkError> {
        Ok(match self {
            Self::SinglePrefix(routes) => RoutingInputs::SinglePrefix(
                routes
                    .into_iter()
                    .map(|(name, path)| Ok((net.get_router_id(name)?, path)))
                    .collect::<Result<_, NetworkError>>()?,
            ),
            Self::MultiPrefix(routes_per_prefix) => RoutingInputs::MultiPrefix(
                routes_per_prefix
                    .into_iter()
                    .map(|routes| {
                        routes
                            .into_iter()
                            .map(|(name, path)| Ok((net.get_router_id(name)?, path)))
                            .collect::<Result<Vec<_>, NetworkError>>()
                    })
                    .collect::<Result<Vec<_>, NetworkError>>()?,
            ),
            Self::RepeatedPrefix { inner, num } => {
                RoutingInputs::MultiPrefix(vec![
                    inner
                        .into_iter()
                        .map(|(name, path)| Ok((net.get_router_id(name)?, path)))
                        .collect::<Result<_, NetworkError>>()?;
                    num
                ])
            }
        })
    }
}

impl RoutingInputs<RouterId> {
    /// Allows to check whether a given set of `RoutingInputs` contains a `(Prefix, RouterId)` pair.
    pub fn contains(&self, prefix: P, ext: RouterId) -> bool {
        match self {
            RoutingInputs::SinglePrefix(routes) => {
                self.get_prefixes().contains(&prefix) && routes.iter().any(|(rid, _)| ext == *rid)
            }
            RoutingInputs::MultiPrefix(routes_per_prefix) => {
                if let Some(idx) = self.get_prefixes().iter().position(|p| *p == prefix) {
                    routes_per_prefix[idx].iter().any(|(rid, _)| ext == *rid)
                } else {
                    false
                }
            }
            RoutingInputs::RepeatedPrefix { inner, .. } => {
                if self.get_prefixes().iter().any(|p| *p == prefix) {
                    inner.iter().any(|(rid, _)| ext == *rid)
                } else {
                    false
                }
            }
        }
    }

    pub fn advertise_to<Q: EventQueue<P>>(&self, net: &mut Network<P, Q>) {
        for (prefix, router, aspath) in self.unroll() {
            let _ = net.advertise_external_route(
                router,
                prefix,
                aspath.clone(),
                None,
                [prefix.as_num()],
            );
        }
    }

    pub fn retract_from<Q: EventQueue<P>>(&self, net: &mut Network<P, Q>) {
        for (prefix, router, _) in self.unroll() {
            let _ = net.withdraw_external_route(router, prefix);
        }
    }

    /// Returns an vector of all routes (together with the router that advertise the route).
    pub fn all_routes(&self) -> Vec<(RouterId, BgpRoute<P>)> {
        self.unroll()
            .map(|(prefix, router, as_path)| {
                (
                    router,
                    BgpRoute::new(
                        router,
                        prefix,
                        as_path,
                        None,
                        vec![bgpsim::types::Prefix::as_num(&prefix)],
                    ),
                )
            })
            .collect()
    }
}

impl<'a, 'n, Q, Ospf: OspfImpl> bgpsim::formatter::NetworkFormatter<'a, 'n, P, Q, Ospf>
    for RoutingInputs<RouterId>
{
    type Formatter = String;

    fn fmt(&'a self, net: &'n Network<P, Q, Ospf>) -> Self::Formatter {
        match self {
            RoutingInputs::SinglePrefix(routes) => format!(
                "RoutingInputs(SinglePrefix, advertised at {:?})",
                routes
                    .iter()
                    .map(|(rid, _)| rid.fmt(net))
                    .collect::<Vec<_>>()
            ),
            RoutingInputs::MultiPrefix(routers_per_prefix) => format!(
                "RoutingInputs(MultiPrefix, {:?})",
                routers_per_prefix
                    .iter()
                    .enumerate()
                    .map(|(prefix, routes)| format!(
                        "{prefix} => {:?})",
                        routes
                            .iter()
                            .map(|(rid, _)| rid.fmt(net))
                            .collect::<Vec<_>>()
                    ))
                    .collect::<Vec<_>>()
            ),
            RoutingInputs::RepeatedPrefix { inner, num } => {
                format!(
                    "RoutingInputs(RepeatedPrefix, {:?}, {num})",
                    inner
                        .iter()
                        .map(|(rid, _)| rid.fmt(net))
                        .collect::<Vec<_>>()
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_contains() {
        // define the helper variables
        let r = RouterId::from(0);
        let r2 = RouterId::from(1);
        let p = SimplePrefix::from(0);
        let p2 = SimplePrefix::from(1);
        let aspath = vec![100.into(), 100.into(), 1000.into()];

        // define the routing inputs, announcing `p` at `r` with AS-path `aspath`
        let single = RoutingInputs::SinglePrefix(vec![(r, aspath.clone())]);
        let multi = RoutingInputs::MultiPrefix(vec![vec![(r, aspath.clone())], vec![]]);

        // both routing inputs should contain (p, r)
        assert!(single.contains(p, r));
        assert!(multi.contains(p, r));
        // both should not contain (p, r2)
        assert!(!single.contains(p, r2));
        assert!(!multi.contains(p, r2));
        // both should not contain (p2, r)
        assert!(!single.contains(p2, r));
        assert!(!multi.contains(p2, r));
        // both should not contain (p2, r2)
        assert!(!single.contains(p2, r2));
        assert!(!multi.contains(p2, r2));
    }

    #[test]
    fn test_filter() {
        // define the helper variables
        let r = RouterId::from(0);
        let r2 = RouterId::from(1);
        let p = SimplePrefix::from(0);
        let p2 = SimplePrefix::from(1);
        let aspath = vec![100.into(), 100.into(), 1000.into()];

        // define the routing inputs, announcing `p` at `r` and `r2` with AS-path `aspath`
        let single = RoutingInputs::SinglePrefix(vec![(r, aspath.clone()), (r2, aspath.clone())]);
        let single_filtered_r = RoutingInputs::SinglePrefix(vec![(r, aspath.clone())]);
        let single_filtered_r2 = RoutingInputs::SinglePrefix(vec![(r2, aspath.clone())]);
        let single_empty = RoutingInputs::SinglePrefix(vec![]);

        let multi = RoutingInputs::MultiPrefix(vec![
            vec![(r, aspath.clone()), (r2, aspath.clone())],
            vec![(r, aspath.clone())],
        ]);
        let multi_filtered_r =
            RoutingInputs::MultiPrefix(vec![vec![(r, aspath.clone())], vec![(r, aspath.clone())]]);
        let multi_filtered_r2 =
            RoutingInputs::MultiPrefix(vec![vec![(r2, aspath.clone())], vec![]]);
        let multi_filtered_p = RoutingInputs::MultiPrefix(vec![
            vec![(r, aspath.clone()), (r2, aspath.clone())],
            vec![],
        ]);
        let multi_filtered_p2 = RoutingInputs::MultiPrefix(vec![vec![], vec![(r, aspath.clone())]]);

        // filter by prefix
        assert_eq!(single.filter(|prefix, _, _| *prefix == p), single);
        assert_eq!(single.filter(|prefix, _, _| *prefix == p2), single_empty);
        assert_eq!(multi.filter(|prefix, _, _| *prefix == p), multi_filtered_p);
        assert_eq!(
            multi.filter(|prefix, _, _| *prefix == p2),
            multi_filtered_p2
        );

        // filter by router
        assert_eq!(single.filter(|_, rid, _| *rid == r), single_filtered_r);
        assert_eq!(single.filter(|_, rid, _| *rid == r2), single_filtered_r2);
        assert_eq!(multi.filter(|_, rid, _| *rid == r), multi_filtered_r);
        assert_eq!(multi.filter(|_, rid, _| *rid == r2), multi_filtered_r2);

        // filter by aspath
        assert_eq!(single.filter(|_, _, a| *a == aspath), single);
        assert_eq!(multi.filter(|_, _, a| *a == aspath), multi);
    }

    #[test]
    fn test_filter_repeated() {
        // define the helper variables
        let r = RouterId::from(0);
        let r2 = RouterId::from(1);
        let p = SimplePrefix::from(0);
        let p2 = SimplePrefix::from(1);
        let aspath = vec![100.into(), 100.into(), 1000.into()];

        let repeated = RoutingInputs::RepeatedPrefix {
            inner: vec![(r, aspath.clone()), (r2, aspath.clone())],
            num: 3,
        };

        let multi =
            RoutingInputs::MultiPrefix(vec![vec![(r, aspath.clone()), (r2, aspath.clone())]; 3]);
        let multi_filtered_r = RoutingInputs::MultiPrefix(vec![vec![(r, aspath.clone())]; 3]);
        let multi_filtered_r2 = RoutingInputs::MultiPrefix(vec![vec![(r2, aspath.clone())]; 3]);
        let multi_filtered_p = RoutingInputs::MultiPrefix(vec![
            vec![(r, aspath.clone()), (r2, aspath.clone())],
            vec![],
            vec![],
        ]);
        let multi_filtered_p2 = RoutingInputs::MultiPrefix(vec![
            vec![],
            vec![(r, aspath.clone()), (r2, aspath.clone())],
            vec![],
        ]);

        // filter by prefix
        assert_eq!(
            repeated.filter(|prefix, _, _| *prefix == p),
            multi_filtered_p
        );
        assert_eq!(
            repeated.filter(|prefix, _, _| *prefix == p2),
            multi_filtered_p2
        );

        // filter by router
        assert_eq!(repeated.filter(|_, rid, _| *rid == r), multi_filtered_r);
        assert_eq!(repeated.filter(|_, rid, _| *rid == r2), multi_filtered_r2);

        // filter by aspath
        assert_eq!(repeated.filter(|_, _, a| *a == aspath), multi);
    }
}
