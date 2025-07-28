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
use geoutils::Location;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error};

use bgpsim::{
    builder::{constant_link_weight, NetworkBuilder},
    prelude::*,
    topology_zoo::TopologyZoo,
    types::NetworkDeviceRef,
};

use crate::{event::AnalyzerEvent, routing_inputs::RoutingInputs, Prefix as P};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Topology {
    Path(usize),
    Star(usize),
    Grid(usize, usize),
    TopologyZoo(TopologyZoo),
}

impl Topology {
    /// print readable (and filename-compatible) string representation of the topology
    pub fn fmt(&self) -> String {
        match self {
            Self::Path(i) => format!("Path_{i}"),
            Self::Star(i) => format!("Star_{i}"),
            Self::Grid(rows, cols) => format!("Grid_{rows}_{cols}"),
            Self::TopologyZoo(topo) => format!("{topo:?}"),
        }
    }

    pub fn build_network<R: AsRef<str> + Clone + Eq + std::hash::Hash>(
        &self,
        static_inputs: &RoutingInputs<R>,
        event: &AnalyzerEvent<R>,
    ) -> Result<Network<P>, Box<dyn Error>> {
        let mut net: Network<P> = Network::new(BasicEventQueue::default());
        match self {
            Self::Path(k) => {
                let mut last = None;
                for i in 0..*k {
                    let r = net.add_router(&format!("r{i}"));

                    // connect to the last node
                    if let Some(neighbor) = last {
                        net.add_link(neighbor, r)?;
                        net.set_link_weight(r, neighbor, 1.0)?;
                        net.set_link_weight(neighbor, r, 1.0)?;
                    }
                    last = Some(r);
                }
            }
            Self::Star(k) => {
                let center = net.add_router("center");
                for i in 0..k - 1 {
                    let r = net.add_router(&format!("r{i}"));

                    // connect to the center node
                    net.add_link(r, center)?;
                    net.set_link_weight(r, center, 1.0)?;
                    net.set_link_weight(center, r, 1.0)?;
                }
            }
            #[allow(clippy::needless_range_loop)]
            Self::Grid(rows, cols) => {
                let mut last_row = vec![None; *cols];
                for i in 0..*rows {
                    let mut last = None;
                    for j in 0..*cols {
                        let r = net.add_router(&format!("r_{i}_{j}"));

                        // connect in the row
                        if let Some(neighbor) = last {
                            net.add_link(neighbor, r)?;
                            net.set_link_weight(r, neighbor, 1.0)?;
                            net.set_link_weight(neighbor, r, 1.0)?;
                        }
                        last = Some(r);

                        // connect to the last row
                        if let Some(neighbor) = last_row[j] {
                            net.add_link(neighbor, r)?;
                            net.set_link_weight(r, neighbor, 1.0)?;
                            net.set_link_weight(neighbor, r, 1.0)?;
                        }
                        last_row[j] = Some(r);
                    }
                }
            }
            Self::TopologyZoo(topo) => {
                net = topo.build(BasicEventQueue::new());
                net.build_link_weights(constant_link_weight, 1.0)?;
            }
        }

        for (r, as_id) in static_inputs
            .external_routers()
            .into_iter()
            .chain(event.external_routers())
            .unique()
        {
            let name = r.as_ref();
            // check if the external router already exists
            if let Ok(id) = net.get_router_id(name) {
                // make sure that it is an external router
                let Ok(NetworkDeviceRef::ExternalRouter(r)) = net.get_device(id) else {
                    // the router is an internal router
                    let msg = format!("The router {name} is an internal router!");
                    log::error!("{msg}");
                    Err(msg)?
                };

                // check the AS ID
                if r.as_id() == as_id {
                    log::debug!("The external router {name} already exists.");
                    continue;
                } else {
                    // the router is an internal router
                    let msg = format!(
                        "The AS ID of external router {name} already exists with AS-ID {} (but it should be {as_id})",
                        r.as_id()
                    );
                    log::error!("{msg}");
                    Err(msg)?
                }
            }

            // router does not exist yet.

            // Get the internal router by removing the suffix _ext.
            let Some(internal_name) = name.strip_suffix("_ext") else {
                let msg =
                    format!("Can only create external routers that end with `_ext`. Got {name}");
                log::error!("{msg}");
                Err(msg)?
            };

            // get the router ID of the internal router
            let Ok(internal_router) = net.get_router_id(internal_name) else {
                let msg = format!(
                    "The internal router of {name} (i.e., {internal_name}) does not exist!"
                );
                log::error!("{msg}");
                Err(msg)?
            };

            // add the external router
            let external_router = net.add_external_router(name, as_id);

            // add the connecting link
            net.add_link(internal_router, external_router).unwrap();
            net.set_bgp_session(internal_router, external_router, Some(BgpSessionType::EBgp))
                .unwrap();
        }

        Ok(net)
    }
}

impl<'a, 'n, Q, Ospf: OspfImpl> bgpsim::formatter::NetworkFormatter<'a, 'n, P, Q, Ospf>
    for Topology
{
    type Formatter = String;

    fn fmt(&'a self, _net: &'n Network<P, Q, Ospf>) -> Self::Formatter {
        self.fmt()
    }
}

/// Speed of light in a fiber cable is ~2/3 of the speed of light
/// https://en.wikipedia.org/wiki/Fiber-optic_cable#Propagation_speed_and_delay
const SPEED_OF_LIGHT: f64 = 0.66 * 299_792_458.0;

/// Description of the link delays in the network
#[derive(Debug, Clone)]
pub struct LinkDelayBuilder<R> {
    default: Option<f64>,
    exceptions: HashMap<(R, R), f64>,
    speed_of_light: f64,
}

impl<R: Default> Default for LinkDelayBuilder<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> LinkDelayBuilder<R> {
    pub fn new() -> Self {
        Self {
            default: None,
            exceptions: Default::default(),
            speed_of_light: SPEED_OF_LIGHT,
        }
    }

    /// Sets the default delay (in microseconds). If not set, then the delay will be zero.
    ///
    /// For networks from topology zoo, setting the default delay will overwrite any existing delay.
    /// If the default delay is not set, then the delay is read from topology zoo.
    pub fn default_delay(mut self, default_delay: f64) -> Self {
        self.default = Some(default_delay);
        self
    }

    /// Sets the speed of light in optical cables. This is only relevant for the topology zoo. By
    /// default, it is set to 2/3 the speed of light in a vacuum.
    pub fn speed_of_light(mut self, speed_of_light: f64) -> Self {
        self.speed_of_light = speed_of_light;
        self
    }
}

impl<R> LinkDelayBuilder<R>
where
    R: Eq + std::hash::Hash,
{
    /// Add an overwrite rule to the link delays (in seconds)
    pub fn overwrite(mut self, a: R, b: R, delay: f64) -> Self {
        let key = (a, b);
        self.exceptions.insert(key, delay);
        self
    }
}

impl<R> LinkDelayBuilder<R>
where
    R: AsRef<str>,
{
    pub fn build<Q>(self, net: &Network<P, Q>) -> Result<LinkDelayBuilder<RouterId>, NetworkError> {
        Ok(LinkDelayBuilder {
            default: self.default,
            exceptions: self
                .exceptions
                .into_iter()
                .map(|((a, b), d)| {
                    let ra = net.get_router_id(a)?;
                    let rb = net.get_router_id(b)?;
                    let key = (ra, rb);
                    Ok((key, d))
                })
                .collect::<Result<_, NetworkError>>()?,
            speed_of_light: self.speed_of_light,
        })
    }
}

impl LinkDelayBuilder<RouterId> {
    /// Generate link delays (in microseconds) for the analyzer
    pub fn generate_delays<Q>(
        &self,
        net: &Network<P, Q>,
        topo: &Topology,
    ) -> HashMap<(RouterId, RouterId), f64> {
        let topology_zoo_geo = if let Topology::TopologyZoo(topo) = topo {
            let mut geo = topo.geo_location();
            geo.retain(|_, v| v.latitude() != 0f64 || v.longitude() != 0f64);

            let center_point = Location::center(&geo.values().collect_vec());
            for r in net.internal_routers() {
                geo.entry(r.router_id()).or_insert(center_point);
            }

            Some(geo)
        } else {
            None
        };

        let mut delays = HashMap::new();

        let g = net.get_topology();
        for e in g.edge_indices() {
            let (a, b) = g.edge_endpoints(e).unwrap();

            // skip all external links
            if !(net.get_device(a).unwrap().is_internal()
                && net.get_device(b).unwrap().is_internal())
            {
                continue;
            }

            // get the default delay
            let default_delay = if self.default.is_some() {
                self.default
            } else if let Some(geo) = topology_zoo_geo.as_ref() {
                let a_loc = geo.get(&a).unwrap();
                let b_loc = geo.get(&b).unwrap();
                let distance = a_loc
                    .distance_to(b_loc)
                    .unwrap_or_else(|_| a_loc.haversine_distance_to(b_loc))
                    .meters();
                let delay = distance / self.speed_of_light * 1_000_000.0;
                Some(delay)
            } else {
                None
            };

            // check if there is an exception (and also check if there is one in the other direction)
            let delay = self
                .exceptions
                .get(&(a, b))
                .or(self.exceptions.get(&(b, a)))
                .or(default_delay.as_ref())
                .copied();

            // if the delay is still None, then don't change anything. Otherwise, set the delay
            if let Some(delay) = delay {
                delays.insert((a, b), delay);
            }
        }

        delays
    }
}
