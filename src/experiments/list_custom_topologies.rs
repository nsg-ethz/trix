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
use std::collections::HashMap;

use geoutils::Location;

use bgpsim::prelude::*;

use crate::Prefix as P;

pub type TopologyDescription = (
    &'static str,                               // topo_name
    Network<P>,                                 // net
    Option<HashMap<RouterId, Location>>,        // geo_locations
    Option<HashMap<(RouterId, RouterId), f64>>, // external_routers
    Vec<(RouterId, Vec<AsId>)>,                 // as_paths
);

/// List of custom topologies that are being explored for transient behavior under BGP updates.
///
/// Returns a fixed-size array where each entry is a tuple containing:
/// - a topology_name
/// - a `Network`
/// - the geographic locations of the routers
/// - two `RouterId`s of the external routers
/// - two `Vec<AsId>`s containing the respective AS paths
pub fn list_custom_topologies(prefixes: &[P]) -> [TopologyDescription; 128] {
    // introduce shared variables
    let first_prefix = prefixes[0];
    let e1_aspath: Vec<AsId> = vec![100.into(), 1000.into()];
    let e2_aspath: Vec<AsId> = vec![200.into(), 200.into(), 1000.into()];
    let e3_aspath: Vec<AsId> = vec![300.into(), 300.into(), 300.into(), 1000.into()];

    // define your custom topologies here
    [
        {
            let topo_name = "Path01";
            let (net, (r0, e1, e2)) = net! {
                Prefix = P;
                links = {
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r0;
                    // iBGP full mesh
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (e2, Location::new(0.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path02_FullMesh";
            let (net, (r0, r1, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (e2, Location::new(10.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e2, Location::new(20.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e2, Location::new(30.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e2, Location::new(40.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e2, Location::new(50.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (e2, Location::new(60.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (e2, Location::new(70.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (e2, Location::new(80.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (e2, Location::new(90.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (r10, Location::new(100.0, 0.0)),
                (e2, Location::new(100.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEnds";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (r10, Location::new(100.0, 0.0)),
                (r11, Location::new(110.0, 0.0)),
                (e2, Location::new(110.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    e3!(300) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (e3, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e2, Location::new(20.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e3, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e2, Location::new(30.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e3, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e2, Location::new(40.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e2, Location::new(50.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (e2, Location::new(60.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e3, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (e2, Location::new(70.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e3, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (e2, Location::new(80.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e3, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (e2, Location::new(90.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e3, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (r10, Location::new(100.0, 0.0)),
                (e2, Location::new(100.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEndsAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    e3!(300) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (e1, Location::new(0.0, 0.0)),
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (e3, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (r10, Location::new(100.0, 0.0)),
                (r11, Location::new(110.0, 0.0)),
                (e2, Location::new(110.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r1;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (e1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e2, Location::new(20.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e1, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e2, Location::new(30.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (e1, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e2, Location::new(40.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e1, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e2, Location::new(50.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (e1, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (e2, Location::new(60.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e1, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (e2, Location::new(70.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (e1, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (e2, Location::new(80.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e1, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (e2, Location::new(90.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (e1, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (r10, Location::new(100.0, 0.0)),
                (e2, Location::new(100.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtFrontAndCenter";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r6;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // describe geo_locations as tuples of `(Latitude, Longitude)`
            let geo_locations = HashMap::from([
                (r0, Location::new(0.0, 0.0)),
                (r1, Location::new(10.0, 0.0)),
                (r2, Location::new(20.0, 0.0)),
                (r3, Location::new(30.0, 0.0)),
                (r4, Location::new(40.0, 0.0)),
                (r5, Location::new(50.0, 0.0)),
                (r6, Location::new(60.0, 0.0)),
                (e1, Location::new(60.0, 0.0)),
                (r7, Location::new(70.0, 0.0)),
                (r8, Location::new(80.0, 0.0)),
                (r9, Location::new(90.0, 0.0)),
                (r10, Location::new(100.0, 0.0)),
                (r11, Location::new(110.0, 0.0)),
                (e2, Location::new(110.0, 0.0)),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                Some(geo_locations),
                None,
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path01_3ms";
            let (net, (r0, e1, e2)) = net! {
                Prefix = P;
                links = {
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r0;
                    // iBGP full mesh
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([((e1, r0), 0.0), ((e2, r0), 0.0)]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path02_FullMesh_3ms";
            let (net, (r0, r1, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays =
                HashMap::from([((e1, r0), 0.0), ((r0, r1), 3_000.0), ((e2, r1), 0.0)]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((r9, r10), 3_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEnds_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((r9, r10), 3_000.0),
                ((r10, r11), 3_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    e3!(300) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((e3, r1), 0.0),
                ((r1, r2), 3_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((e3, r2), 0.0),
                ((r2, r3), 3_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((e3, r2), 0.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((e3, r3), 0.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((e3, r3), 0.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e3, r4), 0.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e3, r4), 0.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e3, r5), 0.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e3, r5), 0.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((r9, r10), 3_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEndsAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    e3!(300) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((e3, r6), 0.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((r9, r10), 3_000.0),
                ((r10, r11), 3_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r1;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((e1, r1), 0.0),
                ((r1, r2), 3_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((e1, r2), 0.0),
                ((r2, r3), 3_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((e1, r2), 0.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((e1, r3), 0.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((e1, r3), 0.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e1, r4), 0.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((e1, r4), 0.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e1, r5), 0.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((e1, r5), 0.0),
                ((r5, r6), 3_000.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((r9, r10), 3_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtFrontAndCenter_3ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r6;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // set all link delays to 3ms
            let link_delays = HashMap::from([
                ((r0, r1), 3_000.0),
                ((r1, r2), 3_000.0),
                ((r2, r3), 3_000.0),
                ((r3, r4), 3_000.0),
                ((r4, r5), 3_000.0),
                ((r5, r6), 3_000.0),
                ((e1, r6), 0.0),
                ((r6, r7), 3_000.0),
                ((r7, r8), 3_000.0),
                ((r8, r9), 3_000.0),
                ((r9, r10), 3_000.0),
                ((r10, r11), 3_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path01_5ms";
            let (net, (r0, e1, e2)) = net! {
                Prefix = P;
                links = {
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r0;
                    // iBGP full mesh
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([((e1, r0), 0.0), ((e2, r0), 0.0)]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path02_FullMesh_5ms";
            let (net, (r0, r1, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays =
                HashMap::from([((e1, r0), 0.0), ((r0, r1), 5_000.0), ((e2, r1), 0.0)]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((r9, r10), 5_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEnds_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((r9, r10), 5_000.0),
                ((r10, r11), 5_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    e3!(300) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((e3, r1), 0.0),
                ((r1, r2), 5_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((e3, r2), 0.0),
                ((r2, r3), 5_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((e3, r2), 0.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((e3, r3), 0.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((e3, r3), 0.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e3, r4), 0.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e3, r4), 0.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e3, r5), 0.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e3, r5), 0.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((r9, r10), 5_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEndsAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    e3!(300) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((e3, r6), 0.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((r9, r10), 5_000.0),
                ((r10, r11), 5_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r1;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((e1, r1), 0.0),
                ((r1, r2), 5_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((e1, r2), 0.0),
                ((r2, r3), 5_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((e1, r2), 0.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((e1, r3), 0.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((e1, r3), 0.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e1, r4), 0.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((e1, r4), 0.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e1, r5), 0.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((e1, r5), 0.0),
                ((r5, r6), 5_000.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((r9, r10), 5_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtFrontAndCenter_5ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r6;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // set all link delays to 5ms
            let link_delays = HashMap::from([
                ((r0, r1), 5_000.0),
                ((r1, r2), 5_000.0),
                ((r2, r3), 5_000.0),
                ((r3, r4), 5_000.0),
                ((r4, r5), 5_000.0),
                ((r5, r6), 5_000.0),
                ((e1, r6), 0.0),
                ((r6, r7), 5_000.0),
                ((r7, r8), 5_000.0),
                ((r8, r9), 5_000.0),
                ((r9, r10), 5_000.0),
                ((r10, r11), 5_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path01_10ms";
            let (net, (r0, e1, e2)) = net! {
                Prefix = P;
                links = {
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r0;
                    // iBGP full mesh
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([((e1, r0), 0.0), ((e2, r0), 0.0)]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path02_FullMesh_10ms";
            let (net, (r0, r1, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays =
                HashMap::from([((e1, r0), 0.0), ((r0, r1), 10_000.0), ((e2, r1), 0.0)]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((r9, r10), 10_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEnds_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((r9, r10), 10_000.0),
                ((r10, r11), 10_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r2;
                    e3!(300) -> r1;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((e3, r1), 0.0),
                ((r1, r2), 10_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r3;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((e3, r2), 0.0),
                ((r2, r3), 10_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r4;
                    e3!(300) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((e3, r2), 0.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r5;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((e3, r3), 0.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r6;
                    e3!(300) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((e3, r3), 0.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r7;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e3, r4), 0.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r8;
                    e3!(300) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e3, r4), 0.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r9;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e3, r5), 0.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r10;
                    e3!(300) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e3, r5), 0.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((r9, r10), 10_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtAtEndsAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r0;
                    e2!(200) -> r11;
                    e3!(300) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                    e3 -> first_prefix as {path: &e3_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2, e3)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((e1, r0), 0.0),
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((e3, r6), 0.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((r9, r10), 10_000.0),
                ((r10, r11), 10_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![
                    (e1, e1_aspath.clone()),
                    (e2, e2_aspath.clone()),
                    (e3, e3_aspath.clone()),
                ],
            )
        },
        {
            let topo_name = "Path03_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r1;
                    e2!(200) -> r2;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r1 -> r2: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((e1, r1), 0.0),
                ((r1, r2), 10_000.0),
                ((e2, r2), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path04_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r3;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r2 -> r3: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((e1, r2), 0.0),
                ((r2, r3), 10_000.0),
                ((e2, r3), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path05_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r2;
                    e2!(200) -> r4;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r3 -> r4: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((e1, r2), 0.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e2, r4), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path06_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r5;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r4 -> r5: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((e1, r3), 0.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e2, r5), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path07_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r3;
                    e2!(200) -> r6;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r5 -> r6: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((e1, r3), 0.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((e2, r6), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path08_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r7;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r6 -> r7: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e1, r4), 0.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((e2, r7), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path09_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r4;
                    e2!(200) -> r8;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r7 -> r8: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((e1, r4), 0.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((e2, r8), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path10_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r9;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r8 -> r9: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e1, r5), 0.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((e2, r9), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path11_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r5;
                    e2!(200) -> r10;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r9 -> r10: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((e1, r5), 0.0),
                ((r5, r6), 10_000.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((r9, r10), 10_000.0),
                ((e2, r10), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
        {
            let topo_name = "Path12_FullMesh_ExtFrontAndCenter_10ms";
            let (net, (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)) = net! {
                Prefix = P;
                links = {
                    r0 -> r1: 1;
                    r1 -> r2: 1;
                    r2 -> r3: 1;
                    r3 -> r4: 1;
                    r4 -> r5: 1;
                    r5 -> r6: 1;
                    r6 -> r7: 1;
                    r7 -> r8: 1;
                    r8 -> r9: 1;
                    r9 -> r10: 1;
                    r10 -> r11: 1;
                };
                sessions = {
                    // external routers
                    e1!(100) -> r6;
                    e2!(200) -> r11;
                    // iBGP full mesh
                    r0 -> r1: peer;
                    r0 -> r2: peer;
                    r0 -> r3: peer;
                    r0 -> r4: peer;
                    r0 -> r5: peer;
                    r0 -> r6: peer;
                    r0 -> r7: peer;
                    r0 -> r8: peer;
                    r0 -> r9: peer;
                    r0 -> r10: peer;
                    r0 -> r11: peer;
                    r1 -> r2: peer;
                    r1 -> r3: peer;
                    r1 -> r4: peer;
                    r1 -> r5: peer;
                    r1 -> r6: peer;
                    r1 -> r7: peer;
                    r1 -> r8: peer;
                    r1 -> r9: peer;
                    r1 -> r10: peer;
                    r1 -> r11: peer;
                    r2 -> r3: peer;
                    r2 -> r4: peer;
                    r2 -> r5: peer;
                    r2 -> r6: peer;
                    r2 -> r7: peer;
                    r2 -> r8: peer;
                    r2 -> r9: peer;
                    r2 -> r10: peer;
                    r2 -> r11: peer;
                    r3 -> r4: peer;
                    r3 -> r5: peer;
                    r3 -> r6: peer;
                    r3 -> r7: peer;
                    r3 -> r8: peer;
                    r3 -> r9: peer;
                    r3 -> r10: peer;
                    r3 -> r11: peer;
                    r4 -> r5: peer;
                    r4 -> r6: peer;
                    r4 -> r7: peer;
                    r4 -> r8: peer;
                    r4 -> r9: peer;
                    r4 -> r10: peer;
                    r4 -> r11: peer;
                    r5 -> r6: peer;
                    r5 -> r7: peer;
                    r5 -> r8: peer;
                    r5 -> r9: peer;
                    r5 -> r10: peer;
                    r5 -> r11: peer;
                    r6 -> r7: peer;
                    r6 -> r8: peer;
                    r6 -> r9: peer;
                    r6 -> r10: peer;
                    r6 -> r11: peer;
                    r7 -> r8: peer;
                    r7 -> r9: peer;
                    r7 -> r10: peer;
                    r7 -> r11: peer;
                    r8 -> r9: peer;
                    r8 -> r10: peer;
                    r8 -> r11: peer;
                    r9 -> r10: peer;
                    r9 -> r11: peer;
                    r10 -> r11: peer;
                };
                routes = {
                    // create both links and sessions for external routers and advertise first_prefix
                    e1 -> first_prefix as {path: &e1_aspath};
                    e2 -> first_prefix as {path: &e2_aspath};
                };
                return (r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, e1, e2)
            };

            // set all link delays to 10ms
            let link_delays = HashMap::from([
                ((r0, r1), 10_000.0),
                ((r1, r2), 10_000.0),
                ((r2, r3), 10_000.0),
                ((r3, r4), 10_000.0),
                ((r4, r5), 10_000.0),
                ((r5, r6), 10_000.0),
                ((e1, r6), 0.0),
                ((r6, r7), 10_000.0),
                ((r7, r8), 10_000.0),
                ((r8, r9), 10_000.0),
                ((r9, r10), 10_000.0),
                ((r10, r11), 10_000.0),
                ((e2, r11), 0.0),
            ]);

            // return the topology's information
            (
                topo_name,
                net,
                None,
                Some(link_delays),
                vec![(e1, e1_aspath.clone()), (e2, e2_aspath.clone())],
            )
        },
    ]
}
