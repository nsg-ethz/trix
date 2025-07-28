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

use trix::timing_model::TimingModel;
use bgpsim::prelude::*;

use geoutils::Location;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // init
    let prefix = SimplePrefix::from(0);

    #[allow(unused_variables)]
    let (net, (r0, r1, r2, e1, e2)) = net! {
        Prefix = SimplePrefix;
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
            e1 -> prefix as {path: [100, 100, 100, 1000]};
            e2 -> prefix as {path: [200, 200, 1000]};
        };
        return (r0, r1, r2, e1, e2)
    };

    let geo_locations = HashMap::from([
        (e1, Location::new(10.0, 0.0)),
        (r0, Location::new(10.0, 0.0)),
        (r1, Location::new(20.0, 0.0)),
        (r2, Location::new(30.0, 0.0)),
        (e2, Location::new(30.0, 0.0)),
    ]);
    let timing_model = TimingModel::<SimplePrefix>::from_geo_location(&geo_locations);

    // serialize
    let serialized_net = net.as_json_str();
    println!("Network: {}", serialized_net);
    println!();

    let serialized_timing_model = serde_json::to_string(&timing_model)?;
    println!("Locations: {}", serialized_timing_model);
    println!();

    drop(net);
    drop(timing_model);

    // deserialize
    let net: Network<SimplePrefix, BasicEventQueue<SimplePrefix>> =
        Network::from_json_str(&serialized_net, Default::default)?;

    let timing_model: TimingModel<SimplePrefix> = serde_json::from_str(&serialized_timing_model)?;

    let net = net.swap_queue(timing_model).unwrap();

    println!("restored: {net:?}");

    Ok(())
}
