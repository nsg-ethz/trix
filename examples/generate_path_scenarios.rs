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
use std::path::PathBuf;

use trix::{experiments::*, prelude::*};
use bgpsim::prelude::Prefix;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    //let prefixes = ScenarioPrefix::SinglePrefix.prefixes();
    let prefixes = ScenarioPrefix::MultiPrefix(10).prefixes();

    for (topo_name, mut net, geo_locations, delays, external_routers) in
        list_custom_topologies(&prefixes).into_iter()
    {
        // advertise other prefixes
        for &prefix in prefixes.iter() {
            if prefix != prefixes[0] {
                for (ext, ext_aspath) in external_routers.iter() {
                    net.advertise_external_route(
                        *ext,
                        prefix,
                        ext_aspath,
                        None,
                        vec![prefix.as_num()],
                    )
                    .unwrap();
                }
            }
        }

        // create queue from geo_locations or delays and swap out the network's queue
        let queue;
        if let Some(geo_location) = &geo_locations {
            queue = TimingModel::from_geo_location(geo_location);
        } else if let Some(delays) = &delays {
            queue = TimingModel::from_delays(delays);
        } else {
            unreachable!(
                "EmpiricalTimingModel cannot be initialized without geo_location and delays!"
            );
        }

        // generate experiment and write it to file
        for (scenario_name, event) in
            list_path_scenarios(&net, &prefixes, &external_routers).into_iter()
        {
            if !scenario_name.contains("LinkFailure")
                || !topo_name.contains("ExtAtEnds_")
                || !topo_name.contains("Path03")
            {
                continue;
            }
            // get the correct folder name
            let root = "./experiments/";
            let mut path = PathBuf::from(root);
            if prefixes.len() > 1 {
                path.push(format!("{}_{}prefixes", topo_name, prefixes.len()));
            } else {
                path.push(topo_name);
            }
            path.push(scenario_name);
            std::fs::create_dir_all(&path)?;
            path.push("scenario.json");

            let net = net.clone().swap_queue(queue.clone()).unwrap();

            if !path.exists() || !try_deserialize(&path) {
                log::info!("Generating topology: {path:?}");
                let mut experiment = Analyzer::new(net, event, vec![], 0.95, 0.01)?;
                if let Some(geo_location) = &geo_locations {
                    experiment.set_geo_location(geo_location.clone());
                } else if let Some(delays) = &delays {
                    experiment.set_delays(delays.clone());
                } else {
                    unreachable!("EmpiricalTimingModel cannot be initialized without geo_location and delays!");
                }

                // serialize experiment and write it to file
                serialize_to_file(&path, &experiment)?;
            } else {
                log::trace!("{topo_name}/{scenario_name} already exists!");
            }
        }
    }

    Ok(())
}
