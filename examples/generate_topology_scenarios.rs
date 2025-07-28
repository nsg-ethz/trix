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
use trix::experiments::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    //let prefixes = ScenarioPrefix::MultiPrefix(3).prefixes();
    let prefixes = ScenarioPrefix::SinglePrefix.prefixes();
    let _first_prefix = prefixes[0];

    todo!("fix expected parameters");
    /*
    for (topo_name, mut net, geo_locations, _delays, e1, e2, e1_aspath, e2_aspath) in
        list_custom_topologies(&prefixes).into_iter()
    {
        // advertise other prefixes
        for &prefix in prefixes.iter() {
            if prefix != first_prefix {
                net.advertise_external_route(e1, prefix, &e1_aspath, None, [])
                    .unwrap();
                net.advertise_external_route(e2, prefix, &e2_aspath, None, [])
                    .unwrap();
            }
        }

        // create timing_model from geo_locations and swap out the network's queue
        //let timing_model = EmpiricalTimingModel::<P>::new(&geo_locations);
        //let net = net.swap_queue(timing_model).unwrap();

        for scenario in list_scenarios().iter() {
            // generate experiment and write it to file
            {
                // get the correct folder name
                let root = "./experiments_custom_topologies/";
                let mut path = PathBuf::from(root);
                path.push(format!("{}", topo_name));
                path.push(format!("{}", scenario.name()));
                std::fs::create_dir_all(&path)?;
                path.push("scenario.json");

                if !path.exists() || !try_deserialize(&path) {
                    log::info!("Generating topology: {path:?}");

                    let experiment;
                    if let Some(geo_location) = &geo_locations {
                        experiment = scenario.build_from(&net, &geo_location)?;
                    } else {
                        unimplemented!("generating only topologies with geo_locations thus far!");
                    }

                    // serialize experiment and write it to file
                    let _ = serialize_to_file(&path, &experiment)?;
                } else {
                    log::trace!("Topology {topo_name} already exists!");
                }
            }
        }
    }

    Ok(())
    */
}
