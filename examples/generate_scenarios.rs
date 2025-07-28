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

use trix::experiments::*;
use bgpsim::{prelude::*, topology_zoo::TopologyZoo};

use itertools::Itertools;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    // get a selected list of topologies from `TopologyZoo`, uncomment the `.filter()` below to select only specific topologies
    let topos = TopologyZoo::topologies_increasing_nodes()
        .iter()
        //.filter(|t| t.num_internals() <= 11)
        .copied()
        .collect_vec();

    // go through all combinations of topologies and scenarios and build
    for topo in topos {
        // create network and get locations from the `TopologyZoo` topology
        let net = topo.build(BasicEventQueue::new());
        let geo_location = topo.geo_location();

        for scenario in list_scenarios().iter() {
            // generate experiment and write it to file
            {
                // get the correct folder name
                let root = "./experiments_scenario_builder/";
                let mut path = PathBuf::from(root);
                path.push(format!("{:?}", topo));
                path.push(scenario.name());
                std::fs::create_dir_all(&path)?;
                path.push("scenario.json");

                if !path.exists() || !try_deserialize(&path) {
                    log::info!("Generating scenario: {path:?}");
                    let experiment = scenario.build_from(&net, &geo_location)?;

                    // serialize experiment and write it to file
                    serialize_to_file(&path, &experiment)?;
                } else {
                    log::trace!("Skip: {path:?}");
                }

                /*
                //use time::{format_description, OffsetDateTime};
                // add current execution timestamp
                let cur_time = OffsetDateTime::now_local()
                    .unwrap_or_else(|_| OffsetDateTime::now_utc())
                    .format(
                        &format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]")
                            .unwrap(),
                    )
                    .unwrap();
                let mut execution_slug = format!("route_intervals_{cur_time}");
                path.push(format!("{execution_slug}.csv"));
                // avoid duplicates
                let mut idx = None;
                while path.exists() {
                    let i = idx.unwrap_or(0) + 1;
                    idx = Some(i);
                    path.pop();
                    execution_slug = format!("route_intervals_{cur_time}_{i}.csv", name.as_ref());
                    path.push(format!("{execution_slug}.csv"));
                }

                path.push(format!("{}---{}.csv", src.fmt(net), ext.fmt(net)));
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&path)?;
                file.write_all(b"send_time,recv_time,sequence_num\n")?;
                file.write_all(
                    data.entry(ext)
                        .or_insert_with(Vec::new)
                        .iter()
                        .map(|(t, sn)| format!("{t},{t},{sn}"))
                        .join("\n")
                        .as_bytes(),
                )?;
                path.pop();
                */
            }
        }
    }

    /*
    let nt = net.as_json_str();
    println!("Network: {}", nt);
    println!();
    let tm = serde_json::to_string(&timing_model)?;
    println!("Locations: {}", tm);

    drop(net);
    drop(timing_model);

    let timing_model: EmpiricalTimingModel<_> = serde_json::from_str(&tm)?;
    let net: Network<SimplePrefix, BasicEventQueue<SimplePrefix>> =
        Network::from_json_str(&nt, Default::default)?;

    let mut net = net.swap_queue(timing_model).unwrap();
    net.advertise_external_route(e2, first_prefix, &e2_aspath, None, [])
        .unwrap();

        */
    Ok(())
}
