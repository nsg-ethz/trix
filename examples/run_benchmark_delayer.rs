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
use std::{fs, path::PathBuf, process::Command, time::Duration};

use trix::experiments::*;
use trix_utils::other::send_slack_notification;

#[cfg(feature = "router_lab")]
mod generate_experiments;
#[cfg(feature = "router_lab")]
use generate_experiments::set_conf_dir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    #[cfg(feature = "router_lab")]
    set_conf_dir()?;

    for k in 2..=12 {
        // manually select a topo & scenario for benchmarking
        let filter_topo = &format!("Path_{k}");
        let scenario = "ExtAtEnds_FullMesh_Prefix1_WithdrawPrefix0AtR0_Delay10000";

        // keep constant prober_frequency of 100k and distribute over nodes
        let capture_frequency = 100_000 / k;

        let topos = fs::read_dir("./experiments/").unwrap();
        for topo_dir in topos {
            let topo_path = topo_dir.unwrap().path();
            if !topo_path.to_string_lossy().contains(filter_topo) {
                continue;
            }

            let mut scenario_path = topo_path.clone();
            scenario_path.push(scenario);
            scenario_path.push("scenario.json");

            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                continue;
            }

            let mut analyzer = deserialize_from_file(&scenario_path)?;
            if analyzer.num_routers() > 12 {
                log::trace!(
                    "Skipping scenario from {scenario_path:?} as it won't fit on our hardware."
                );
                continue;
            }

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = scenario_path.parent().unwrap().file_name().unwrap();

            // get the correct output folder name
            let data_root = "./benchmark/";
            let mut data_path = PathBuf::from(data_root);
            data_path.push(format!("{}", topo_name.to_string_lossy()));
            data_path.push(format!("{}", scenario_name.to_string_lossy()));
            std::fs::create_dir_all(&data_path)?;

            // run cisco_analyzer, trying to auto-fix upon an error, otherwise proceed to next
            while let Err(e) = {
                log::debug!(
                    "Running topology {} with scenario {scenario_name:?}...",
                    topo_name.to_string_lossy()
                );
                analyzer
                    .analyze_router_lab(100, 5, capture_frequency, &data_path)
                    .await
            } {
                let error_message = format!("{e:?}");

                // attempt to clean up if a run-time error caused the lock not to be
                // released properly; make sure to only do it for your user!
                if error_message.contains("CannotObtainLock") && error_message.contains("roschmi") {
                    let _ = Command::new("ssh")
                        .args(["moonshine", "rm /tmp/router-lab.lock"])
                        .output();
                    log::debug!("unlocking!");
                } else if error_message.contains("WrongSupervisorStatus(")
                    || error_message.contains("CannotParseShowModule(Error(")
                {
                    log::debug!("reloading router...");

                    // send slack notification
                    send_slack_notification(&format!("Rebooting router due to {error_message}"));

                    // reload router accordingly
                    if error_message.contains("lab-router1") {
                        let _ = Command::new("ssh").args(["lab-router1", "reload"]).output();
                    } else if error_message.contains("lab-router2") {
                        let _ = Command::new("ssh").args(["lab-router2", "reload"]).output();
                    } else if error_message.contains("lab-router3") {
                        let _ = Command::new("ssh").args(["lab-router3", "reload"]).output();
                    }

                    log::debug!("(waiting for 10 minutes until VDCs are created)");

                    // send slack notification
                    send_slack_notification("Waiting for recovery...");

                    // wait for 10 minutes
                    tokio::time::sleep(Duration::from_secs(10 * 60)).await;

                    // send slack notification
                    send_slack_notification("Done.");
                } else if error_message.contains("Ssh(Timeout)")
                    || error_message.contains("CiscoShell(UnexpectedStdout(")
                {
                    // Recoverable Errors
                    log::error!("Recoverable error detected: {error_message}.");
                } else if error_message.contains("CiscoShell(Synchronization)")
                    || error_message.contains("CommandError(")
                    || error_message.contains("Export(NotEnoughInterfaces(")
                {
                    // Unrecoverable Errors
                    log::error!("Unrecoverable error detected: {error_message}.");

                    // send slack notification
                    /*
                    send_slack_notification(&format!(
                        "Routing Testbed Unrecoverable Error at {} / {}:\n{error_message}",
                        topo_name.to_string_lossy(),
                        scenario_name.to_string_lossy(),
                    ));
                    */

                    break;
                } else {
                    log::error!("Unknown error: {error_message}");

                    // send slack notification
                    send_slack_notification(&format!(
                        "Routing Testbed Unknown Error at {} / {}:\n{error_message}",
                        topo_name.to_string_lossy(),
                        scenario_name.to_string_lossy(),
                    ));

                    /*
                    // wait for interactive resolution of the unknown error
                    println!("Please press [ENTER] to continue, or type 'retry' to try this scenario again:");

                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;

                    // allows to skip trying the current scenario again
                    if !input.contains("retry") {
                        break;
                    }
                    */
                    break;
                }
                log::debug!("Trying to run the same scenario again ...");
            }

            // attempt to clean up better before loading new topology / scenario
            let _ = Command::new("ssh")
                .args(["moonshine", "killall exabgp"])
                .output();

            let _ = Command::new("ssh")
            .args(["lab-tofino", "bash -c \"source /data/set_sde_9.8.0.sh; /home/nsg/bf-sde-9.8.0/run_bfshell.sh -f /home/nsg/roschmi/ports_setup.cmd\""])
            .output();
        }
    }

    send_slack_notification("Completed a full run. Looping!");

    Ok(())
}
