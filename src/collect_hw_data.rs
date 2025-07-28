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

use clap::Parser;
use tokio::process::Command;

use trix::{experiments::*, util};
use trix_utils::other::send_slack_notification;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Overwrite the input path for data.
    #[arg(short, long, default_value = "./data/")]
    data_root: String,
    /// Overwrite the topology filter for extracting BGP updates.
    #[arg(short, long, default_value = "Abilene")]
    topo: String,
    /// Overwrite the scenario filter for extracting BGP updates.
    #[arg(short, long, default_value = "")]
    scenario: String,
    /// Inverse filter to forbid certain patterns in the scenario string. Can be applied multiple
    /// times.
    #[arg(short = 'v', long)]
    scenario_invert: Vec<String>,
    /// Overwrite the scenario_end filter for extracting BGP updates.
    #[arg(short = 'e', long = "scenario-end", default_value = "")]
    scenario_end: String,
    /// Select the number of samples run.
    #[arg(short, long, default_value_t = 1)]
    num_samples: usize,
    /// Select the number of samples run.
    #[arg(long, default_value_t = 10)]
    num_probes: usize,
    /// Select the number of samples run.
    #[arg(short, long, default_value_t = 1000)]
    prober_frequency: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    util::init_logging();
    util::set_conf_dir()?;

    let args = Args::parse();
    let filter = Filter {
        topo: args.topo,
        scenario: args.scenario,
        scenario_end: args.scenario_end,
        sample_id: "".to_string(),
    };

    // get all scenario names from the filtered topologies
    for (
        ExperimentDescription {
            topo: _,
            topo_name,
            scenario_name,
            config: _,
            delays: _,
            static_routing_inputs: _,
            event: _,
        },
        mut analyzer,
    ) in iterate_experiments(filter)
    {
        if args
            .scenario_invert
            .iter()
            .any(|avoided_str| scenario_name.contains(avoided_str))
        {
            continue;
        }
        // get the correct output folder name
        let mut data_path = PathBuf::from(&args.data_root);
        data_path.push(&topo_name);
        data_path.push(&scenario_name);
        std::fs::create_dir_all(&data_path)?;

        // attempt to clean up better before loading new topology / scenario
        log::debug!("cleanup exabgp...");
        log::trace!(
            "{:?}",
            Command::new("ssh")
                .args(["moonshine", "./cleanup_exabgp.sh"])
                .output()
                .await?
        );
        log::debug!("done.");

        log::debug!("cleanup tofino...");
        log::trace!(
            "{:?}",
            Command::new("ssh")
                .args(["lab-tofino", "./roschmi/ports_setup.sh"])
                .output()
                .await?
        );
        log::debug!("done.");

        // run cisco_analyzer, trying to auto-fix upon an error, otherwise proceed to next
        while let Err(e) = {
            log::info!("Running topology {topo_name} with scenario {scenario_name}...",);
            analyzer
                .analyze_router_lab(
                    args.num_samples,
                    args.num_probes,
                    args.prober_frequency,
                    &data_path,
                )
                .await
        } {
            let error_message = format!("{e:?}");

            // attempt to clean up if a run-time error caused the lock not to be
            // released properly; make sure to only do it for your user!
            if error_message.contains("CannotObtainLock") && error_message.contains("roschmi") {
                let _ = Command::new("ssh")
                    .args(["moonshine", "rm /tmp/router-lab.lock"])
                    .output()
                    .await?;
                log::debug!("unlocking!");
            } else if error_message.contains("WrongSupervisorStatus(")
                || error_message.contains("CannotParseShowModule(Error(")
            {
                send_slack_notification(format!(
                    "Error {error_message} should not happen with the new hardware!"
                ));
                panic!("this should not happen with the new hardware!");

                /*
                log::debug!("reloading router...");

                // send slack notification
                send_slack_notification(&format!(
                    "Rebooting router due to {error_message}"
                ));

                // reload router accordingly
                if error_message.contains("lab-router1") {
                    let _ = Command::new("ssh").args(["lab-router1", "reload"]).output().await?;
                } else if error_message.contains("lab-router2") {
                    let _ = Command::new("ssh").args(["lab-router2", "reload"]).output().await?;
                } else if error_message.contains("lab-router3") {
                    let _ = Command::new("ssh").args(["lab-router3", "reload"]).output().await?;
                }

                log::debug!("(waiting for 10 minutes until VDCs are created)");

                // send slack notification
                send_slack_notification(&format!("Waiting for recovery..."));

                // wait for 10 minutes
                tokio::time::sleep(Duration::from_secs(10 * 60)).await;

                // send slack notification
                send_slack_notification(&format!("Done."));
                */
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
                //
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
                send_slack_notification(format!(
                            "Routing Testbed Unknown Error at {topo_name} / {scenario_name}:\n{error_message}",
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
    }
    Ok(())
}
