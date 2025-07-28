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
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{self, Display},
    fs,
    path::{Path, PathBuf},
    process,
    time::Duration,
};

use clap::{Parser, ValueEnum};
use itertools::Itertools;
use serde::Serialize;

use trix::{analyzer::CiscoAnalyzerData, experiments::*, util};

mod process_pcaps;

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Overwrite the input path for data.
    #[arg(short, long, default_value = "./data/")]
    data_path: String,
    /// Overwrite the output path for plots.
    #[arg(short, long, default_value = "./plots/")]
    output_path: String,
    /// Type of plot to generate.
    #[arg(short, long, value_enum)]
    plot_type: Plot,
    /// BGP event to consider
    #[arg(short, long, value_enum, default_value_t=Event::Withdraw)]
    event_type: Event,
}

#[derive(ValueEnum, Clone, Debug, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Plot {
    /// Shows the violation times of the default scenario.
    #[default]
    Default,
    /// Shows the prefix with the largest violation times of the largest scenario.
    Motivation,
    /// Shows the impact of increasing (decreasing) the number of prefixes on the violation times
    /// of the default scenario.
    Prefixes,
    /// Shows the impact of increasing (decreasing) the number of iBGP peers on the violation times
    /// of the path scenarios with 10k prefixes.
    Peers,
    /// Shows the impact of having the backup route available or not on the violation times of the
    /// default scenario.
    BackupAvailable,
    /// Shows the impact of having the backup route available or not on the violation times of the
    /// default scenario, comparing the different event types.
    BackupComparison,
    /// Shows the impact of having route reflectors configured, as opposed to a full mesh, on the
    /// violation times of the default scenario.
    RouteReflection,
    /// Shows the impact of having route reflectors configured, as opposed to a full mesh, on the
    /// violation times of the default scenario with only 100 prefixes.
    RouteReflectionDistance,
    /// Shows the impact of the different event types on the violation times of the default scenario.
    Events,
    /// Shows the impact of the distance between the event and the backup route on the default
    /// scenario with 100 prefixes.
    Distance,
    /// Shows boxplots per router for each individual scenario.
    IndividualScenarios,
}

#[derive(ValueEnum, Clone, Debug, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Event {
    /// Produces plots for all events.
    #[default]
    All,
    /// Produces plots only for withdraw events.
    Withdraw,
    /// Produces plots only for withdraw events.
    Announce,
    /// Produces plots only for withdraw events.
    UpdateBetter,
    /// Produces plots only for withdraw events.
    UpdateWorse,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Event::All => write!(f, "All"),
            Event::Withdraw => write!(f, "WithdrawAllPrefixes"),
            Event::Announce => write!(f, "AnnounceAllNewBest"),
            Event::UpdateBetter => write!(f, "UpdateAllBetter"),
            Event::UpdateWorse => write!(f, "UpdateAllWorse"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct RawDataPoint<'a, 'b, 'c, 'd> {
    sample_id: &'a str,
    column_name: &'b str,
    router_name: &'c str,
    prefix: &'d str,
    violation: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    util::init_logging();

    // parse plot parameters
    let args = Args::parse();
    let plot_dir = args.output_path;
    fs::create_dir_all(plot_dir.clone())?;

    // ensure that the data folder exists
    let data_path = PathBuf::from(args.data_path);
    if !data_path.exists() {
        log::error!("Could not read data in {data_path:?}!");
        process::exit(1)
    }

    for event in [
        "WithdrawAllPrefixes",
        "AnnounceAllNewBest",
        "UpdateAllBetter",
        "UpdateAllWorse",
    ]
    .into_iter()
    .filter(|event| event.contains(&format!("{}", args.event_type)))
    {
        match args.plot_type {
            Plot::Default => plot_violations(
                data_path.clone(),
                Filter {
                    topo: "Abilene".to_string(),
                    scenario: "ExtLosAngelesKansasCity_FullMesh_Prefix10000_".to_string(),
                    scenario_end: format!("PhysicalExternal{event}AtLosAngeles"),
                    sample_id: "".to_string(),
                },
                plot_dir.clone(),
            )?,
            Plot::Motivation => plot_k_filters(
                data_path.clone(),
                [
                    (
                        "withdraw10k",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "2024-10-03_19-38-32".to_string(),
                        },
                    ),
                ].to_vec(),
                plot_dir.clone(),
                "motivation",
                false,
            )?,
            /*
            plot_prefixes(
                data_path.clone(),
                Filter {
                    topo: "Abilene".to_string(),
                    scenario: "ExtLosAngelesKansasCity_FullMesh_Prefix1000000_".to_string(),
                    scenario_end: "PhysicalExternalWithdrawAllPrefixesAtLosAngeles".to_string(),
                    sample_id: "2024-10-04_22-27-01".to_string(),
                },
                plot_dir.clone(),
            )?,
            */
            Plot::Prefixes => plot_k_filters(
                data_path.clone(),
                [1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000]
                    .map(|num_prefixes|
                        (
                            format!("{num_prefixes}"),
                            Filter {
                                topo: "Abilene".to_string(),
                                scenario: format!("ExtLosAngelesKansasCity_FullMesh_Prefix{num_prefixes}_"),
                                scenario_end: format!("PhysicalExternal{event}AtLosAngeles"),
                                sample_id: "".to_string(),
                            },
                        )
                    )
                    .to_vec(),
                plot_dir.clone(),
                "prefixes",
                false,
            )?,
            Plot::Peers => {
                for num_prefixes in [10, 100, 10_000] {
                    plot_k_filters(
                        data_path.clone(),
                        (1..=10).map(|num_peers|
                            (
                                format!("{num_peers} peers"),
                                Filter {
                                    topo: format!("Path_{}", num_peers + 1),
                                    scenario: format!("ExtAtEnds_FullMesh_Prefix{num_prefixes}_"),
                                    scenario_end: format!("PhysicalExternal{event}AtR0_Delay0"),
                                    sample_id: "".to_string(),
                                },
                            ))
                            .collect_vec(),
                        plot_dir.clone(),
                        "peers",
                        false,
                    )?;
                }
            }
            Plot::BackupAvailable => plot_k_filters(
                data_path.clone(),
                [
                    (
                        "FM + Backup hidden",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "1RR Seattle + Backup hidden",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "2RR AtlantaSeattle + Backup hidden",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "2RR SeattleNewYork + Backup hidden",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "FM + Backup available",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngelesKeepOther"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "1RR Seattle + Backup available",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix10000_PhysicalExternal{event}AtLosAngelesKeepOther"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "2RR AtlantaSeattle + Backup available",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix10000_PhysicalExternal{event}AtLosAngelesKeepOther"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "2RR SeattleNewYork + Backup available",
                         Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix10000_PhysicalExternal{event}AtLosAngelesKeepOther"),
                            sample_id: "".to_string(),
                        },
                    ),
                ].to_vec(),
                plot_dir.clone(),
                "backup_available",
                false,
            )?,
            Plot::BackupComparison => plot_k_filters(
                data_path.clone(),
                ["AnnounceAllNewBest", "UpdateAllBetter", "UpdateAllWorse", "WithdrawAllPrefixes"]
                    .into_iter()
                    .flat_map(|event|
                        [
                            (
                                format!("Backup hidden {event}"),
                                Filter {
                                    topo: "Abilene".to_string(),
                                    scenario: "".to_string(),
                                    scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                                    sample_id: "".to_string(),
                                },
                            ),
                            (
                                format!("Backup available {event}"),
                                Filter {
                                    topo: "Abilene".to_string(),
                                    scenario: "".to_string(),
                                    scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngelesKeepOther"),
                                    sample_id: "".to_string(),
                                },
                            )
                        ]
                            .into_iter()
                )
                    .collect_vec(),
                plot_dir.clone(),
                "backup_comparison",
                false,
            )?,
            Plot::RouteReflection => plot_k_filters(
                data_path.clone(),
                [
                    (
                        "Full-Mesh",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR Atlanta",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR Seattle",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR NewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR AtlantaSeattle",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR AtlantaNewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR SeattleNewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR AtlantaSeattleNewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                ].to_vec(),
                plot_dir.clone(),
                "route_reflection",
                false,
            )?,
            Plot::RouteReflectionDistance => plot_k_filters(
                data_path.clone(),
                [
                    (
                        "Full-Mesh",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR Atlanta",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlanta_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR Seattle",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattle_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR NewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsNewYork_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR AtlantaSeattle",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaSeattle_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR AtlantaNewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaNewYork_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR SeattleNewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsSeattleNewYork_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "RR AtlantaSeattleNewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_ReflectorsAtlantaSeattleNewYork_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                ].to_vec(),
                plot_dir.clone(),
                "route_reflection_distance",
                false,
            )?,
            Plot::Events => plot_k_filters(
                data_path.clone(),
                [
                    (
                        "Withdraw",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "Announce",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: "ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternalAnnounceAllNewBestAtLosAngeles".to_string(),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "UpdateBetter",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: "ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternalUpdateAllBetterAtLosAngeles".to_string(),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "UpdateWorse",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: "ExtLosAngelesKansasCity_FullMesh_Prefix10000_PhysicalExternalUpdateAllWorseAtLosAngeles".to_string(),
                            sample_id: "".to_string(),
                        },
                    ),
                ].to_vec(),
                plot_dir.clone(),
                "events",
                false,
            )?,
            Plot::Distance => plot_k_filters(
                data_path.clone(),
                [
                    (
                        "Sunnyvale",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesSunnyvale_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "Houston",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesHouston_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "Denver",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesDenver_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "KansasCity",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesKansasCity_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "Indianapolis",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesIndianapolis_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "Chicago",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesChicago_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                    (
                        "NewYork",
                        Filter {
                            topo: "Abilene".to_string(),
                            scenario: "".to_string(),
                            scenario_end: format!("ExtLosAngelesNewYork_FullMesh_Prefix100_PhysicalExternal{event}AtLosAngeles"),
                            sample_id: "".to_string(),
                        },
                    ),
                ].to_vec(),
                plot_dir.clone(),
                "distance",
                false,
            )?,
            Plot::IndividualScenarios => plot_violations(
                data_path.clone(),
                Filter {
                    topo: "".to_string(),
                    scenario: "".to_string(),
                    scenario_end: "".to_string(),
                    sample_id: "".to_string(),
                },
                plot_dir.clone(),
            )?,
        }
    }
    Ok(())
}

/// Creates plots for each scenario matching the filter showing the violation times captured per
/// sample for each probed prefix.
fn plot_violations(
    data_root: impl AsRef<Path> + Sync,
    filter: Filter,
    plot_dir: impl AsRef<Path> + Sync,
) -> Result<(), Box<dyn std::error::Error>> {
    let data_root = data_root.as_ref();

    // get all (topo, scenario) combinations
    util::process_data(data_root, filter, |topo_name, scenario_name, eval_path| {
        // read violation_times from the files
        let mut reachability_violation_file_path = eval_path.to_path_buf();
        reachability_violation_file_path.push("violation_reachability.json");
        if reachability_violation_file_path.exists() {
            let serialized_reachability_violation_times =
                fs::read_to_string(&reachability_violation_file_path).unwrap();
            let reachability_violation_times: Vec<Sample> =
                serde_json::from_str(&serialized_reachability_violation_times).unwrap();

            plot_violation_times(
                topo_name,
                scenario_name,
                "reachability",
                &reachability_violation_times,
                plot_dir.as_ref(),
            );
        }

        /*
        let mut loopfreedom_violation_file_path = eval_path.clone();
        loopfreedom_violation_file_path.push("violation_loopfreedom.json");
        if loopfreedom_violation_file_path.exists() {
            let serialized_loopfreedom_violation_times =
                fs::read_to_string(&loopfreedom_violation_file_path).unwrap();
            let loopfreedom_violation_times: Vec<Sample> =
                serde_json::from_str(&serialized_loopfreedom_violation_times).unwrap();

            plot_violation_times(
                &topo_name,
                &scenario_name,
                "loopfreedom",
                &loopfreedom_violation_times,
                plot_dir.as_ref(),
            );
        }

        let mut stable_path_violation_file_path = eval_path.clone();
        stable_path_violation_file_path.push("violation_stable_path.json");
        if stable_path_violation_file_path.exists() {
            let serialized_stable_path_violation_times =
                fs::read_to_string(&stable_path_violation_file_path).unwrap();
            let stable_path_violation_times: Vec<Sample> =
                serde_json::from_str(&serialized_stable_path_violation_times).unwrap();

            plot_violation_times(
                &topo_name,
                &scenario_name,
                "stable_path",
                &stable_path_violation_times,
                plot_dir.as_ref(),
            );
        }

        let mut glob_path = eval_path.to_string_lossy().to_string();
        glob_path.push_str("/violation_waypoint_*.json");
        for glob_result in glob::glob(&glob_path).unwrap() {
            let waypoint_violation_file_path = glob_result.unwrap();
            let waypoint = waypoint_violation_file_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
                .replace("violation_waypoint_", "")
                .replace(".json", "");
            let serialized_waypoint_violation_times =
                fs::read_to_string(waypoint_violation_file_path).unwrap();
            let waypoint_violation_times: Vec<Sample> =
                serde_json::from_str(&serialized_waypoint_violation_times).unwrap();
            plot_violation_times(
                &topo_name,
                &scenario_name,
                &format!("waypoint_{waypoint}"),
                &waypoint_violation_times,
                plot_dir.as_ref(),
            );
        }
        */
    });

    Ok(())
}

/// Creates a plot for each prefix of the scenario/experiment (should be only one experiment!)
/// matching the filter. Shows the connectivity of the prefix over time.
#[allow(unused)]
fn plot_prefixes(
    data_root: impl AsRef<Path> + Sync,
    filter: Filter,
    plot_dir: impl AsRef<Path> + Sync,
) -> Result<(), Box<dyn std::error::Error>> {
    let data_root = data_root.as_ref();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // produce histograms of all prefixes of this sample
            process_pcaps::process_pcaps(data_root, filter, Some(plot_dir.as_ref()))
                .await
                .unwrap();

            // wait for one second
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

    Ok(())
}

/// Creates a plot for the given scenario showing the violation times captured per sample for each
/// probed prefix.
fn plot_violation_times(
    topo_name: impl AsRef<str>,
    scenario: impl AsRef<str>,
    property_name: impl AsRef<str>,
    violation_times: &[Sample],
    plot_dir: impl AsRef<Path>,
) {
    let topo_name = topo_name.as_ref();
    let scenario = scenario.as_ref();
    let property_name = property_name.as_ref();

    let mut plot_dir = plot_dir.as_ref().to_path_buf();
    plot_dir.push(property_name);
    fs::create_dir_all(&plot_dir).unwrap();

    // HashMap to store the vectors of violation times per router
    let mut result: HashMap<&str, Vec<f64>> = HashMap::new();

    for sample in violation_times.iter() {
        for (_prefix, sample_properties) in sample.violation_times.iter() {
            for (router_name, violation_info) in sample_properties.iter() {
                // discard additional information, only add violation times to the plots
                if let ViolationInfo::Time(violation_time) = violation_info {
                    result.entry(router_name).or_default().push(*violation_time);
                }
            }
        }
    }

    // at this point we have a result `HashMap<&str, Vec<f64>>` mapping router_name to the
    // violation times observed for a set of samples.
    let mut data: HashMap<String, Vec<f64>> = HashMap::new();
    for (router_name, violation_times) in result {
        data.insert(router_name.to_string(), violation_times);
    }

    // plot violation data
    let mut plot = plotly::Plot::new();
    for (topo_router_prefix, violation_times) in data
        .into_iter()
        .sorted_by(|a, b| human_sort::compare(&a.0, &b.0))
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(violation_times).name(&topo_router_prefix);
        plot.add_trace(trace);
    }

    log::debug!(
        "Plotting {}/{topo_name}_{scenario}.html",
        plot_dir.to_string_lossy()
    );
    plot.write_html(format!(
        "{}/{topo_name}_{scenario}.html",
        plot_dir.to_string_lossy()
    ));
}

/// Create a single plot containing all scenarios matching the `filters`, showing the average
/// minimum, median, and maximum violation times captured per sample.
fn plot_k_filters(
    data_root: impl AsRef<Path> + Sync,
    filters: Vec<(impl AsRef<str>, Filter)>,
    plot_dir: impl AsRef<Path> + Sync,
    plot_prefix: impl Display,
    allow_drops: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(!filters.is_empty());

    let data_root = data_root.as_ref();
    let plot_dir = plot_dir.as_ref();

    // get all (topo, scenario) combinations
    let data = filters
        .iter()
        .flat_map(|(column_name, filter)| {
            util::filter_data(data_root, filter.clone())
                .into_iter()
                .map(|x| (column_name.as_ref().to_string(), x))
        })
        .filter_map(|(column_name, (_topo_name, _scenario_name, eval_path))| {
            // read violation_times from the files
            let mut reachability_violation_file_path = eval_path.clone();
            reachability_violation_file_path.push("violation_reachability.json");
            if !reachability_violation_file_path.exists() {
                return None;
            }

            let filtered_out = if allow_drops {
                HashSet::new()
            } else {
                // check the cisco_analyzer for whether packets were dropped in a sample or not
                let mut analyzer_csv_path = eval_path.clone();
                analyzer_csv_path.push("cisco_analyzer.csv");
                if !analyzer_csv_path.exists() {
                    log::error!(
                        "Cannot check whether packets were dropped for scenario {analyzer_csv_path:?} as it has no captured data."
                    );
                    return None; // `return;` in a `for_each(...)` loop is equivalent to `continue;`
                }
                let analyzer_csv = fs::File::open(analyzer_csv_path.clone()).unwrap();
                let mut csv = csv::Reader::from_reader(analyzer_csv);

                csv.deserialize().filter_map(|record| {
                    let record: CiscoAnalyzerData = record.unwrap();
                    if record.packets_dropped > 0 {
                        Some(record.execution_timestamp)
                    } else {
                        None
                    }
                }).collect()
            };

            let serialized_reachability_violation_times =
                fs::read_to_string(&reachability_violation_file_path).unwrap();
            let reachability_violation_times: Vec<Sample> =
                serde_json::from_str(&serialized_reachability_violation_times).unwrap();

            Some(reachability_violation_times.into_iter().filter_map(
                move |Sample {
                          sample_id,
                          violation_times,
                      }| {
                    if filtered_out.contains(&sample_id) {
                        return None;
                    }
                    let violations_per_router = violation_times
                        .into_iter()
                        .flat_map(move |(prefix, sample_properties)| {
                            sample_properties.into_iter().filter_map(
                                move |(router_name, violation_info)| match violation_info {
                                    ViolationInfo::Time(violation_time) => {
                                        Some((router_name, prefix.to_string(), violation_time))
                                    }
                                    _ => None,
                                },
                            )
                        })
                        // iterator over all (router, violation_time) tuples, over all prefixes
                        .sorted_by_key(|(router_name, _prefix, _violation_time)| router_name.to_string())
                        .group_by(|(router_name, _prefix, _violation_time)| router_name.to_string());
                    Some(violations_per_router
                        .into_iter()
                        // for each router, get the min, med, and max
                        .map(|(router_name, group)| {
                            let router_violations = group
                                .into_iter()
                                .map(|(_, prefix, violation_time)| (prefix, violation_time))
                                .sorted_by(|a, b| a.1.total_cmp(&b.1))
                                .collect_vec();
                            (
                                (sample_id.to_string(), column_name.to_string(), router_name.to_string()),
                                router_violations,
                            )
                        })
                        .collect_vec())
                },
            )
            .flatten())
        })
        .flatten()
        .collect::<BTreeMap<_, _>>();

    // write raw data to csv
    let mut csv_path = plot_dir.to_path_buf();
    csv_path.push(format!(
        "{plot_prefix}_{}_{}_{}.csv",
        filters[0].1.topo, filters[0].1.scenario, filters[0].1.scenario_end
    ));
    let mut csv = csv::WriterBuilder::new().from_writer(
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(false)
            .truncate(true)
            .open(&csv_path)
            .unwrap(),
    );

    if format!("{plot_prefix}") == "prefixes" {
        for (num_prefixes, mut violation_times) in data
            .iter()
            .flat_map(|((_sample_id, x, _router_name), ys)| {
                ys.iter().map(move |(_prefix, y)| (x.to_string(), y))
            })
            .sorted_by_key(|(x, _y)| filters.iter().position(|z| x == z.0.as_ref()).unwrap())
            .group_by(|(x, _y)| x.to_string())
            .into_iter()
            .map(|(x, group)| (x, group.into_iter().map(|(_x, y)| *y).collect_vec()))
        {
            violation_times.sort_by(|a, b| a.total_cmp(b));

            #[derive(Serialize)]
            struct PrefixQuantiles<'a> {
                num_prefixes: &'a str,
                q0: f64,
                q1: f64,
                q5: f64,
                q10: f64,
                q25: f64,
                q45: f64,
                q50: f64,
                q55: f64,
                q75: f64,
                q90: f64,
                q95: f64,
                q99: f64,
                q100: f64,
                avg: f64,
            }

            let zero = 0.02;

            csv.serialize(PrefixQuantiles {
                num_prefixes: &num_prefixes,
                q0: violation_times[0].max(zero),
                q1: violation_times[violation_times.len() / 100].max(zero),
                q5: violation_times[5 * violation_times.len() / 100].max(zero),
                q10: violation_times[10 * violation_times.len() / 100].max(zero),
                q25: violation_times[25 * violation_times.len() / 100].max(zero),
                q45: violation_times[45 * violation_times.len() / 100].max(zero),
                q50: violation_times[50 * violation_times.len() / 100].max(zero),
                q55: violation_times[55 * violation_times.len() / 100].max(zero),
                q75: violation_times[75 * violation_times.len() / 100].max(zero),
                q90: violation_times[90 * violation_times.len() / 100].max(zero),
                q95: violation_times[95 * violation_times.len() / 100].max(zero),
                q99: violation_times[99 * violation_times.len() / 100].max(zero),
                q100: violation_times[violation_times.len() - 1].max(zero),
                avg: (violation_times.iter().sum::<f64>() / violation_times.len() as f64).max(zero),
            })
            .unwrap();
        }
    } else {
        for ((sample_id, column_name, router_name), violations) in data.iter() {
            for (prefix, violation) in violations.iter() {
                csv.serialize(RawDataPoint {
                    sample_id,
                    column_name,
                    router_name,
                    prefix,
                    violation: *violation,
                })
                .unwrap();
            }
        }
    }
    csv.flush().unwrap();

    let routers: HashSet<String> = HashSet::from_iter(
        data.iter()
            .map(|((_sample_id, _column_name, router_name), _violations)| router_name.to_string()),
    );

    // generate the plot for all routers
    let mut plot = plotly::Plot::new();

    for (column_name, violation_times) in data
        .iter()
        .flat_map(|((_sample_id, x, _router_name), ys)| ys.iter().map(move |y| (x.to_string(), y)))
        .sorted_by_key(|(x, _y)| filters.iter().position(|z| x == z.0.as_ref()).unwrap())
        .group_by(|(x, _y)| x.to_string())
        .into_iter()
        .map(|(x, group)| {
            (
                x,
                group.into_iter().map(|(_x, (_prefix, y))| *y).collect_vec(),
            )
        })
    {
        let trace = plotly::BoxPlot::<f64, f64>::new(violation_times).name(&column_name);
        plot.add_trace(trace);
    }

    let mut output = plot_dir.to_path_buf();
    output.push(format!(
        "{plot_prefix}_{}_{}_{}.html",
        filters[0].1.topo, filters[0].1.scenario, filters[0].1.scenario_end
    ));
    log::debug!("Plotting {output:?}");
    plot.write_html(output);

    // generate separate plots per router
    for router_name in routers {
        let mut plot = plotly::Plot::new();

        for (column_name, violation_times) in data
            .iter()
            .filter_map(|((_sample_id, x, r), ys)| {
                if *r == router_name {
                    Some((x.to_string(), ys))
                } else {
                    None
                }
            })
            .flat_map(|(x, ys)| ys.iter().map(move |(_prefix, y)| (x.to_string(), y)))
            .sorted_by_key(|(x, _y)| filters.iter().position(|z| x == z.0.as_ref()).unwrap())
            .group_by(|(x, _y)| x.to_string())
            .into_iter()
            .map(|(x, group)| (x, group.into_iter().map(|(_x, y)| *y).collect_vec()))
        {
            let trace = plotly::BoxPlot::<f64, f64>::new(violation_times).name(&column_name);
            plot.add_trace(trace);
        }

        let mut output = plot_dir.to_path_buf();
        output.push(format!(
            "{plot_prefix}_{}_{}_{}_{router_name}.html",
            filters[0].1.topo, filters[0].1.scenario, filters[0].1.scenario_end
        ));
        log::debug!("Plotting {output:?}");
        plot.write_html(output);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_plots() {
        util::init_logging();

        plot_violations(
            "./src/test/pcap_processing/",
            Filter {
                topo: "".to_string(),
                scenario: "".to_string(),
                scenario_end: "".to_string(),
                sample_id: "".to_string(),
            },
            "./plots",
        )
        .expect("Plotting should pass withour errors.");
    }
}
