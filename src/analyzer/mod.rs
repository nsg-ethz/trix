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
//! Module that performs the probabilistic convergence analysis
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs,
    hash::Hasher,
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use geoutils::Location;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use time::{format_description, OffsetDateTime};
use tokio::time::timeout;

use bgpsim::{
    event::{EventQueue, FmtPriority},
    export::Addressor,
    forwarding_state::ForwardingState,
    interactive::PartialClone,
    policies::Policy,
    prelude::*,
    types::StepUpdate,
};
pub use router_lab::hardware_mapping::HardwareMapping;
use router_lab::{export_capture_to_csv, RouterLab};

// pub use to keep dependencies working where stuff was originally defined in this file
pub use trix_utils::serde::CiscoAnalyzerData;

use crate::{
    event::AnalyzerEvent,
    timing_model::TimingModel,
    transient_specification::{compute_violation_times, TransientPolicy},
    MultiPrefixConvergenceTrace, Prefix,
};

pub mod analyzer_script;
pub mod bgp_log_parser;
pub mod cpu_monitor;
pub mod ipfib_log_parser;
mod log_parser;
mod prefix;
mod result;
pub mod ufdm_log_parser;
pub mod urib_log_parser;

use analyzer_script::*;
use bgp_log_parser::{BgpPrefixesLogParser, BgpUribLogParser};
use cpu_monitor::*;
use ipfib_log_parser::IpfibLogParser;
use log_parser::{setup_parsers, store_logs};
pub use prefix::AnalyzerPrefix;
pub use result::*;
use ufdm_log_parser::UfdmLogParser;
use urib_log_parser::UribLogParser;

/// directory where to log the data to
//const CAPTURE_OUTPUT_DIR: &str = "captures";

pub fn num_workers() -> usize {
    // use multiple threads
    //num_cpus::get() / 2
    // use a single thread
    1
    // use a fixed number of threads
    // 100
}

/// Type for the stats structure
type Stats = HashMap<u64, Vec<Vec<f64>>>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    bound(
        deserialize = "Q: for<'a> serde::Deserialize<'a> + EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq, Q::Priority: Default + FmtPriority + Clone"
    ),
    try_from = "SerializedAnalyzer<Q>"
)]
pub struct Analyzer<Q> {
    /// The original network before any event occurs
    pub original_net: Network<Prefix, Q>,
    /// The prepared event containing all information that should occur in the network
    pub event: AnalyzerEvent<RouterId>,
    /// The network right after the event occurs, without any BGP messages being processed.
    pub scheduled_net: Network<Prefix, Q>,
    /// The forwarding state of the original network,
    pub original_fw: ForwardingState<Prefix>,
    /// the forwarding state of the scheduled network,
    pub scheduled_fw: ForwardingState<Prefix>,
    /// The time offset of the network at the beginning of the convergence
    /// recordings (if applicable)
    pub time_offset: f64,
    /// The set of policies to verify.
    pub policies: Vec<TransientPolicy>,
    /// Confidence (1-alpha), typically 95% or 99%.
    pub confidence: f64,
    /// Precision, how accurate the final result should be.
    #[serde(default)]
    pub num_samples: Option<usize>,
    /// Precision, how accurate the final result should be.
    pub precision: f64,
    /// The network's nodes' geographical locations on earth, if available.
    #[serde(default)]
    pub geo_location: Option<HashMap<RouterId, Location>>,
    /// The network's nodes' delays, if available.
    #[serde(default, with = "crate::serde_generic_hashmap::in_option")]
    pub delays: Option<HashMap<(RouterId, RouterId), f64>>,
}

/// Type used to deserialize an `Analyzer<Q>` whilst ignoring `scheduled_net` and `scheduled_fw`
/// and recomputing those by applying the event to the network
#[derive(Deserialize, Serialize)]
#[serde(bound(deserialize = "Q: for<'a> serde::Deserialize<'a>"))]
pub struct SerializedAnalyzer<Q> {
    /// The original network before any event occurs
    pub original_net: Network<Prefix, Q>,
    /// The prepared event containing all information that should occur in the network
    pub event: AnalyzerEvent<RouterId>,
    /// The forwarding state of the original network,
    pub original_fw: ForwardingState<Prefix>,
    /// The time offset of the network at the beginning of the convergence
    /// recordings (if applicable)
    pub time_offset: f64,
    /// The set of policies to verify.
    pub policies: Vec<TransientPolicy>,
    /// Confidence (1-alpha), typically 95% or 99%.
    pub confidence: f64,
    /// Precision, how accurate the final result should be.
    pub precision: f64,
    /// The network's nodes' geographical locations on earth, if available.
    #[serde(default)]
    pub geo_location: Option<HashMap<RouterId, Location>>,
    /// The network's nodes' delays, if available.
    #[serde(default, with = "crate::serde_generic_hashmap::in_option")]
    pub delays: Option<HashMap<(RouterId, RouterId), f64>>,
}

impl<Q> TryFrom<SerializedAnalyzer<Q>> for Analyzer<Q>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
{
    type Error = NetworkError;

    fn try_from(analyzer: SerializedAnalyzer<Q>) -> Result<Self, Self::Error> {
        let mut scheduled_net = analyzer.original_net.clone();
        scheduled_net.manual_simulation();

        // perform the event
        analyzer.event.trigger(&mut scheduled_net)?;

        // get the scheduled forwarding state
        let scheduled_fw = scheduled_net.get_forwarding_state();

        Ok(Self {
            original_net: analyzer.original_net,
            event: analyzer.event,
            scheduled_net,
            original_fw: analyzer.original_fw,
            scheduled_fw,
            time_offset: analyzer.time_offset,
            policies: analyzer.policies,
            confidence: analyzer.confidence,
            num_samples: None,
            precision: analyzer.precision,
            geo_location: analyzer.geo_location,
            delays: analyzer.delays,
        })
    }
}

#[allow(dead_code)]
impl<Q> Analyzer<Q>
where
    Q: EventQueue<Prefix> + Clone + Send + Sync + std::fmt::Debug + PartialEq,
    Q::Priority: Default + FmtPriority + Clone,
{
    /// Create a new analyzer with the given parameters. The event is a callback function that
    /// should perform the specific event.
    pub fn new(
        net: Network<Prefix, Q>,
        event: AnalyzerEvent<RouterId>,
        policies: Vec<TransientPolicy>,
        confidence: f64,
        precision: f64,
    ) -> Result<Self, NetworkError> {
        let original_fw = net.get_forwarding_state();

        let mut scheduled_net = net.clone();
        scheduled_net.manual_simulation();

        // perform the event
        event.trigger(&mut scheduled_net)?;

        // get the scheduled forwarding state
        let scheduled_fw = scheduled_net.get_forwarding_state();

        // get the initial time_offset
        let time_offset = scheduled_net.queue().get_time().unwrap_or_default();

        Ok(Self {
            original_net: net,
            event,
            scheduled_net,
            original_fw,
            scheduled_fw,
            time_offset,
            policies,
            confidence,
            num_samples: None,
            precision,
            geo_location: None,
            delays: None,
        })
    }

    /// Return the number of routers required to execute this analyzer.
    pub fn num_routers(&self) -> usize {
        self.original_net.internal_routers().count()
    }

    pub fn build_queue(&self) -> TimingModel<Prefix> {
        if let Some(geo_location) = &self.geo_location {
            TimingModel::from_geo_location(geo_location)
        } else if let Some(delays) = &self.delays {
            TimingModel::from_delays(delays)
        } else {
            panic!("TimingModel cannot be initialized without geo_location and delays!");
        }
    }

    /// Perform the analysis, returning the probability that the property is satisfied (plus minus
    /// `self.imprecision` with confidence `self.confidence`). This will spawn threads and start
    /// sampling the network in parallel.
    ///
    /// If the features `router_lab` is enabled, this procedure also runs the same experiment on the
    /// routing testbed. This function assumes that the router-lab config is already created and
    /// that the required environment variables have been set. Check `main.rs` for an example.
    pub fn analyze(&self) -> AnalysisResult {
        let stats_mutex = Arc::new(Mutex::new(Stats::new()));

        let workers = num_workers();
        let iters_per_worker = ((self.num_samples() as f64) / (workers as f64)).ceil() as usize;

        let result_mutex = Arc::new(Mutex::new(AnalysisResult {
            confidence: self.confidence,
            precision: self.precision,
            n_samples: iters_per_worker * workers,
            ..Default::default()
        }));

        let start = Instant::now();

        crossbeam_utils::thread::scope(|s| {
            (0..workers).for_each(|_| {
                let result = result_mutex.clone();
                let stats = stats_mutex.clone();
                s.spawn(|_| self.worker(result, stats, iters_per_worker));
            })
        })
        .unwrap();

        let stats = Arc::try_unwrap(stats_mutex).unwrap().into_inner().unwrap();
        let mut result = Arc::try_unwrap(result_mutex).unwrap().into_inner().unwrap();

        let count_satisfied: usize = stats
            .values()
            .flatten()
            .filter(|violation_times| violation_times.iter().all(|&t| t == 0.0))
            .count();
        let mut sample_iters: Vec<_> = stats.values().flatten().map(|s| s.iter()).collect();

        result.p_satisfied = (count_satisfied as f64) / (result.n_samples as f64);
        result.t_wall = start.elapsed();
        result.convergence_time /= result.n_samples as f64;
        result.violation_time_distributions = self
            .policies
            .iter()
            .map(|p| {
                let violation_times: Vec<f64> = sample_iters
                    .iter_mut()
                    .map(|s| s.next().copied().unwrap())
                    .sorted_by(|a, b| a.total_cmp(b))
                    .collect();
                ((p.router().unwrap(), p.prefix().unwrap()), violation_times)
            })
            .collect();
        result.n_unique_equiv = stats.len();

        /*
        log::debug!("STATUS UPDATE: simulator distribution");
        for (rid, prefix) in result.violation_time_distributions.keys().sorted() {
            let simulated_distribution = result
                .violation_time_distributions
                .get(&(*rid, *prefix))
                .unwrap();
            log::debug!(
                "{} for {prefix:?} simulated (avg: {})\n{simulated_distribution:?}",
                rid.fmt(&self.original_net),
                simulated_distribution.iter().sum::<f64>() / simulated_distribution.len() as f64,
            );
        }
        */

        result
    }

    /// Collect measurements for `num_samples` on the hardware and store all gathered data in the
    /// `data_path` directory (which is created if it doesn't exist yet).
    #[allow(unused)]
    pub async fn analyze_router_lab(
        &mut self,
        num_samples: usize,
        num_probes: usize,
        capture_frequency: u64,
        data_path: &Path,
    ) -> Result<HashMap<(RouterId, Prefix), Vec<f64>>, Box<dyn std::error::Error>> {
        let mut result = HashMap::new();

        // create the lab
        let mut lab = if let Some(physical_ext) = self.event.get_triggering_external() {
            RouterLab::with_bindings(
                &self.original_net,
                &HashMap::new(),
                &HashMap::from([(
                    physical_ext,
                    router_lab::config::VDCS.first().unwrap().ssh_name.clone(),
                )]),
            )
        } else {
            RouterLab::new(&self.original_net)
        }?;

        #[cfg(feature = "packet_equivalence_class")]
        {
            // create and register multiple prefix equivalence classes
            let pecs: Vec<Ipv4Net> = (0..100)
                .map(|x| Ipv4Addr::from((200u32 << 24) + (x << 8)))
                .map(|ip| Ipv4Net::new(ip, 24).unwrap())
                .collect();

            lab.addressor_mut().register_pec(Prefix, pecs);
        }

        self.event.prepare_initial_advertisements(&mut lab)?;
        for _ in 0..num_samples {
            // advance exabgp time before event
            lab.step_external_time();

            // apply the event as specified
            self.event.trigger_cisco_exabgp(&mut lab)?;

            // advance exabgp time before cleanup
            lab.step_external_time();

            // revert the event properly so that we can take another sample
            self.event.revert_cisco_exabgp(&mut lab)?;
        }

        if let Some(geo_location) = &self.geo_location {
            // set all link delays according to the geo_location from TopologyZoo
            lab.set_link_delays_from_geolocation(geo_location.clone());
        } else if let Some(delays) = &self.delays {
            // set all link delays according to the delays given
            for ((from, to), delay_us) in delays.iter() {
                lab.set_link_delay(*from, *to, (*delay_us) as u32);
                // set the reverse option if it is not set differently
                if !delays.contains_key(&(*to, *from)) {
                    lab.set_link_delay(*to, *from, (*delay_us) as u32);
                }
                log::trace!(
                    "link delay from {} to {}: {delay_us}",
                    from.fmt(&self.original_net),
                    to.fmt(&self.original_net)
                );
            }
        }

        // connect the network
        log::debug!("[cisco-analyzer] Connecting to routing testbed...");
        let mut lab = lab.connect().await?;

        // last setup for the event if necessary
        self.event.setup_cisco_direct(&mut lab).await?;

        // setup ssh handle and experiment paths
        let (traffic_pcap_path, traffic_monitor_handle) = lab
            .start_traffic_monitor(
                format!("monitor_{}", self.event.fmt(&self.original_net)),
                true,
            )
            .await?;
        let (ssh, packets_dropped) = lab.stop_traffic_monitor(traffic_monitor_handle).await?;
        log::debug!("[cisco-analyzer] dropped {packets_dropped} packets.");

        // cleanup: remove unused pcap
        ssh.execute_cmd_stdout(&[
            "rm -f ",
            &format!("{:?}", traffic_pcap_path.to_string_lossy()),
        ])
        .await?;

        let experiment_slug = traffic_pcap_path.file_stem().unwrap().to_str().unwrap();
        let mut experiment_path = traffic_pcap_path.clone();
        experiment_path.pop();
        let analyzer_path = write_analyzer_script(
            &lab,
            &self.original_net,
            &ssh,
            &experiment_path,
            experiment_slug,
        )
        .await?;

        log::debug!("[cisco-analyzer] Transferring pcap analyzer script");
        let mut local_analyzer_path = data_path.to_path_buf();
        local_analyzer_path.push(analyzer_path.file_name().unwrap());
        ssh.scp_rem2loc(&analyzer_path, &local_analyzer_path)
            .await?;
        ssh.execute_cmd(&["rm", "-f", &analyzer_path.to_string_lossy()])
            .await?;

        let mut csv_path = data_path.to_path_buf();
        csv_path.push("cisco_analyzer.csv");
        let mut csv = csv::WriterBuilder::new()
            .has_headers(!csv_path.exists() || fs::metadata(&csv_path)?.len() == 0)
            .from_writer(
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .truncate(false)
                    .open(&csv_path)?,
            );

        log::debug!("[cisco-analyzer] Waiting for initial convergence...");
        lab.wait_for_convergence().await?;

        // add some data-plane traffic by replicating 1Gbps TCP traffic
        let iperf_handle = lab.start_iperf(1, false).await?;

        for i in 0..num_samples {
            let execution_timestamp = OffsetDateTime::now_local()
                .unwrap_or_else(|_| OffsetDateTime::now_utc())
                .format(
                    &format_description::parse("[year]-[month]-[day]_[hour]-[minute]-[second]")
                        .unwrap(),
                )
                .unwrap();
            log::info!("[cisco-analyzer] starting sample {i} at {execution_timestamp}");

            let execution_start = Instant::now();

            // setup cpu monitoring on all cisco routers
            let cpu_monitors = setup_cpu_monitoring(&self.original_net, &lab).await?;
            let mut extended_cpu_monitoring_dir = data_path.to_path_buf();
            extended_cpu_monitoring_dir.push(&format!("cpu_monitor_{execution_timestamp}"));
            let extended_cpu_monitors = setup_extended_cpu_monitoring(
                &self.original_net,
                &lab,
                extended_cpu_monitoring_dir,
            )
            .await?;

            // setup the log parser on all routers
            let ipfib_log_parser = setup_parsers::<IpfibLogParser, _, _, _, _>(&lab).await?;
            let bgp_prefix_log_parser =
                setup_parsers::<BgpPrefixesLogParser, _, _, _, _>(&lab).await?;
            let bgp_urib_log_parser = setup_parsers::<BgpUribLogParser, _, _, _, _>(&lab).await?;
            let urib_log_parser = setup_parsers::<UribLogParser, _, _, _, _>(&lab).await?;
            let ufdm_log_parser = setup_parsers::<UfdmLogParser, _, _, _, _>(&lab).await?;

            // start the traffic monitor
            let (traffic_pcap_path, traffic_monitor_handle) = lab
                .start_traffic_monitor(
                    format!("monitor_{}", self.event.fmt(&self.original_net)),
                    true,
                )
                .await?;

            // start the capture & cpu monitoring
            log::debug!("[cisco-analyzer] Starting capture for cisco sample...");
            let capture = lab
                .start_capture(num_probes, capture_frequency, true)
                .await?;
            start_cpu_monitoring(&lab).await?;

            let mut tokio_scope = unsafe { async_scoped::TokioScope::create() };
            match &self.event {
                AnalyzerEvent::AnnounceRoute(_, ext, _)
                | AnalyzerEvent::WithdrawRoute(_, ext, _)
                | AnalyzerEvent::PhysicalExternalAnnounceRoute(_, ext, _)
                | AnalyzerEvent::PhysicalExternalWithdrawRoute(_, ext, _) => {
                    let ssh = lab.get_server_session();
                    let mut addressor = lab.addressor().clone();

                    tokio_scope.spawn(async move {
                        let ifaces = addressor.list_ifaces(*ext);
                        // set up filter for non-keepalive (85 bytes) BGP packets, add a
                        // null-statement in front to append all neighbors afterwards as a
                        // disjunction
                        let mut filter = String::from("\"port 179 and len > 85 and ((port 1 and port 2)");

                        for (neighbor, ipv4) in ifaces.iter().map(|(neighbor, ipv4, _, _)| (neighbor, ipv4)).unique() {
                            if let Ok(neighbor_ipv4) = addressor.iface_address(*neighbor, *ext) {
                                filter.push_str(&format!(
                                    " or (src {ipv4} and dst {neighbor_ipv4})"
                                ));
                            }
                        }

                        filter.push_str(")\"");

                        let cmd = format!(
                            "sudo tcpdump_pfring -i enp132s0f1 {filter} -c1 -w - 2>/dev/null | tshark -r - -T fields -e frame.time_epoch 2>/dev/null",
                        );

                        log::trace!("executing: {cmd}");

                        ssh.execute_cmd_stdout(&[&cmd])
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Could not determine BGP event's timestamp!");
                            String::from("0.0")
                        })
                    });
                }
                AnalyzerEvent::AnnounceRoutingInputs(inputs)
                | AnalyzerEvent::WithdrawRoutingInputs(inputs)
                | AnalyzerEvent::PhysicalExternalAnnounceRoutingInputs(inputs)
                | AnalyzerEvent::PhysicalExternalWithdrawRoutingInputs(inputs)
                | AnalyzerEvent::PhysicalExternalUpdateBetterRoutingInputs(inputs)
                | AnalyzerEvent::PhysicalExternalUpdateWorseRoutingInputs(inputs) => {
                    let ssh = lab.get_server_session();
                    let mut addressor = lab.addressor().clone();

                    tokio_scope.spawn(async move {
                        // set up filter for non-keepalive (85 bytes) BGP packets, add a
                        // null-statement in front to append all neighbors afterwards as a
                        // disjunction
                        let mut filter = String::from("\"port 179 and len > 85 and ((port 1 and port 2)");

                        for ext in inputs.external_routers().iter().unique().map(|(rid, _)| rid) {
                            let ifaces = addressor.list_ifaces(*ext);
                            for (neighbor, ipv4, _, _) in ifaces.iter().unique() {
                                if let Ok(neighbor_ipv4) = addressor.iface_address(*neighbor, *ext) {
                                    filter.push_str(&format!(
                                        " or (src {ipv4} and dst {neighbor_ipv4})"
                                    ));
                                }
                            }
                        }

                        filter.push_str(")\"");

                        let cmd = format!(
                            "sudo tcpdump_pfring -i enp132s0f1 {filter} -c1 -w - 2>/dev/null | tshark -r - -T fields -e frame.time_epoch 2>/dev/null",
                        );

                        log::trace!("executing: {cmd}");

                        ssh.execute_cmd_stdout(&[&cmd])
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Could not determine BGP event's timestamp!");
                            String::from("0.0")
                        })
                    });
                }
                AnalyzerEvent::AddLink(_, _, _, _, _)
                | AnalyzerEvent::RemoveLink(_, _, _)
                | AnalyzerEvent::LowerLocalPref(_, _, _) => {
                    let ssh = lab.get_server_session();

                    tokio_scope.spawn(async move {
                        // use server time as a replacement for non-bgp events
                        ssh.execute_cmd_stdout(&["date", "+%s.%N"])
                            .await
                            .unwrap_or_else(|_| {
                                log::warn!("Could not determine event's timestamp!");
                                String::from("0.0")
                            })
                    });
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;

            // step in exabgp: execute the event
            log::debug!("[cisco-analyzer] Introducing network event... (capture until there are no more BGP messages for 5 seconds)!");
            self.event.trigger_cisco_direct(&mut lab).await?;
            lab.get_exabgp_handle().step().await?;

            // wait for the detection of the event start
            log::debug!("waiting for capturing the event start...");
            let event_start: f64 = timeout(Duration::from_secs(30), tokio_scope.collect()).await?
                [0]
            .as_ref()
            .unwrap_or(&String::from("0.0"))
            .trim()
            .parse()
            .unwrap();
            drop(tokio_scope); // end TokioScope
            log::debug!("violation started at time {event_start:?}");

            // then, capture for at least 10 seconds without any BGP messages
            lab.wait_for_no_bgp_messages_on_monitoring_iface(Duration::from_secs(10))
                .await?;

            // collect and log the results to .csv
            let capture_result = lab.stop_capture(capture).await?;

            // stop the traffic_monitor
            let (_, packets_dropped) = lab.stop_traffic_monitor(traffic_monitor_handle).await?;

            // stop the cpu monitoring
            let mut cpu_monitoring_path = data_path.to_path_buf();
            cpu_monitoring_path.push(&format!("cpu_monitor_{execution_timestamp}.csv"));
            let _cpu_monitoring_path =
                stop_cpu_monitoring(&lab, cpu_monitors, cpu_monitoring_path).await?;
            for mut child in extended_cpu_monitors.into_values() {
                child.wait().await?;
            }

            // get the root path for all unprocessed log messages
            let mut log_path = data_path.to_path_buf();
            let mut raw_log_dir = data_path.to_path_buf();
            raw_log_dir.push(format!("logs_{execution_timestamp}"));

            // get the ipfib log
            log_path.push(format!("ipfib_log_{execution_timestamp}.csv"));
            store_logs(ipfib_log_parser, &log_path, Some(&raw_log_dir)).await?;

            // store the bgp_prefixes log
            log_path.pop();
            log_path.push(format!("bgp_prefix_log_{execution_timestamp}.csv"));
            store_logs(bgp_prefix_log_parser, &log_path, Some(&raw_log_dir)).await?;

            // store the bgp_urib log
            log_path.pop();
            log_path.push(format!("bgp_urib_log_{execution_timestamp}.csv"));
            store_logs(bgp_urib_log_parser, &log_path, Some(&raw_log_dir)).await?;

            // store the urib log
            log_path.pop();
            log_path.push(format!("urib_log_{execution_timestamp}.csv"));
            store_logs(urib_log_parser, &log_path, Some(&raw_log_dir)).await?;

            // store the ufdm log
            log_path.pop();
            log_path.push(format!("ufdm_log_{execution_timestamp}.csv"));
            store_logs(ufdm_log_parser, &log_path, Some(&raw_log_dir)).await?;

            // clear all event history logs
            log_parser::clear_event_history(&lab).await?;

            let mut captures_path = data_path.to_path_buf();
            captures_path.push("captures");
            export_capture_to_csv(&self.original_net, &capture_result, &captures_path, "event")?;
            /*
            // captures are currently no longer used
            for ((rid, prefix, _), samples) in capture_result.iter() {
                let len = samples
                    .iter()
                    .count();

                if samples.len() - len > 100 {
                    log::warn!(
                        "Discarding {} samples happening after the event_start for router {}",
                        samples.len() - len,
                        rid.fmt(&self.original_net)
                    );
                }

                let total_num_samples = (samples.into_iter().map(|x| x.3).max().unwrap_or(0)
                    - samples.into_iter().map(|x| x.3).min().unwrap_or(0))
                    as usize
                    + 1;
                result
                    .entry((*rid, *prefix))
                    .or_insert_with(Vec::new)
                    .push((total_num_samples - len) as f64 / capture_frequency as f64);
            }
            print_captures(
                &self.original_net,
                capture_result.clone(),
                &self.event,
                event_start,
                capture_frequency,
            );
            */

            // step in exabgp: revert the event and wait for convergence
            log::debug!("[cisco-analyzer] Reverting network event...!");
            self.event.revert_cisco_direct(&mut lab).await?;
            lab.get_exabgp_handle().step().await?;

            /*
            // violations can only be determined by post-processing
            log::debug!("STATUS UPDATE: cisco distribution");
            for (rid, prefix) in result.keys().sorted() {
                let cisco_distribution = result.get(&(*rid, *prefix)).unwrap();
                log::debug!(
                    "{} for {prefix:?} measured:\n{cisco_distribution:?}",
                    rid.fmt(&self.original_net)
                );
            }
            */

            log::debug!("[cisco-analyzer] Writing prober_result file");
            let prober_result_filename = format!("prober_results_{execution_timestamp}.json");
            let mut prober_result_path = data_path.to_path_buf();
            prober_result_path.push(&prober_result_filename);
            let mut prober_result_file = fs::File::create(prober_result_path)?;
            prober_result_file.write_all(
                serde_json::to_string(&capture_result.into_iter().collect::<Vec<_>>())?.as_bytes(),
            )?;
            // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`

            log::debug!("[cisco-analyzer] Transferring pcap file");
            let pcap_filename = format!("pcap_{execution_timestamp}.pcap.gz");
            let mut pcap_path = data_path.to_path_buf();
            pcap_path.push(&pcap_filename);
            ssh.execute_cmd(&["gzip", &traffic_pcap_path.to_string_lossy()])
                .await?;
            let mut zipped_pcap = traffic_pcap_path.clone();
            zipped_pcap.set_extension("pcap.gz");
            ssh.scp_rem2loc(&zipped_pcap, &pcap_path).await?;
            ssh.execute_cmd(&["rm", "-f", &zipped_pcap.to_string_lossy()])
                .await?;

            log::debug!("[cisco-analyzer] Writing hardware mapping");
            let hardware_mapping = lab.get_hardware_mapping();
            let hardware_mapping_filename = format!("hardware_mapping_{execution_timestamp}.json");
            let mut hardware_mapping_path = data_path.to_path_buf();
            hardware_mapping_path.push(&hardware_mapping_filename);
            let mut hardware_mapping_file = fs::File::create(hardware_mapping_path)?;
            hardware_mapping_file
                .write_all(serde_json::to_string_pretty(hardware_mapping)?.as_bytes())?;
            // deserialize as Vec<(K, V)> and run `.into_iter().collect::<HashMap<...>>()`

            log::debug!("[cisco-analyzer] Writing CSV");
            // write results to persistent csv
            csv.serialize(CiscoAnalyzerData {
                execution_timestamp,
                execution_duration: execution_start.elapsed().as_secs_f64(),
                event_start,
                prober_result_filename,
                pcap_filename,
                capture_frequency,
                hardware_mapping_filename,
                packets_dropped,
            })?;
            csv.flush()?;

            lab.wait_for_convergence().await?;
        }

        lab.stop_iperf(iperf_handle).await?;

        // disconnect the network.
        print!("Network is disconnecting...");
        let _ = lab.disconnect().await?;
        log::debug!("[cisco-analyzer] Done.");

        Ok(result)
    }

    fn worker(
        &self,
        result_global: Arc<Mutex<AnalysisResult>>,
        stats_global: Arc<Mutex<Stats>>,
        iters: usize,
    ) {
        // thread-local copies of the network and fw_state
        let mut t = self.scheduled_net.clone();
        let mut fw_state = self.original_fw.clone();

        // thread-local HashMap to keep track of the results
        let mut stats = Stats::new();

        // initialize durations for accumulative performance measurements per worker
        let mut sum_simulate = Duration::new(0, 0);
        let mut sum_checking = Duration::new(0, 0);
        let mut sum_clone = Duration::new(0, 0);

        let mut convergence_time = 0.0;

        let mut queue;
        if let Some(geo_location) = &self.geo_location {
            queue = TimingModel::from_geo_location(geo_location);
        } else if let Some(delays) = &self.delays {
            queue = TimingModel::from_delays(delays);
        } else {
            panic!("TimingModel cannot be initialized without geo_location and delays!");
        }

        for _ in 0..iters {
            let step = self.simulate_once(t, fw_state, &mut queue, &mut stats);
            t = step.0;
            fw_state = step.1;
            sum_simulate += step.2;
            sum_checking += step.3;
            sum_clone += step.4;
            convergence_time += step.5;
        }

        // make sure (only once per worker) that the partial_clone is actually safe
        assert_eq!(t, self.scheduled_net);

        let now = Instant::now();

        // wait for exclusive access on global stats hashmap
        let mut stats_global = stats_global.lock().unwrap();
        // insert all values into the global hashmap
        for (eq_class, violation_times) in stats.into_iter() {
            stats_global
                .entry(eq_class)
                .or_default()
                .extend(violation_times);
        }

        let time_insert_global = now.elapsed();

        // collect the timing
        let mut result_global = result_global.lock().unwrap();
        result_global.t_checking += sum_checking;
        result_global.t_cloning += sum_clone;
        result_global.t_simulate += sum_simulate;
        result_global.t_collect += time_insert_global;
        result_global.convergence_time += convergence_time;
    }

    /// Perform a single iteration on the worker
    pub fn simulate_once(
        &self,
        mut net: Network<Prefix, Q>,
        mut fw_state: ForwardingState<Prefix>,
        queue: &mut TimingModel<Prefix>,
        stats: &mut Stats,
    ) -> (
        Network<Prefix, Q>,
        ForwardingState<Prefix>,
        Duration,
        Duration,
        Duration,
        f64,
    ) {
        let now = Instant::now();

        let trace = self.build_trace(&mut net);

        // compute equivalence classes with a canonical message ordering
        let eq_class = compute_equivalence_class(&trace, &self.scheduled_fw, &self.policies);

        let t_simulate = now.elapsed();
        let now = Instant::now();

        // generate convergence recording
        //let mut recording = ConvergenceRecording::new(fw_state, trace);
        /*
        // generate a data-plane graph similar to the hardware measurements
        let _ = export_simulated_recording_to_csv(
            &t,
            &mut recording,
            capture_frequency * 10,
            CAPTURE_OUTPUT_DIR,
            "simulation",
        );
        */

        let transient_policies: HashMap<(RouterId, Prefix), Vec<TransientPolicy>> = self
            .policies
            .iter()
            .filter_map(|policy| {
                let (Some(rid), Some(prefix)) = (policy.router(), policy.prefix()) else {
                    return None;
                };
                Some((rid, prefix, policy.clone()))
            })
            .sorted_by(|(rid1, prefix1, _), (rid2, prefix2, _)| {
                rid1.cmp(rid2).then(prefix1.cmp(prefix2))
            })
            .group_by(|(rid, prefix, _policy)| (*rid, *prefix))
            .into_iter()
            .map(|((rid, prefix), group)| {
                (
                    (rid, prefix),
                    group
                        .into_iter()
                        .map(|(_, _, policy)| policy)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        // check transient policies
        let violation_times = compute_violation_times(
            &self.original_net,
            queue,
            &mut fw_state,
            &trace,
            &transient_policies,
            None::<&std::path::Path>,
        );

        // reuse the original ForwardingState with the next sample
        //fw_state = recording.into_initial_fw_state();

        // fix the return type to the old vec-based implementation
        let mut fixed_violation_times = vec![0.0; self.policies.len()];
        for (policy, violation) in violation_times {
            fixed_violation_times[self.policies.iter().position(|p| *p == policy).unwrap()] =
                violation;
        }
        // use entry syntax to avoid race condition for call to `contains_key`
        stats
            .entry(eq_class)
            .or_default()
            .push(fixed_violation_times);

        let t_checking = now.elapsed();

        let now = Instant::now();

        let convergence_time = net
            .queue()
            .get_time()
            .map(|x| x - self.time_offset)
            .unwrap_or_default();

        // reuse most parts of the network for faster cloning
        net = unsafe {
            PartialClone::new(&self.scheduled_net)
                .reuse_config(true)
                .reuse_igp_state(true)
                .reuse_queue_params(true)
                .conquer(net)
        };

        let t_clone = now.elapsed();

        (
            net,
            fw_state,
            t_simulate,
            t_checking,
            t_clone,
            convergence_time,
        )
    }

    pub fn build_trace(&self, net: &mut Network<Prefix, Q>) -> MultiPrefixConvergenceTrace {
        let mut trace = MultiPrefixConvergenceTrace::new();

        while let Some((step, event)) = net.simulate_step().unwrap() {
            match step {
                StepUpdate::Unchanged => {}
                StepUpdate::Single(delta) => {
                    let time = net.queue().get_time().map(|x| x - self.time_offset);
                    let prefix = delta.prefix;
                    let prefix_trace = trace.entry(prefix).or_default();
                    // handle conflicts of forwarding updates after sampling the processing time
                    prefix_trace.push((vec![(event.router(), delta.old, delta.new)], time.into()));
                }
                StepUpdate::Multiple => {
                    unreachable!("not sure if this is expected. ignoring step update making multiple fw state changes at once");
                }
            }
        }
        trace
    }

    /// Replace all policies to analyze
    pub fn set_policies(&mut self, policies: Vec<TransientPolicy>) {
        self.policies = policies
    }

    pub fn net(&self) -> &Network<Prefix, Q> {
        &self.original_net
    }

    pub fn scheduled_net(&self) -> &Network<Prefix, Q> {
        &self.scheduled_net
    }

    /// Set the confidence (`1 - alpha`). Typically, this value should be 95% or 99%.
    pub fn set_confidence(&mut self, confidence: f64) {
        self.confidence = confidence
    }

    /// Set the number of collected samples explicitly.
    pub fn set_num_samples(&mut self, num_samples: usize) {
        self.num_samples = Some(num_samples)
    }

    /// Set the precision.
    pub fn set_precision(&mut self, precision: f64) {
        self.precision = precision
    }

    /// Set the geographic locations of the network's nodes on earth.
    pub fn set_geo_location(&mut self, geo_location: HashMap<RouterId, Location>) {
        self.geo_location = Some(geo_location.clone());
    }

    /// Set the router delays of the network's nodes.
    pub fn set_delays(&mut self, delays: HashMap<(RouterId, RouterId), f64>) {
        self.delays = Some(delays.clone());
    }

    /// Compute the number of samples required to reach the given confidence and precision
    pub fn num_samples(&self) -> usize {
        //self.num_samples
        //    .unwrap_or(hoeffding(self.confidence, self.precision))
        1
    }
}

/// Compute the number of samples required to reach the given confidence and precision
pub fn hoeffding(confidence: f64, precision: f64) -> usize {
    (f64::ln(2.0 / (1.0 - confidence)) / (0.5 * precision * precision)).ceil() as usize
}

/// Allows to compute an equivalence class using a custom hasher. Will unify message orderings
/// that are guaranteed to be equivalent upon reordering messages with respect to the given
/// TransientPolicies.
pub fn compute_equivalence_class(
    trace: &MultiPrefixConvergenceTrace,
    fw_state: &ForwardingState<Prefix>,
    transient_policies: &[TransientPolicy],
) -> u64 {
    // compute equivalence classes with a custom hasher:
    let mut hasher = DefaultHasher::new();

    for (prefix, prefix_trace) in trace.iter().sorted_by(|a, b| a.0.cmp(b.0)) {
        // encode considered prefix
        hasher.write_u32(bgpsim::types::Prefix::as_num(prefix));

        // store nodes that may be reached from any node with transient properties on this prefix
        let mut reachable_set: HashSet<RouterId> = HashSet::new();
        let mut todo_vec: Vec<RouterId> = transient_policies
            .iter()
            .map(|x| x.router().unwrap())
            .collect();
        while let Some(current_node) = todo_vec.pop() {
            if reachable_set.insert(current_node) {
                todo_vec.extend(
                    fw_state
                        .get_next_hops(current_node, *prefix)
                        .iter()
                        .copied(),
                );
            }
        }

        // cache the forwarding updates for routers that could not be reached before
        let mut cache: HashMap<RouterId, &[RouterId]> = HashMap::new();

        // check if there are any unnecessary updates or possible canonical reorderings
        for (fw_deltas, _) in prefix_trace.iter() {
            let mut reachable_fw_deltas = vec![];
            // collect applied updates and update caches for other updates accordingly
            for fw_delta in fw_deltas.iter() {
                if reachable_set.contains(&fw_delta.0) {
                    reachable_fw_deltas.push(fw_delta.clone());
                } else {
                    cache.insert(fw_delta.0, &fw_delta.2);
                }
            }

            // extend applied updates to newly reachable nodes
            let mut todo_vec: Vec<RouterId> = vec![];
            reachable_fw_deltas
                .iter()
                .for_each(|x| todo_vec.extend(x.2.iter().copied()));
            while let Some(current_node) = todo_vec.pop() {
                if reachable_set.insert(current_node) {
                    if let Some(next_hops) = cache.remove(&current_node) {
                        reachable_fw_deltas.push((current_node, vec![], next_hops.to_vec()));
                        todo_vec.extend(next_hops);
                    }
                }
            }

            // sort applied updates for uniqueness
            reachable_fw_deltas.sort();

            // extend hash value by all applied updates
            hasher.write_usize(reachable_fw_deltas.len());
            for fw_delta in reachable_fw_deltas {
                // encode modified router
                hasher.write_usize(fw_delta.0.index());

                // encode next_hops
                hasher.write_usize(fw_delta.2.len());
                let mut next_hops = fw_delta.2.clone();
                next_hops.sort();
                for x in next_hops {
                    hasher.write_usize(x.index());
                }
            }
        }
    }
    hasher.finish()
}
