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
use std::{collections::HashMap, time::Duration};

use csv::Reader;
use geoutils::Location;
use itertools::Itertools;

use trix::{analyzer::analyzer_script::*, prelude::*};
use bgpsim::{
    event::{GeoTimingModel, ModelParams},
    export::Addressor,
    prelude::*,
};
use router_lab::RouterLab;

type Prefix = SimplePrefix;

#[cfg(feature = "router_lab")]
mod generate_experiments;
#[cfg(feature = "router_lab")]
use generate_experiments::set_conf_dir;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> R {
    pretty_env_logger::init();

    #[cfg(feature = "router_lab")]
    set_conf_dir()?;

    let prefixes = MultiPrefix(3).prefixes();
    let first_prefix = prefixes[0];

    let e1_aspath: Vec<AsId> = vec![100.into(), 100.into(), 100.into(), 1000.into()];
    let e2_aspath: Vec<AsId> = vec![200.into(), 200.into(), 1000.into()];

    let mut analyzer_set = tokio::task::JoinSet::new();

    #[allow(unused_variables)]
    let (mut net, (r0, r1, r2, e1, e2)) = net! {
        Prefix = Prefix;
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
            e1 -> first_prefix as {path: &e1_aspath};
            e2 -> first_prefix as {path: &e2_aspath};
        };
        return (r0, r1, r2, e1, e2)
    };

    // advertise other prefixes
    for &prefix in prefixes.iter() {
        if prefix != first_prefix {
            net.advertise_external_route(e1, prefix, &e1_aspath, None, [])
                .unwrap();
            net.advertise_external_route(e2, prefix, &e2_aspath, None, [])
                .unwrap();
        }
    }

    let geo_locations = HashMap::from([
        (r0, Location::new(10.0, 0.0)),
        (r1, Location::new(20.0, 0.0)),
        (r2, Location::new(30.0, 0.0)),
    ]);

    let geo_timing_model = GeoTimingModel::<Prefix>::new(
        // ModelParams anyway ignored by the RouterLab
        ModelParams::new(0.0, 0.0, 1.0, 1.0, 0.0),
        ModelParams::new(0.0, 0.0, 1.0, 1.0, 0.0),
        &geo_locations,
    );

    let net = net.swap_queue(geo_timing_model).unwrap();

    // create the lab
    let mut lab = RouterLab::new(&net)?;

    // set link delays
    lab.set_link_delays_from_geolocation(geo_locations.clone());

    let num_samples = 1000;

    // setup route flapping
    for _ in 0..num_samples {
        lab.step_external_time();
        for prefix in prefixes.iter() {
            lab.withdraw_route(e2, *prefix).unwrap();
        }
        lab.step_external_time();
        for prefix in prefixes.iter() {
            lab.advertise_route(
                e2,
                &BgpRoute {
                    prefix: *prefix,
                    as_path: e2_aspath.clone(),
                    next_hop: e2,
                    local_pref: None,
                    med: None,
                    community: Default::default(),
                    originator_id: None,
                    cluster_list: Default::default(),
                },
            )
            .unwrap();
        }
    }

    // connect the network
    let mut lab = lab.connect().await?;

    // setup ssh handle and experiment paths
    let (traffic_pcap_path, traffic_monitor_handle) = lab
        .start_traffic_monitor(format!("monitor_{}", "withdraw_e2"), true)
        .await?;
    let (ssh, _) = lab.stop_traffic_monitor(traffic_monitor_handle).await?;

    // cleanup: remove unused pcap
    ssh.execute_cmd_stdout(&[
        "rm -f ",
        &format!("{}", traffic_pcap_path.to_string_lossy()),
    ])
    .await?;

    // let network converge, later we will only check that we see no more BGP changes
    lab.wait_for_convergence().await?;

    let experiment_slug = traffic_pcap_path.file_stem().unwrap().to_str().unwrap();
    let mut experiment_path = traffic_pcap_path.clone();
    experiment_path.pop();
    let analyzer_path =
        write_analyzer_script(&lab, &net, &ssh, &experiment_path, experiment_slug).await?;

    // add some data-plane traffic with 1Gbps TCP traffic
    let iperf_handle = lab.start_iperf(2, false).await?;

    for sample_idx in 0..num_samples {
        let now = std::time::Instant::now();

        log::debug!("[analyzer] Execute event {sample_idx}: withdrawing best route");

        // start the capture
        let capture_frequency = 3_000;
        let capture = lab.start_capture(5, capture_frequency, false).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // start the traffic monitor
        let (traffic_pcap_path, traffic_monitor_handle) = lab
            .start_traffic_monitor(format!("monitor_{}", "withdraw_e2"), true)
            .await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        lab.get_exabgp_handle().step().await?;

        for r in net.internal_routers() {
            if r.name() == "r0" {
                let rid = r.router_id();
                let vdc = lab.get_router_properties(rid).unwrap();
                let ifaces = lab.addressor().list_ifaces(rid);
                for (neighbor, ipv4, _, iface_idx) in ifaces.iter() {
                    if neighbor.fmt(&net) == "e1" {
                        if let Some(prober_iface) = lab.get_prober_ifaces().get(&rid) {
                            log::trace!(
                                "[analyzer] Waiting for message on link {}-{}, IP: {:?}, local MAC: {}\n{:#?}",
                                r.name(),
                                neighbor.fmt(&net),
                                ipv4,
                                vdc.ifaces[*iface_idx]
                                    .mac
                                    .map(|b: u8| format!("{b:02x}"))
                                    .join(":"),
                                vdc.ifaces[*iface_idx],
                            );

                            // wait until we observe the changed FW state
                            let tcpdump = ssh.execute_cmd_stdout(&[&format!(
                                "sudo tcpdump -eln -i enp130s0f1 -c1 ether src {} and src {} and dst 100.0.0.1 2>/dev/null",
                                vdc.ifaces[*iface_idx]
                                    .mac
                                    .map(|b: u8| format!("{b:02x}"))
                                    .join(":"),
                                &prober_iface.2,
                            )])
                            .await?;
                            log::trace!("[analyzer] tcpdump of first DP-packet\n{tcpdump}");
                        }
                    }
                }
            }
        }

        lab.wait_for_no_bgp_messages(Duration::from_secs(2)).await?;

        // stop traffic monitor
        let _ = lab.stop_traffic_monitor(traffic_monitor_handle).await?;

        // stop prober traffic and gather results
        let capture_result = lab.stop_capture(capture).await?;

        for ((rid, _, _), samples) in capture_result.iter().sorted_by(|a, b| a.0 .0.cmp(&b.0 .0)) {
            let len = samples.len();
            let total_num_samples = (samples.iter().map(|x| x.3).max().unwrap()
                - samples.iter().map(|x| x.3).min().unwrap())
                as usize
                + 1;
            println!(
                "router {:?}: found {:?}/{:?} ({:.2}%) --> violation: ~{:.2}ms",
                rid,
                len,
                total_num_samples,
                (len * 100) as f64 / total_num_samples as f64,
                (total_num_samples - len) as f64 / (capture_frequency as f64 / 1000.0)
            );
        }

        {
            let ssh = ssh.clone();
            let traffic_pcap_path = traffic_pcap_path.clone();
            let analyzer_path = analyzer_path.clone();
            analyzer_set.spawn(async move {
                log::debug!(
                    "[analyzer] processing pcap {}",
                    &traffic_pcap_path.to_string_lossy(),
                );

                let mut analyzer_output = analyzer_headers();
                analyzer_output.push_str(&match run_analyzer(
                    &ssh,
                    &analyzer_path.to_string_lossy(),
                    &traffic_pcap_path.to_string_lossy(),
                )
                .await
                {
                    Ok(x) => x,
                    Err(x) => {
                        log::debug!("Error running analyzer: {:?}", x);
                        String::from("Error running analyzer!")
                    }
                });

                let result = match evaluate_trace(analyzer_output).await {
                    Ok(x) => Some(x),
                    e => {
                        log::warn!("[analyzer] error: {e:?}");
                        None
                    }
                };

                // preemptively store progress
                ssh.execute_cmd(&[&format!("echo \"{:?}\" >> data_withdraw_e2.csv", result)])
                    .await
                    .expect("Writing process should not cause problems!");

                result
            });
        }

        log::debug!("[analyzer] Reset experiment: announcing new best route");
        lab.get_exabgp_handle().step().await?;

        lab.wait_for_no_bgp_messages(Duration::from_secs(2)).await?;

        log::debug!(
            "[analyzer] Sample taken in {} seconds.",
            now.elapsed().as_secs()
        );
    }

    lab.stop_iperf(iperf_handle).await?;

    let mut results = Vec::new();

    while let Some(Ok(output)) = analyzer_set.join_next().await {
        if let Some(result) = output {
            log::debug!("[analyzer] found times:\n{result:#?}");
            results.push(result);
        }
    }

    log::debug!(
        "[analyzer] Final results vector:\n{results:#?}\n{} successful, {} errors.",
        results.len(),
        num_samples - results.len()
    );

    // wait for one second
    tokio::time::sleep(Duration::from_secs(1)).await;

    // disconnect the network.
    let _ = lab.disconnect().await?;

    Ok(())
}

/// Computing the actual control- and data-plane reaction times from a given `analyzer_output`.
async fn evaluate_trace(analyzer_output: String) -> R<(f64, f64)> {
    log::trace!("[analyzer] event trace:\n{}", analyzer_output);

    let mut csv = Reader::from_reader(analyzer_output.as_bytes());

    let mut messages: Vec<Msg> = Vec::new();
    for record in csv.deserialize() {
        messages.push(record?);
    }

    log::trace!("[analyzer] CSV parsed: {messages:#?}");

    // find initiating message
    let e2r2_bgp = messages
        .iter()
        .find(|msg| msg.src_rid == "e2" && msg.dst_rid == "r2" && msg.msg_type == "BGP")
        .ok_or("e2 needs to send a BGP update to r2")?;

    log::trace!("[analyzer] found bgp message from e2 to r2: {e2r2_bgp:#?}");

    // find fourth occurrence of r2's BGP message to r0
    let r2r0_bgp = messages
        .iter()
        .filter(|msg| msg.timestamp >= e2r2_bgp.timestamp)
        .filter(|msg| msg.src_rid == "r2" && msg.dst_rid == "r0" && msg.msg_type == "BGP")
        .nth(3)
        .ok_or("r2 needs to send a BGP update to r0 that passes the delayer twice")?;

    log::trace!("[analyzer] found bgp message from r2 to r0: {r2r0_bgp:#?}");

    // find first occurrence of r0's response BGP message to r2
    let r0_bgp_reply = messages
        .iter()
        .filter(|msg| msg.timestamp >= r2r0_bgp.timestamp)
        .find(|msg| {
            msg.src_rid == "r0"
                && (msg.dst_rid == "r1" || msg.dst_rid == "r2" || msg.dst_rid == "e1")
                && msg.msg_type == "BGP"
        })
        .ok_or("r0 needs to send a BGP update to its peers")?;

    log::trace!("[analyzer] found bgp message from r0 to a peer: {r0_bgp_reply:#?}");

    // ensure that the network had the expected forwarding state when the BGP message arrives
    let r0r1_probe = messages
        .iter()
        .filter(|msg| msg.timestamp >= r2r0_bgp.timestamp)
        .find(|msg| msg.src_rid == "r0" && msg.dst_rid == "r1" && msg.msg_type == "PROBE")
        .ok_or("r0 should still send traffic to r1 for now")?;

    log::trace!("[analyzer] found probe message from r0 to r1: {r0r1_probe:#?}");

    // find the first prober packet being routed on the new link
    let r0e1_probe = messages
        .iter()
        .filter(|msg| msg.timestamp >= r0r1_probe.timestamp)
        .find(|msg| msg.src_rid == "r0" && msg.dst_rid == "e1" && msg.msg_type == "PROBE")
        .ok_or("r0 should send traffic to e1 now")?;

    log::trace!("[analyzer] found probe message from r0 to e1: {r0e1_probe:#?}");

    log::trace!(
        "[analyzer] cp reaction: {:.3?}ms, dp reaction: {:.3?}ms",
        (r0_bgp_reply.timestamp - r2r0_bgp.timestamp) * 1000.0,
        (r0e1_probe.timestamp - r2r0_bgp.timestamp) * 1000.0
    );
    Ok((
        (r0_bgp_reply.timestamp - r2r0_bgp.timestamp) * 1000.0,
        (r0e1_probe.timestamp - r2r0_bgp.timestamp) * 1000.0,
    ))
}
