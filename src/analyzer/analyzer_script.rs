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
//! Module for writing an analyzer script that utilizes standard linux tools `tcpdump`, `tshark`
//! and `editcap` to find specific changes in the labsetup.

use std::path::{Path, PathBuf};

use bgpsim::{export::Addressor, prelude::*};
use router_lab::{ssh::SshSession, RouterLab};

use serde::Deserialize;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Message struct for deserialization of the Analyzer's output
#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Msg {
    pub timestamp: f64,
    pub src_mac: String,
    pub dst_mac: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_rid: String,
    pub dst_rid: String,
    pub msg_type: String,
}

pub fn analyzer_headers() -> String {
    String::from("timestamp,src_mac,dst_mac,src_ip,dst_ip,src_rid,dst_rid,msg_type\n")
}

/// Build analyzer script to print all BGP update messages and the first observed message on each
/// FW choice. Returns a `std::path::PathBuf` to where the analyzer script has been written.
pub async fn write_analyzer_script<P: Prefix, Q, Ospf: OspfImpl, S>(
    lab: &RouterLab<'_, P, Q, Ospf, S>,
    net: &Network<P, Q>,
    ssh: &SshSession,
    experiment_path: &Path,
    experiment_slug: &str,
) -> R<PathBuf> {
    let mut analyzer = String::from("#!/usr/bin/bash\n");
    analyzer.push('\n');
    analyzer.push_str(&format!(
        "# Traffic trace analyzer for Experiment {experiment_slug}\n"
    ));

    analyzer.push('\n');
    analyzer.push_str("# uncompress pcap file if required\n");
    analyzer.push_str("if [ ! -f \"${1}\" ] ; then\n");
    analyzer.push_str("    gunzip \"${1}.gz\"\n");
    analyzer.push_str("fi\n");
    analyzer.push('\n');

    let mut analyzer_path = experiment_path.to_path_buf();
    analyzer_path.push(format!("analyze_{experiment_slug}.sh"));
    log::debug!(
        "[analyzer] writing analyzer script to {}",
        analyzer_path.to_string_lossy()
    );

    // packet processor setup
    let tcpdump_cmd = "tcpdump -w - 2>/dev/null";
    let tshark_cmd =
        "| tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null";
    let bgp_filter =
        "\"(port 179)\" | tshark -r - -Y \"not bgp || bgp.type != 4\" -w - 2>/dev/null";

    analyzer.push_str("\n# Pre-process the traffic capture to start with the first BGP Upate message and adjust timestamps accordingly\n");
    analyzer.push_str("# Requires wireshark v3.6 to work! Try `sudo add-apt-repository wireshark-dev/stable && sudo apt-get update && sudo apt-get install wireshark` to install\n");
    analyzer.push_str("# NOTE: this filter filters out \"TCP Retransmission\" packets on purpose to ensure that we don't end up finding a keepalive packet that had to be retransmitted!\n");
    analyzer.push_str("TIME_OFFSET=$(tcpdump -r \"${{1}}\" -w - 2>/dev/null \"(port 179)\" | tshark -r - -Y \"bgp.type != 4\" -w - 2>/dev/null | tshark -r - -c1 -T fields -e frame.time_epoch 2>/dev/null)\n");
    let tmp_pcap_path = "/tmp/tmp_${TIME_OFFSET}.pcap";
    analyzer.push_str(&format!(
        "editcap -A \"${{TIME_OFFSET}}\" -t \"-${{TIME_OFFSET}}\" \"${{1}}\" \"{tmp_pcap_path}\" \n"
    ));
    analyzer.push('\n');

    analyzer.push_str("# Find the first local prober packet to each possible next-hop:\n");
    analyzer.push_str("function get_fw_updates_from {\n");
    let offset_pcap_path = format!("\"{tmp_pcap_path}.${{1}}\"");
    analyzer.push_str(&format!(
        "editcap -A \"${{1}}\" \"{tmp_pcap_path}\" {offset_pcap_path}\n"
    ));
    // prepare `sed` expressions to append human-readable router names
    let mut display_src_router = String::new();
    let mut display_dst_router = String::new();

    for r in net.internal_routers() {
        analyzer.push_str(&format!("# Router {}\n", r.name()));
        let vdc = lab.get_router_properties(r.router_id()).unwrap();
        let ifaces = lab.addressor().list_ifaces(r.router_id());
        for (neighbor, ipv4, _, iface_idx) in ifaces.iter() {
            log::trace!(
                "[analyzer] Tracking link: {}-{}, IP: {:?}, local MAC: {}, iface: {:#?}",
                r.name(),
                neighbor.fmt(net),
                ipv4,
                vdc.ifaces[*iface_idx]
                    .mac
                    .map(|b: u8| format!("{b:02x}"))
                    .join(":"),
                vdc.ifaces[*iface_idx],
            );
            // interface details
            analyzer.push_str(&format!(
                "# local iface {iface_idx}: MAC({}) IP({ipv4})\n",
                vdc.ifaces[*iface_idx]
                    .mac
                    .map(|b: u8| format!("{b:02x}"))
                    .join(":"),
            ));
            // tcpdump command
            if let Some(prober_iface) = lab.get_prober_ifaces().get(&r.router_id()) {
                analyzer.push_str(&format!(
                "{tcpdump_cmd} -r {offset_pcap_path} \"(ether src {} and src {} and dst 100.0.0.1)\" {tshark_cmd} -c1 | sed -e \"s/$/,{},{},PROBE/\"\n",
                &vdc.ifaces[*iface_idx]
                    .mac
                    .map(|b: u8| format!("{b:02x}"))
                    .join(":"),
                &prober_iface.2,
                // add human-readable output
                r.name(),
                neighbor.fmt(net),
            ));
            } else {
                log::warn!("[analyzer] could not find prober_iface for {}", r.name());
                analyzer.push_str(&format!("# could not find prober_iface for {}", r.name()));
                log::debug!("[analyzer] prober_ifaces: {:#?}", lab.get_prober_ifaces());
            }
            if net.external_routers().any(|n| n.router_id() == *neighbor) {
                let ext_ipv4 = lab
                    .addressor()
                    .try_get_iface_address(*neighbor, r.router_id())
                    .expect("Interface should exist!")?;
                log::trace!(
                    "[analyzer] neighbor: {}, ip: {}",
                    neighbor.fmt(net),
                    ext_ipv4
                );

                display_src_router.push_str(&format!(" | sed -e \"s/\\({}\\),\\([^,.]\\+\\.[^,.]\\+\\.[^,.]\\+\\.[^,.]\\+\\),,\\([^,]*\\)$/\\1,\\2,{},\\3/\"",
                    format!("{}", ipv4).replace('.', "\\."),
                    r.name(),
                ));
                display_src_router.push_str(&format!(" | sed -e \"s/\\({}\\),\\([^,.]\\+\\.[^,.]\\+\\.[^,.]\\+\\.[^,.]\\+\\),,\\([^,]*\\)$/\\1,\\2,{},\\3/\"",
                    format!("{}", ext_ipv4).replace('.', "\\."),
                    neighbor.fmt(net),
                ));
                display_dst_router.push_str(&format!(
                    " | sed -e \"s/\\({}\\),\\([^,]*\\),$/\\1,\\2,{}/\"",
                    format!("{}", ipv4).replace('.', "\\."),
                    r.name(),
                ));
                display_dst_router.push_str(&format!(
                    " | sed -e \"s/\\({}\\),\\([^,]*\\),$/\\1,\\2,{}/\"",
                    format!("{}", ext_ipv4).replace('.', "\\."),
                    neighbor.fmt(net),
                ));
            }
        }

        let local_ipv4 = format!(
            "{}",
            lab.addressor()
                .try_get_router_address(r.router_id())
                .expect("Router should exist")
        );
        display_src_router.push_str(&format!(" | sed -e \"s/\\({}\\),\\([^,.]\\+\\.[^,.]\\+\\.[^,.]\\+\\.[^,.]\\+\\),,\\([^,]*\\)$/\\1,\\2,{},\\3/\"",
            local_ipv4.replace('.', "\\."),
            r.name(),
        ));
        display_dst_router.push_str(&format!(
            " | sed -e \"s/\\({}\\),\\([^,]*\\),$/\\1,\\2,{}/\"",
            local_ipv4.replace('.', "\\."),
            r.name(),
        ));
    }
    analyzer.push_str("# cleanup tmp dir\n");
    analyzer.push_str(&format!("rm -f {offset_pcap_path}\n"));
    analyzer.push_str("} # end function get_fw_updates_from\n");
    analyzer.push('\n');
    analyzer.push_str("# make sure to collect all relevant data-plane updates\n");
    analyzer.push_str(&format!("for time in $({tcpdump_cmd} -r \"{tmp_pcap_path}\" {bgp_filter} | tshark -r - -T fields -e frame.time_epoch 2>/dev/null); do\n"));
    analyzer.push_str("    get_fw_updates_from \"${time}\"\n");
    analyzer.push_str("done\n");
    analyzer.push('\n');

    analyzer.push_str("# BGP trace:\n");
    // tcpdump command and append two commas
    analyzer.push_str(&format!(
        "{tcpdump_cmd} -r \"{tmp_pcap_path}\" {bgp_filter} {tshark_cmd} | sed -e \"s/$/,,/\" {display_src_router} {display_dst_router} | sed -e \"s/$/,BGP/\"\n"
    ));
    analyzer.push('\n');
    analyzer.push_str("# cleanup tmp dir\n");
    analyzer.push_str(&format!("rm \"{tmp_pcap_path}\"\n"));
    analyzer.push('\n');
    analyzer.push_str("# compress pcap file to save disk space\n");
    analyzer.push_str("gzip \"${1}\"\n");

    log::trace!(
        "[analyzer] Writing file: {}\n{}",
        analyzer_path.to_string_lossy(),
        analyzer
    );

    ssh.write_file(&analyzer_path.to_string_lossy(), analyzer)
        .await?;
    Ok(analyzer_path)
}

pub async fn run_analyzer(ssh: &SshSession, analyzer_path: &str, pcap_path: &str) -> R<String> {
    Ok(ssh
        .execute_cmd_stdout(&["bash", analyzer_path, pcap_path, "| sort | uniq"])
        .await?)
}
