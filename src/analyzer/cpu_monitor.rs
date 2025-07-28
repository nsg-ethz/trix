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
//! Enables a CPU monitor on the cisco routers, tracking their load throughout experiments.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};

use itertools::Itertools;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Child,
};

use bgpsim::prelude::*;
use router_lab::{ssh::SshSession, RouterLab};

use crate::{records::CpuRecord, Prefix};

const CPU_MONITOR_FILE: &str = ".router_lab_cpu_monitor.py";
const CPU_MONITOR_CONTROL_FILE: &str = ".router_lab_cpu_monitor_control";

async fn control_monitoring(
    ssh_name: impl AsRef<str>,
    enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = SshSession::new(ssh_name.as_ref())
        .await?
        .command(format!(
            "run bash echo {} > {CPU_MONITOR_CONTROL_FILE}",
            enabled as i32
        ))
        .output()
        .await?;

    Ok(())
}

/// Transfer the cpu monitor script to all routers, initialize control file and start the
/// monitoring processes.
pub async fn setup_cpu_monitoring<Q, Ospf: OspfImpl, S>(
    net: &Network<Prefix, Q>,
    lab: &RouterLab<'_, Prefix, Q, Ospf, S>,
) -> Result<HashMap<RouterId, Child>, Box<dyn std::error::Error>> {
    let mut monitors = HashMap::new();

    for (rid, (router_properties, _)) in lab.routers() {
        // create the control file and disable the monitoring
        control_monitoring(&router_properties.ssh_name, false).await?;

        // transfer the cpu monitoring file and start the process
        // cat ../../cpu-monitor.py | ssh -T cisco-nexus1 "run bash cat > {FILE}"
        let session = SshSession::new(&router_properties.ssh_name).await?;
        let mut transfer = session
            .command("-T")
            .arg(format!("run bash cat > {CPU_MONITOR_FILE}"))
            .stdin(Stdio::piped())
            .spawn()?;
        transfer
            .stdin
            .take()
            .unwrap()
            .write_all(include_str!("../../cpu-monitor.py").as_bytes())
            .await?;
        transfer.wait().await?;

        // ssh cisco-nexus1 "run bash python3 cpu-monitor.py --std-out --router-id X --router-name Y"
        let child = session
            .command(format!(
                "run bash python3 {CPU_MONITOR_FILE} --control-file {CPU_MONITOR_CONTROL_FILE} --interval 0.1 --std-out --router-id {} --router-name {}",
                rid.index(),
                rid.fmt(net),
            ))
            .stdout(Stdio::piped())
            .spawn()?;

        monitors.insert(*rid, child);
    }

    Ok(monitors)
}

/// Start the extended monitoring processes. Has to be called after `setup_cpu_monitoring`. Will
/// automatically stop once `stop_cpu_monitoring` has been called, but should be `.await?`ed
/// nonetheless.
pub async fn setup_extended_cpu_monitoring<Q, Ospf: OspfImpl, S>(
    net: &Network<Prefix, Q>,
    lab: &RouterLab<'_, Prefix, Q, Ospf, S>,
    output_dir: impl AsRef<Path>,
) -> Result<HashMap<RouterId, Child>, Box<dyn std::error::Error>> {
    let output_dir = output_dir.as_ref();
    std::fs::create_dir_all(output_dir)?;
    let mut monitors = HashMap::new();

    for (rid, (router_properties, _)) in lab.routers() {
        let session = SshSession::new(&router_properties.ssh_name).await?;
        // ssh cisco-nexus1 "run bash python3 cpu-monitor.py --std-out --router-id X --router-name Y"
        let mut output_path = output_dir.to_path_buf();
        output_path.push(format!("{}.csv", rid.fmt(net)));

        let child = session
            .command(format!(
                "run bash python3 {CPU_MONITOR_FILE} --control-file {CPU_MONITOR_CONTROL_FILE} --interval 0.001 --std-out --router-id {} --router-name {} --all-processes",
                rid.index(),
                rid.fmt(net),
            ))
            .stdout(fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&output_path)
                    .unwrap()
                )
            .spawn()?;

        monitors.insert(*rid, child);
    }

    Ok(monitors)
}

/// Activate the (running) monitoring processes. Requires that `setup_cpu_monitoring` has
/// successfully been called previously.
pub async fn start_cpu_monitoring<Q, Ospf: OspfImpl, S>(
    lab: &RouterLab<'_, Prefix, Q, Ospf, S>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (router_properties, _) in lab.routers().values() {
        // start the monitoring
        control_monitoring(&router_properties.ssh_name, true).await?;
    }
    Ok(())
}

/// Stop the ongoing CPU monitoring and collects all data into a single csv file.
pub async fn stop_cpu_monitoring<Q, Ospf: OspfImpl, S>(
    lab: &RouterLab<'_, Prefix, Q, Ospf, S>,
    monitors: HashMap<RouterId, Child>,
    output_path: impl AsRef<Path>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut records = Vec::new();

    // stop the monitoring, capture the outputs into a buffer, and combine all records into a Vec
    for (rid, mut child) in monitors.into_iter() {
        // disable the monitoring
        control_monitoring(&lab.routers().get(&rid).unwrap().0.ssh_name, false).await?;

        let mut buffer = Vec::new();
        let mut stdout = child.stdout.take().unwrap();
        stdout.read_to_end(&mut buffer).await?;

        // deserialize into records vec
        let mut csv = csv::Reader::from_reader(buffer.as_slice());
        for record in csv.deserialize() {
            let record: CpuRecord = record.unwrap();
            records.push(record);
        }
    }

    // sort & write combined csv
    let output_path = output_path.as_ref().to_path_buf();
    let mut csv = csv::WriterBuilder::new().has_headers(true).from_writer(
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_path)
            .unwrap(),
    );
    for record in records
        .into_iter()
        .sorted_by(|a, b| a.timestamp.total_cmp(&b.timestamp))
    {
        csv.serialize(record).unwrap();
    }
    csv.flush().unwrap();

    Ok(output_path)
}
