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
//! Extract the time series of forwarding state udpate from the ufdm log.

use std::{
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
    path::Path,
};

use trix::analyzer::{
    ufdm_log_parser::{UfdmKind, UfdmRecord},
    CiscoAnalyzerData,
};
use bgpsim::types::RouterId;

use super::{Lut, ParseableRecord, TransformParseableRecord, UpdateKind};

impl ParseableRecord for UfdmRecord {
    fn time(&self) -> f64 {
        self.time
    }

    fn router(&self) -> RouterId {
        self.rid
    }

    fn addr(&self) -> Option<std::net::Ipv4Addr> {
        Some(self.prefix.network())
    }

    fn kind(&self) -> Option<UpdateKind> {
        match self.kind {
            UfdmKind::Add => Some(UpdateKind::Add),
            UfdmKind::Del => Some(UpdateKind::Del),
        }
    }

    fn ospf_next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hop
    }
}

pub(crate) fn process_sample(
    metadata: &CiscoAnalyzerData,
    eval_path: &Path,
    lut: &Lut,
    replace: bool,
) -> Result<bool, super::Error> {
    let mut filename = eval_path.to_path_buf();
    filename.push(format!("ufdm_log_{}.csv", metadata.execution_timestamp));
    if !filename.exists() {
        log::warn!(
            "UFDM log doesn't exist! Skipping this sample. Path: {}",
            filename.as_os_str().to_string_lossy()
        );
        return Ok(false);
    }

    // open the writer
    let mut out_filename = eval_path.to_path_buf();
    out_filename.push(format!(
        "time_series_of_forwarding_states_{}",
        metadata.execution_timestamp
    ));
    std::fs::create_dir_all(&out_filename)?;
    out_filename.push("ufdm.csv");

    if out_filename.exists() && !replace {
        return Ok(false);
    }

    let mut writer = csv::Writer::from_path(&out_filename)?;

    let mut last: HashMap<(RouterId, Ipv4Addr), Option<RouterId>> = HashMap::new();

    for record in csv::Reader::from_path(&filename)?.into_deserialize() {
        let record: UfdmRecord = record?;

        // transform the record
        let Some(record) = record.transform(lut, metadata)? else {
            continue;
        };

        let key = (record.src, record.prefix);
        // check if the next-hop is equal to the last
        match last.entry(key) {
            Entry::Occupied(mut e) => {
                if e.get() == &record.next_hop {
                    continue;
                }
                e.insert(record.next_hop);
            }
            Entry::Vacant(e) => {
                e.insert(record.next_hop);
            }
        }

        // write to the output
        writer.serialize(record)?;
    }

    log::info!(
        "Stored FW updates from UFDM ({})",
        out_filename.as_os_str().to_string_lossy()
    );

    Ok(true)
}
