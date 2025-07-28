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
use std::{net::Ipv4Addr, path::Path};

use itertools::Itertools;

use bgpsim::types::RouterId;

use trix::{
    analyzer::CiscoAnalyzerData,
    prelude::{Analyzer, Prefix, TimingModel},
    records::FWRecord,
    FwUpdate,
};

use super::{Error, Lut, ParseableRecord, TransformParseableRecord, UpdateKind};

//pub type FwUpdate = (Vec<FwDelta>, AlwaysEq<Option<f64>>);
#[allow(unused)]
struct SimModelRecord {
    prefix: Prefix,
    router: RouterId,
    old_nh: Option<RouterId>,
    new_nh: Option<RouterId>,
    time: f64,
}

impl From<(Prefix, FwUpdate)> for SimModelRecord {
    fn from((prefix, fw_update): (Prefix, FwUpdate)) -> Self {
        let fw_delta = &fw_update.0[0];
        Self {
            prefix,
            router: fw_delta.0,
            old_nh: fw_delta.1.first().copied(),
            new_nh: fw_delta.2.first().copied(),
            time: fw_update.1.into_inner().unwrap(),
        }
    }
}

impl ParseableRecord<Prefix, RouterId> for SimModelRecord {
    fn time(&self) -> f64 {
        self.time
    }

    fn router(&self) -> RouterId {
        self.router
    }

    fn addr(&self) -> Option<Prefix> {
        Some(self.prefix)
    }

    fn kind(&self) -> Option<UpdateKind> {
        self.new_nh
            .map(|_| UpdateKind::Add)
            .or(Some(UpdateKind::Del))
    }

    fn ospf_next_hop(&self) -> Option<RouterId> {
        self.new_nh
    }
}

impl TransformParseableRecord for SimModelRecord {
    /// Return the own router-id, as the next-hop is not known yet!
    fn next_hop(&self, _lut: &Lut) -> Result<Option<RouterId>, Error> {
        Ok(self.new_nh)
    }

    /// Transform the record into an FWRecord. This function will return `None` if the specific
    /// record must be ignored.
    ///
    /// This function calls `next_hop`.
    fn transform(
        &self,
        lut: &Lut,
        metadata: &CiscoAnalyzerData,
    ) -> Result<Option<FWRecord>, Error> {
        // skip all records that don't add or delete.
        if self.kind().is_none() {
            return Ok(None);
        }
        let Some(addr) = self.addr() else {
            return Err(Error::InconsistentData(
                "No IP address for record that is either an Add or a Delete",
            ));
        };
        // normalize address
        let prefix = Ipv4Addr::from(addr);

        // skip if the event was before the official start time
        if self.time() < metadata.event_start - 1.0 {
            return Ok(None);
        }

        let next_hop = self.next_hop(lut)?;

        // record is valid. Transform it.
        Ok(Some(FWRecord {
            time: self.time(),
            src: self.router(),
            src_name: lut.name(self.router()),
            prefix,
            seq: None,
            next_hop,
            next_hop_name: next_hop.and_then(|r| lut.name(r)),
        }))
    }
}

#[allow(dead_code)]
pub(crate) fn process_sample(
    analyzer: &Analyzer<TimingModel<Prefix>>,
    metadata: &CiscoAnalyzerData,
    eval_path: &Path,
    lut: &super::Lut,
    replace: bool,
) -> Result<bool, Error> {
    // open the writer
    let mut out_filename = eval_path.to_path_buf();
    out_filename.push(format!(
        "time_series_of_forwarding_states_{}",
        metadata.execution_timestamp
    ));
    std::fs::create_dir_all(&out_filename)?;
    out_filename.push("bgpsim.csv");

    if out_filename.exists() && !replace {
        return Ok(false);
    }

    let mut writer = csv::Writer::from_path(&out_filename)?;
    let mut sim_records = Vec::new();

    // do the simulation
    let mut analyzer = analyzer.clone();
    analyzer.time_offset = -1.0 * metadata.event_start;
    let mut net = analyzer.scheduled_net.clone();
    let trace = analyzer.build_trace(&mut net);

    for (prefix, prefix_trace) in trace {
        for fw_update in prefix_trace {
            let Some(record) =
                SimModelRecord::from((prefix, fw_update)).transform(lut, metadata)?
            else {
                continue;
            };
            sim_records.push(record);
        }
    }

    // sort updates and write them to the csv
    for record in sim_records
        .into_iter()
        .sorted_by(|a, b| a.time.total_cmp(&b.time))
    {
        writer.serialize(record)?;
    }
    writer.flush()?;

    log::info!(
        "Stored FW updates from BGPsim model ({})",
        out_filename.as_os_str().to_string_lossy()
    );

    Ok(true)
}
