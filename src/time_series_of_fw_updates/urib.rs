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
//! Extract the time series of forwarding state udpate from the urib log.

use std::{
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
    path::Path,
};

use trix::{
    analyzer::{
        urib_log_parser::{UribKind, UribRecord},
        CiscoAnalyzerData,
    },
    prelude::{Analyzer, TimingModel},
    records::FWRecord,
};
use bgpsim::{prelude::SimplePrefix, types::RouterId};
use itertools::Itertools;

use super::{Lut, ParseableRecord, TransformParseableRecord, UpdateKind};

const MIN_DELTA: f64 = 0.0001;

impl ParseableRecord for UribRecord {
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
            UribKind::Add => Some(UpdateKind::Add),
            UribKind::Delete => Some(UpdateKind::Del),
            UribKind::Modify => None,
        }
    }

    fn ospf_next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hop
    }
}

pub(crate) fn process_sample(
    analyzer: &Analyzer<TimingModel<SimplePrefix>>,
    metadata: &CiscoAnalyzerData,
    eval_path: &Path,
    lut: &Lut,
    replace: bool,
) -> Result<bool, super::Error> {
    let mut filename = eval_path.to_path_buf();
    filename.push(format!("urib_log_{}.csv", metadata.execution_timestamp));
    if !filename.exists() {
        log::warn!(
            "URIB log doesn't exist! Skipping this sample. Path: {}",
            filename.as_os_str().to_string_lossy()
        );
        return Ok(false);
    }

    let mut out_filename = eval_path.to_path_buf();
    out_filename.push(format!(
        "time_series_of_forwarding_states_{}",
        metadata.execution_timestamp
    ));
    std::fs::create_dir_all(&out_filename)?;
    out_filename.push("urib.csv");

    if out_filename.exists() && !replace {
        return Ok(false);
    }

    let initial_state = |(router, prefix)| {
        let prefix = SimplePrefix::from(prefix);
        let nhs = analyzer.original_fw.get_next_hops(router, prefix);
        if nhs.is_empty() {
            Ok(None)
        } else if nhs.len() == 1 {
            Ok(Some(nhs[0]))
        } else {
            Err(super::Error::MultipleNextHops(router, nhs.to_vec()))
        }
    };

    let mut sequence: HashMap<(RouterId, Ipv4Addr), Vec<FWRecord>> = HashMap::new();

    for record in csv::Reader::from_path(&filename)?.into_deserialize() {
        let record: UribRecord = record?;

        // transform the record
        let Some(record) = record.transform(lut, metadata)? else {
            continue;
        };

        let key = (record.src, record.prefix);

        // create the initial sequence if necessary
        if let Entry::Vacant(e) = sequence.entry(key) {
            let next_hop = initial_state(key)?;
            let next_hop_name = next_hop.and_then(|r| lut.name(r));
            e.insert(vec![FWRecord {
                time: 0.0,
                src: record.src,
                src_name: record.src_name,
                prefix: record.prefix,
                seq: None,
                next_hop,
                next_hop_name,
            }]);
        }

        let seq = sequence.get_mut(&key).unwrap();
        let last_record = seq.last().unwrap();

        // skip if the last record is equal to the current one
        if last_record.next_hop == record.next_hop {
            continue;
        }

        // only add the new record if the difference to the last is at least MIN_DELTA
        if last_record.time + MIN_DELTA < record.time {
            // record is more than MIN_DELTA newer than the last one.
            seq.push(record);
        } else {
            // This record is only MIN_DELTA newer than the last one.
            // If record has a next-hop, then only keep the newer one.
            // Otherwise, ignore the `record`.
            if record.next_hop.is_some() {
                seq.pop();
                seq.push(record);
            }
        }
    }

    // flatten the entire array, and then sort it.
    let mut trace = sequence
        .into_values()
        .flat_map(|rs| rs.into_iter().skip(1))
        .collect_vec();
    trace.sort_by(|a, b| a.time.total_cmp(&b.time));

    // store the file
    let mut writer = csv::Writer::from_path(&out_filename)?;
    for record in trace {
        writer.serialize(record)?
    }

    log::info!(
        "Stored FW updates from URIB ({})",
        out_filename.as_os_str().to_string_lossy()
    );

    Ok(true)
}
