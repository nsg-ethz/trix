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
//! Module to apply the fib delay filter to all fw records

use std::path::Path;

use trix::{
    analyzer::CiscoAnalyzerData,
    fib_queuing::{FibQueuingModel, NX9K, NX9K_ASYMMETRIC},
    util::PathBufExt,
};

pub fn process_fw_records(
    metadata: &CiscoAnalyzerData,
    eval_path: impl AsRef<Path>,
    replace: bool,
) -> Result<bool, csv::Error> {
    let mut changed = false;
    let ts = &metadata.execution_timestamp;
    let root = eval_path
        .as_ref()
        .then_ts("time_series_of_forwarding_states_{}", ts);
    for file_type in [
        "bgp_messages",
        "bgp_log",
        "ipfib",
        "ufdm",
        "urib",
        //"bgpsim",
    ] {
        let src = root.clone().then(format!("{}.csv", file_type));
        if !src.exists() {
            log::trace!(
                "FW record for {file_type} doesn't exist. Path: {}",
                src.as_os_str().to_string_lossy()
            );
            continue;
        }
        for model in [NX9K, NX9K_ASYMMETRIC] {
            let dst = root.clone().then(format!("{file_type}_{model}.csv"));
            if dst.exists() && !replace {
                continue;
            }
            process_fw_record(&src, &dst, model)?;
            changed = true;
            log::info!(
                "Transformed {file_type} by {model}: {}",
                dst.as_os_str().to_string_lossy()
            );
        }
    }
    Ok(changed)
}

pub fn process_fw_record(
    src: impl AsRef<Path>,
    dst: impl AsRef<Path>,
    model: FibQueuingModel,
) -> Result<(), csv::Error> {
    let mut writer = csv::Writer::from_path(dst.as_ref())?;
    let mut parsed = model
        .apply(csv::Reader::from_path(src.as_ref())?.into_deserialize())
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort_by(|a, b| a.time.total_cmp(&b.time));

    parsed
        .into_iter()
        .map(|fw| writer.serialize(fw))
        .collect::<Result<Vec<_>, _>>()
        .map(|_| ())
}
