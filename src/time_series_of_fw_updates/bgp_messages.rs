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

use std::path::Path;

use itertools::Itertools;
use ordered_float::NotNan;

use trix::{
    analyzer::CiscoAnalyzerData,
    prelude::{Analyzer, TimingModel},
    records::{FWRecord, Record},
};
use bgpsim::{
    bgp::{BgpEvent, BgpRoute},
    event::Event,
    interactive::InteractiveNetwork,
    types::{AsId, NetworkDeviceRef, SimplePrefix, StepUpdate},
};

use super::{is_event_prefix, Error, Lut};

pub(crate) fn process_sample(
    analyzer: &Analyzer<TimingModel<SimplePrefix>>,
    metadata: &CiscoAnalyzerData,
    eval_path: &Path,
    lut: &Lut,
    replace: bool,
) -> Result<bool, Error> {
    let mut filename = eval_path.to_path_buf();
    filename.push(format!("bgp_updates_{}.skip", metadata.pcap_filename));
    if filename.exists() {
        log::trace!(
            "Skipping BGP messages, as there were errors in the pipeline. Path: {}",
            filename.as_os_str().to_string_lossy()
        );
        return Ok(false);
    }
    filename.pop();
    filename.push(format!("bgp_updates_{}.csv", metadata.pcap_filename));
    if !filename.exists() {
        log::warn!(
            "BGP updates trace doesn't exist! Skipping this sample. Path: {}",
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
    out_filename.push("bgp_messages.csv");

    if out_filename.exists() && !replace {
        return Ok(false);
    }

    let mut writer = csv::Writer::from_path(&out_filename)?;
    let mut bgp_messages = Vec::new();

    let mut net = analyzer.original_net.clone();

    for record in csv::ReaderBuilder::new()
        .delimiter(b';')
        .from_path(&filename)?
        .into_deserialize()
    {
        let record: Record = record?;

        // skip records that are too old
        if record.time < metadata.event_start - 1.0 {
            continue;
        }

        let (Some(src), Some(dst)) = (record.src, record.dst) else {
            continue;
        };

        let p: NotNan<f64> = Default::default();
        let asid = match net.get_device(src)? {
            NetworkDeviceRef::InternalRouter(_) => AsId::from(100),
            NetworkDeviceRef::ExternalRouter(e) => e.as_id(),
        };

        // extract all next_hops and get the corresponding router id
        let next_hop = match record.next_hop {
            Some(x) => lut.rid(x)?,
            None if record.reach.is_empty() => 0.into(),
            None => {
                log::info!("Problematic record: {record:#?}");
                return Err(Error::InconsistentData(
                    "Got no next-hop on a BGP update message that announces prefixes",
                ));
            }
        };
        let as_path_len = match record.path_length {
            Some(x) => x,
            None if record.reach.is_empty() => 0,
            None => {
                log::info!("Problematic record: {record:#?}");
                return Err(Error::InconsistentData(
                    "Got no AS path length on a BGP update message that announces prefixes",
                ));
            }
        };

        // generate all events
        let withdraw_events = record
            .unreach
            .into_iter()
            .filter(is_event_prefix)
            .map(SimplePrefix::from)
            .map(BgpEvent::Withdraw)
            .map(|e| Event::Bgp { p, src, dst, e });
        let update_events = record
            .reach
            .into_iter()
            .filter(is_event_prefix)
            .map(|prefix| BgpRoute {
                prefix: SimplePrefix::from(prefix),
                as_path: vec![asid; as_path_len],
                next_hop,
                local_pref: Some(100),
                med: None,
                community: Default::default(),
                originator_id: Default::default(),
                cluster_list: Default::default(),
            })
            .map(BgpEvent::Update)
            .map(|e| Event::Bgp { p, src, dst, e });

        let events = withdraw_events.chain(update_events).collect::<Vec<_>>();

        for event in events {
            let (step_update, _) = unsafe { net.trigger_event(event)? };
            match step_update {
                StepUpdate::Unchanged => {} // nothing to do
                StepUpdate::Single(fw_delta) if fw_delta.new.len() > 1 => {
                    return Err(Error::MultipleNextHops(src, fw_delta.new))
                }
                StepUpdate::Single(fw_delta) => {
                    let next_hop = fw_delta.new.first().copied();
                    let new_record = FWRecord {
                        time: record.time,
                        src: dst,
                        src_name: record.dst_name,
                        prefix: fw_delta.prefix.into(),
                        seq: None,
                        next_hop,
                        next_hop_name: next_hop.and_then(|r| lut.name(r)),
                    };
                    bgp_messages.push(new_record);
                }
                StepUpdate::Multiple => {
                    return Err(Error::InconsistentData(
                        "BGP Update caused multiple next-hops to change",
                    ))
                }
            }
        }
    }

    // sort updates and write them to the csv
    for record in bgp_messages
        .into_iter()
        .sorted_by(|a, b| a.time.total_cmp(&b.time))
    {
        writer.serialize(record)?;
    }
    writer.flush()?;

    log::info!(
        "Stored FW updates from BGP messages ({})",
        out_filename.as_os_str().to_string_lossy()
    );

    Ok(true)
}
