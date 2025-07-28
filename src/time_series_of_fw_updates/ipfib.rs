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
//! Extract the time series of forwarding state udpate from the IPFIB log, including information
//! from the UFIB.

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::Path,
};

use bgpsim::types::{RouterId, SimplePrefix};

use trix::{
    analyzer::{
        ipfib_log_parser::{IpfibRecord, IpfibRecordKind},
        CiscoAnalyzerData,
    },
    records::{FWRecord, Router},
};

use super::{is_event_prefix, Error, Lut, ParseableRecord, TransformParseableRecord, UpdateKind};

/// Special record that always returns no next-hop.
impl ParseableRecord<Ipv4Addr, RouterId> for IpfibRecord {
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
            IpfibRecordKind::Add(_) => Some(UpdateKind::Add),
            IpfibRecordKind::Del => Some(UpdateKind::Del),
        }
    }

    /// Next-hop is not known yet!
    fn ospf_next_hop(&self) -> Option<RouterId> {
        None
    }
}

impl TransformParseableRecord for IpfibRecord {
    /// Return the own router-id, as the next-hop is not known yet!
    fn next_hop(&self, _lut: &Lut) -> Result<Option<RouterId>, Error> {
        Ok(match self.kind {
            IpfibRecordKind::Add(_) => Some(self.rid),
            IpfibRecordKind::Del => None,
        })
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
        // skip if the prefix doesn't start with at least 100
        if !is_event_prefix(&addr) {
            return Ok(None);
        }
        // normalize address
        let prefix = Ipv4Addr::from(SimplePrefix::from(addr));

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

type UfdmUpdate = (f64, Option<RouterId>, Option<Router>);

#[derive(Debug)]
enum IpfibOrUfdm {
    Ipfib(FWRecord),
    Ufdm(f64, Option<RouterId>, Option<Router>),
}

impl IpfibOrUfdm {
    fn time(&self) -> f64 {
        match self {
            IpfibOrUfdm::Ipfib(r) => r.time,
            IpfibOrUfdm::Ufdm(t, _, _) => *t,
        }
    }
}

impl std::fmt::Display for IpfibOrUfdm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfibOrUfdm::Ipfib(r) => write!(f, "Ipfib({})", r.time),
            IpfibOrUfdm::Ufdm(t, _, _) => write!(f, "Ufdm({t})"),
        }
    }
}

/// Extract the sequence of forwarding states from the IPFIB and UFDM log. We use the following
/// algorithm:
///
/// - Iterate over both logs simultaneously. Both logs are sorted by time, so we always take the one
///   that is more recent.
/// - For each UFDM log entry, we remember the resulting FWRecord for that router and prefix. This
///   may overwrite the last entry if there are multiple UFDM updates that occur without any IPFIB
///   update in between.
/// - For each IPFIB log entry, we get the most recent UFDM entry and take the forwarding from that
///   one. In the process, we remove that update from the most recent updates.
/// - The algorithm fails if there are multiple IPFIB updates without an UFDM update in between. If
///   that happens, we no longer know which next-hop this IPFIB update corresponds to.
pub(crate) fn process_sample(
    metadata: &CiscoAnalyzerData,
    eval_path: &Path,
    lut: &Lut,
    replace: bool,
) -> Result<bool, Error> {
    let mut ipfib_filename = eval_path.to_path_buf();
    ipfib_filename.push(format!("ipfib_log_{}.csv", metadata.execution_timestamp));
    let mut ufdm_filename = eval_path.to_path_buf();
    ufdm_filename.push(format!(
        "time_series_of_forwarding_states_{}",
        metadata.execution_timestamp
    ));
    ufdm_filename.push("ufdm.csv");
    if !ipfib_filename.exists() {
        log::warn!(
            "IPFIB log doesn't exist! Skipping this sample. Path: {}",
            ipfib_filename.as_os_str().to_string_lossy()
        );
        return Ok(false);
    }
    if !ufdm_filename.exists() {
        log::warn!(
            "UFDM fw update time series doesn't exist! Skipping this sample. Path: {}",
            ufdm_filename.as_os_str().to_string_lossy()
        );
        return Ok(false);
    }

    // store the file
    let mut out_filename = eval_path.to_path_buf();
    out_filename.push(format!(
        "time_series_of_forwarding_states_{}",
        metadata.execution_timestamp
    ));
    std::fs::create_dir_all(&out_filename)?;
    out_filename.push("ipfib.csv");

    if out_filename.exists() && !replace {
        return Ok(false);
    }

    let mut sequences: HashMap<(Router, Ipv4Addr), (Vec<FWRecord>, Vec<UfdmUpdate>)> =
        HashMap::new();

    // read all ufdm entries and transform them to FWRecords
    for r in csv::Reader::from_path(&ufdm_filename)?.into_deserialize() {
        let r: FWRecord = r?;
        sequences
            .entry((r.src_name.unwrap(), r.prefix))
            .or_default()
            .1
            .push((r.time, r.next_hop, r.next_hop_name));
    }

    // read all ipfib entries and transform them to FWRecords
    for r in csv::Reader::from_path(&ipfib_filename)?.into_deserialize() {
        let record: IpfibRecord = r?;
        let Some(r) = record.transform(lut, metadata)? else {
            continue;
        };
        sequences
            .entry((r.src_name.unwrap(), r.prefix))
            .or_default()
            .0
            .push(r);
    }

    let mut ignored_prefixes = HashSet::new();
    let mut result = Vec::<FWRecord>::new();

    for ((router, prefix), (ipfib, ufdm)) in sequences {
        if ignored_prefixes.contains(&prefix) {
            continue;
        }
        // events is the current ordering of the events, as seen by the system.
        let mut events = ipfib
            .into_iter()
            .map(IpfibOrUfdm::Ipfib)
            .chain(
                ufdm.into_iter()
                    .map(|(t, nh, nh_name)| IpfibOrUfdm::Ufdm(t, nh, nh_name)),
            )
            .collect::<Vec<_>>();
        events.sort_by(|a, b| a.time().total_cmp(&b.time()));

        loop {
            match try_get_ipfib_sequence(&events) {
                Ok(r) => {
                    result.extend(r);
                    break;
                }
                Err(Some((a, b))) => {
                    log::trace!(
                        "{router}, {prefix}: swapping {} and {}",
                        events[a],
                        events[b]
                    );
                    events.swap(a, b);
                }
                Err(None) => {
                    ignored_prefixes.insert(prefix);
                    break;
                }
            }
        }
    }

    if !ignored_prefixes.is_empty() {
        log::error!(
            "Ignoring {} prefixes, as theu could not be matched!\nHere are the first 10 prefixes: {:?}",
            ignored_prefixes.len(),
            ignored_prefixes.iter().take(10).collect::<Vec<_>>(),
        );
    }

    // sort the sequences
    result.sort_by(|a, b| a.time.total_cmp(&b.time));

    let mut writer = csv::Writer::from_path(&out_filename)?;
    for r in result {
        if ignored_prefixes.contains(&r.prefix) {
            // ignore those
            continue;
        }
        writer.serialize(r)?;
    }

    log::info!(
        "Stored FW updates from BGP prefixes ({})",
        out_filename.as_os_str().to_string_lossy()
    );

    Ok(true)
}

fn try_get_ipfib_sequence(seq: &[IpfibOrUfdm]) -> Result<Vec<FWRecord>, Option<(usize, usize)>> {
    // nh is the current next-hop.
    let mut nh: Option<(Option<RouterId>, Option<Router>, usize)> = None;
    let mut result = Vec::new();

    for (i, r) in seq.iter().enumerate() {
        match r {
            IpfibOrUfdm::Ipfib(r) => {
                let Some((nh, nh_name, ufdm_idx)) = nh.take() else {
                    return Err(None);
                };
                // check if the update agres with the nh
                if r.next_hop.is_some() != nh.is_some() {
                    return Err(Some((i, ufdm_idx)));
                }
                // the update works. write it to the result
                result.push(FWRecord {
                    time: r.time,
                    src: r.src,
                    src_name: r.src_name,
                    prefix: r.prefix,
                    seq: None,
                    next_hop: nh,
                    next_hop_name: nh_name,
                });
            }
            IpfibOrUfdm::Ufdm(_, next_hop, next_hop_name) => {
                nh = Some((*next_hop, *next_hop_name, i));
            }
        }
    }

    Ok(result)
}
