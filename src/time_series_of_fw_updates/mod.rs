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
//! Functions to extract the time series of forwarding state updates from individual records.

use std::{collections::HashMap, net::Ipv4Addr, path::Path, str::FromStr};

use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::Filter,
    prelude::{Analyzer, TimingModel},
    records::{FWRecord, Router},
    util::{self, get_num_prefixes, PathBufExt},
};
use bgpsim::{
    ospf::OspfProcess,
    prelude::NetworkFormatter,
    types::{RouterId, SimplePrefix},
};
use rayon::iter::ParallelIterator;

mod bgp;
mod bgp_messages;
mod fib_delay;
mod ipfib;
mod sim_model;
mod ufdm;
mod urib;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV Error: {0}")]
    Csv(#[from] csv::Error),
    #[error("Json Error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Bgpsim Error: {0}")]
    Bgpsim(#[from] bgpsim::types::NetworkError),
    #[error("Multiple next hops configured for router {0:?}: {1:?}")]
    MultipleNextHops(RouterId, Vec<RouterId>),
    #[error("Cannot map IP address {0} to a Router ID")]
    UnknownAddress(Ipv4Addr),
    #[error("Router {0:?} cannot reach {1:?} in bgpsim OSPF.")]
    NoOspfNextHop(RouterId, RouterId),
    #[error("Inconsistent data: {0}")]
    InconsistentData(&'static str),
}

pub(crate) fn run(args: &super::Args) -> Result<Vec<super::ExtractedMeasurement>, Error> {
    util::par_map_data(
        args.data_root.clone(),
        Filter {
            topo: args.topo.clone(),
            scenario: args.scenario.clone(),
            scenario_end: args.scenario_end.clone(),
            sample_id: "".to_string(),
        },
        |topo_name, scenario_name, eval_path| {
            process_directory(topo_name, scenario_name, eval_path, args)
        },
    )
    .collect::<Result<Vec<_>, _>>()
    .map(|x| x.into_iter().flatten().collect())
}

fn process_directory(
    topo_name: &str,
    scenario_name: &str,
    eval_path: &Path,
    args: &super::Args,
) -> Result<Vec<super::ExtractedMeasurement>, Error> {
    let mut new_measurements = Vec::new();

    // evaluate the data captured by the cisco_analyzer
    let analyzer_csv_path = eval_path.then("cisco_analyzer.csv");
    if !analyzer_csv_path.exists() {
        log::trace!("Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet.");
        return Ok(new_measurements);
    }
    log::trace!("Loading: {topo_name}/{scenario_name}/cisco_analyzer.csv");
    let analyzer_csv = std::fs::File::open(analyzer_csv_path.clone())?;
    let mut csv = csv::Reader::from_reader(analyzer_csv);

    let Ok(analyzer) = util::get_analyzer(topo_name, scenario_name) else {
        log::trace!("Could not build `Analyzer` for experiment in {analyzer_csv_path:?}.");
        return Ok(new_measurements);
    };

    for record in csv.deserialize() {
        let record: CiscoAnalyzerData = record?;
        let timestamp = record.execution_timestamp.clone();
        log::trace!("Reading from CSV:\n{record:#?}");

        // the log folder must exist, otherwise, we skip
        let log_folder = eval_path.then_ts("logs_{}", &record.execution_timestamp);
        if !log_folder.exists() {
            log::trace!(
                "skipping {} as no logs were collected",
                record.pcap_filename
            );
            continue;
        }

        if !record.execution_timestamp.contains(&args.sample_id) {
            log::trace!(
                "skipping {} due to filter on sample_id...",
                record.pcap_filename
            );
            continue;
        }

        let t0 = record.event_start;
        match process_sample(&analyzer, record, eval_path, args.replace) {
            Ok(updated) => new_measurements.push(super::ExtractedMeasurement {
                scenario_name: format!("{topo_name}_{scenario_name}"),
                root: eval_path.to_path_buf(),
                timestamp,
                num_prefixes: get_num_prefixes(scenario_name).unwrap(),
                updated,
                t0,
            }),
            Err(e) => {
                log::error!(
                    "Error processing the sample {}\nError: {e}",
                    eval_path.as_os_str().to_string_lossy()
                );
            }
        }
    }

    Ok(new_measurements)
}

#[track_caller]
fn warn<E: std::error::Error>(result: Result<bool, E>, kind: &str, path: &Path) -> bool {
    match result {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "Error processing {kind} of experiment {}\n    Error:{e}",
                path.as_os_str().to_string_lossy()
            );
            false
        }
    }
}

fn process_sample(
    analyzer: &Analyzer<TimingModel<SimplePrefix>>,
    metadata: CiscoAnalyzerData,
    eval_path: &Path,
    replace: bool,
) -> Result<bool, Error> {
    // extract hardware mapping
    let mut hm_path = eval_path.to_path_buf();
    hm_path.push(&metadata.hardware_mapping_filename);
    let hm: HardwareMapping = serde_json::from_str(&std::fs::read_to_string(&hm_path)?)?;

    let lut = Lut {
        ospf_nh: next_hop_lut(analyzer),
        addrs: router_ip_lut(&hm),
        names: router_name_lut(analyzer),
    };

    let mut updated = false;

    updated |= warn(
        bgp_messages::process_sample(analyzer, &metadata, eval_path, &lut, replace),
        "BGP messages",
        eval_path,
    );

    // Skip BGP Log, needs additional modeling
    // updated |= warn(
    //     bgp::process_sample(analyzer, &metadata, eval_path, &lut, replace),
    //     "BGP log",
    //     eval_path,
    // );

    updated |= warn(
        urib::process_sample(analyzer, &metadata, eval_path, &lut, replace),
        "URIB log",
        eval_path,
    );

    updated |= warn(
        ufdm::process_sample(&metadata, eval_path, &lut, replace),
        "UFDM log",
        eval_path,
    );

    updated |= warn(
        ipfib::process_sample(&metadata, eval_path, &lut, replace),
        "IPFIB log",
        eval_path,
    );

    /*
    updated |= warn(
        sim_model::process_sample(analyzer, &metadata, eval_path, &lut, replace),
        "BGPsim model",
        eval_path,
    );
    */

    updated |= warn(
        fib_delay::process_fw_records(&metadata, eval_path, replace),
        "FIB delay model",
        eval_path,
    );

    Ok(updated)
}

struct Lut {
    ospf_nh: HashMap<(RouterId, RouterId), RouterId>,
    addrs: HashMap<Ipv4Addr, RouterId>,
    names: HashMap<RouterId, Router>,
}

impl Lut {
    pub fn rid(&self, ip: Ipv4Addr) -> Result<RouterId, Error> {
        self.addrs
            .get(&ip)
            .copied()
            .ok_or(Error::UnknownAddress(ip))
    }

    pub fn name(&self, r: RouterId) -> Option<Router> {
        self.names.get(&r).copied()
    }

    pub fn ospf_nh(&self, src: RouterId, dst: RouterId) -> Result<RouterId, Error> {
        self.ospf_nh
            .get(&(src, dst))
            .copied()
            .ok_or(Error::NoOspfNextHop(src, dst))
    }
}

fn router_ip_lut(hm: &HardwareMapping) -> HashMap<Ipv4Addr, RouterId> {
    let mut mapping = HashMap::new();
    for (rid, props) in hm {
        // add all addresses of the loopback network.
        for addr in props
            .ipv4_net
            .hosts()
            .chain([props.ipv4_net.network(), props.ipv4_net.broadcast()])
        {
            mapping.insert(addr, *rid);
        }

        // add all interface addresses
        for iface in &props.ifaces {
            mapping.insert(iface.ipv4, *rid);
        }
    }
    mapping
}

fn next_hop_lut(
    analyzer: &Analyzer<TimingModel<SimplePrefix>>,
) -> HashMap<(RouterId, RouterId), RouterId> {
    let net = &analyzer.original_net;
    let mut lut = HashMap::new();
    for r in net.internal_routers() {
        let src = r.router_id();
        for (dst, (next_hops, _)) in r.ospf.get_table() {
            // only get the first next-hop, as ECMP is disabled.
            if let Some(nh) = next_hops.first().copied() {
                lut.insert((src, *dst), nh);
            }
        }
    }

    lut
}

fn router_name(router: RouterId, analyzer: &Analyzer<TimingModel<SimplePrefix>>) -> Option<Router> {
    Router::from_str(router.fmt(&analyzer.original_net)).ok()
}

fn router_name_lut(analyzer: &Analyzer<TimingModel<SimplePrefix>>) -> HashMap<RouterId, Router> {
    analyzer
        .original_net
        .device_indices()
        .filter_map(|r| router_name(r, analyzer).map(move |name| (r, name)))
        .collect()
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum UpdateKind {
    Add,
    Del,
}

trait ParseableRecord<P = Ipv4Addr, T = Ipv4Addr> {
    fn time(&self) -> f64;
    fn router(&self) -> RouterId;
    fn addr(&self) -> Option<P>;
    fn kind(&self) -> Option<UpdateKind>;
    fn ospf_next_hop(&self) -> Option<T>;
}

trait TransformParseableRecord {
    fn next_hop(&self, lut: &Lut) -> Result<Option<RouterId>, Error>;
    fn transform(&self, lut: &Lut, metadata: &CiscoAnalyzerData)
        -> Result<Option<FWRecord>, Error>;
}
impl<T: ParseableRecord<Ipv4Addr, Ipv4Addr>> TransformParseableRecord for T {
    /// Get the forwarding next-hop. This function calls `ospf_next_hop` unless explicitly defined
    /// otherwise.
    fn next_hop(&self, lut: &Lut) -> Result<Option<RouterId>, Error> {
        let Some(kind) = self.kind() else {
            return Err(Error::InconsistentData(
                "Called `next_hop` on a record that should be ignored",
            ));
        };
        match kind {
            UpdateKind::Add => {
                let Some(ospf_next_hop) = self.ospf_next_hop() else {
                    return Err(Error::InconsistentData(
                        "No OSPF next-hop for record that is of kind `Add`",
                    ));
                };
                let ospf_next_hop = lut.rid(ospf_next_hop)?;
                let next_hop = lut.ospf_nh(self.router(), ospf_next_hop)?;
                Ok(Some(next_hop))
            }
            UpdateKind::Del => Ok(None),
        }
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

fn is_event_prefix(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] >= 100
}
