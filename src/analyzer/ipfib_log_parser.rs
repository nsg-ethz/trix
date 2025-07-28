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
use std::path::PathBuf;

use router_lab::router::CiscoSession;
use ipnet::Ipv4Net;
use regex::Regex;
use serde::{Deserialize, Serialize};

use bgpsim::types::RouterId;

use crate::records::Router;

use super::log_parser::{
    parse_hex, parse_num, parse_pfx, GenericLog, GenericLogParser, LogParser, LogParserError,
    LogRecord,
};

pub struct IpfibLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<IpfibKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpfibKind {
    Line,
    Commit,
}

#[async_trait::async_trait]
impl LogParser<IpfibRecord, IpfibKind> for IpfibLogParser {
    fn description() -> &'static str {
        "IPFIB"
    }

    fn re() -> Vec<(IpfibKind, Regex)> {
        vec![
            (
                IpfibKind::Line,
                Regex::new(
                    r"^\[M 27\] \[ipfib\] E_DEBUG ufib_v4_bulk_v1_route_update\(2818\): *(add|del) prefix (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) flags 0x[0-9]* nh_count ([0-9]*)$",
                ).unwrap(),
            ),
            (
                IpfibKind::Commit,
                Regex::new(
                    r"^\[M 27\] \[ipfib\] E_DEBUG ufib_pi_msg_send_delayed_ack\(5169\): *Profiling: Send response to UFDM for update xid 0x([0-9a-f]*)$",
                ).unwrap(),
            ),
        ]
    }

    async fn new(
        rid: RouterId,
        router_name: Option<Router>,
        session: CiscoSession,
    ) -> Result<Self, LogParserError> {
        Ok(Self {
            rid,
            router_name,
            parser: GenericLogParser::new(
                rid,
                router_name,
                session,
                "show forwarding internal debugs",
                Self::re(),
                2,
                true,
            )
            .await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<IpfibRecord>, LogParserError> {
        let mut result: Vec<IpfibRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        let mut commit_time = None;
        let mut commit_id = None;

        for GenericLog { kind, time, groups } in logs {
            match kind {
                IpfibKind::Line => {
                    let Some(kind) = groups.get(1) else { continue };
                    let Some(prefix) = groups.get(2).and_then(parse_pfx) else {
                        continue;
                    };
                    let Some(count) = groups.get(3).and_then(parse_num) else {
                        continue;
                    };

                    let kind = match (kind.as_str(), count) {
                        ("del", 0) => IpfibRecordKind::Del,
                        ("add", k) if k > 0 => IpfibRecordKind::Add(k),
                        _ => continue,
                    };
                    result.push(IpfibRecord {
                        rid: self.rid,
                        router_name: self.router_name,
                        time,
                        commit_time,
                        commit_id,
                        prefix,
                        kind,
                    })
                }
                IpfibKind::Commit => {
                    let Some(id) = groups.get(1).and_then(parse_hex) else {
                        continue;
                    };
                    commit_time = Some(time);
                    commit_id = Some(id);
                }
            }
        }

        Ok(result)
    }
}

/// Record describing the update time gathered from `ipfib`  logs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IpfibRecord {
    pub rid: RouterId,
    pub router_name: Option<Router>,
    /// UTC timestamp in seconds, when the prefix was updated
    pub time: f64,
    /// UTC timestamp in seconds, when the data is committed to the UFDM.
    pub commit_time: Option<f64>,
    pub commit_id: Option<usize>,
    pub prefix: Ipv4Net,
    pub kind: IpfibRecordKind,
}

impl LogRecord for IpfibRecord {
    fn time(&self) -> f64 {
        self.time
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(from = "usize", into = "usize")]
pub enum IpfibRecordKind {
    /// Entry was added, with the given number of next-hops
    Add(usize),
    /// Entry was removed
    Del,
}

impl From<usize> for IpfibRecordKind {
    fn from(value: usize) -> Self {
        if value == 0 {
            Self::Del
        } else {
            Self::Add(value)
        }
    }
}

impl From<IpfibRecordKind> for usize {
    fn from(value: IpfibRecordKind) -> Self {
        match value {
            IpfibRecordKind::Add(x) => x,
            IpfibRecordKind::Del => 0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn add_line() {
        GenericLogParser::new_offline_from::<IpfibLogParser, _>().test_line(
            "2024-11-18T14:44:45.449715000+00:00 [M 27] [ipfib] E_DEBUG ufib_v4_bulk_v1_route_update(2818):  add prefix 100.0.48.0/24 flags 0x0 nh_count 1",
            Some((IpfibKind::Line, ["add", "100.0.48.0/24", "1"]))
        )
    }

    #[test]
    fn del_line() {
        GenericLogParser::new_offline_from::<IpfibLogParser, _>().test_line(
            "2024-11-18T14:45:53.575693000+00:00 [M 27] [ipfib] E_DEBUG ufib_v4_bulk_v1_route_update(2818): del prefix 100.0.32.0/24 flags 0x0 nh_count 0",
            Some((IpfibKind::Line, ["del", "100.0.32.0/24", "0"]))
        )
    }

    #[test]
    fn commit() {
        GenericLogParser::new_offline_from::<IpfibLogParser, _>().test_line(
            "2024-11-18T14:45:53.577571000+00:00 [M 27] [ipfib] E_DEBUG ufib_pi_msg_send_delayed_ack(5169): Profiling: Send response to UFDM for update xid 0x8f6",
            Some((IpfibKind::Commit, ["8f6"]))
        )
    }
}
