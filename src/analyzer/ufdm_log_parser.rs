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
use std::{net::Ipv4Addr, path::PathBuf};

use router_lab::router::CiscoSession;
use ipnet::Ipv4Net;
use regex::Regex;
use serde::{Deserialize, Serialize};

use bgpsim::types::RouterId;

use crate::records::Router;

use super::log_parser::{
    parse_ip, parse_pfx, GenericLog, GenericLogParser, LogParser, LogParserError, LogRecord,
};

pub struct UfdmLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<UfdmKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum UfdmKind {
    Add,
    Del,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UfdmRecord {
    pub rid: RouterId,
    pub router_name: Option<Router>,
    pub time: f64,
    pub kind: UfdmKind,
    pub prefix: Ipv4Net,
    pub next_hop: Option<Ipv4Addr>,
}

#[async_trait::async_trait]
impl LogParser<UfdmRecord, UfdmKind> for UfdmLogParser {
    fn description() -> &'static str {
        "UFDM"
    }

    fn re() -> Vec<(UfdmKind, Regex)> {
        vec![
            (
                UfdmKind::Del,
                Regex::new(
                    r"urib: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) 0 next hops, length \d+ del route",
                ).unwrap(),
            ),
            (
                UfdmKind::Add,
                Regex::new(
                    r"urib: urib_fill_ufdm_route - (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) add nh (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) nh_flags 0x[0-9a-f]+ ext_nh_flag 0x[0-9a-f]+",
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
                "show routing internal event-history ufdm-detail",
                Self::re(),
                1,
                true,
            )
            .await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<UfdmRecord>, LogParserError> {
        let mut result: Vec<UfdmRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        for GenericLog { kind, time, groups } in logs {
            // first and second groups are always prefix and peer
            let Some(prefix) = groups.get(1).and_then(parse_pfx) else {
                continue;
            };
            let mut next_hop = None;
            if kind == UfdmKind::Add {
                next_hop = groups.get(2).and_then(parse_ip);
                // skip this entry if the next-hop could not be parsed.
                if next_hop.is_none() {
                    continue;
                }
            }

            result.push(UfdmRecord {
                rid: self.rid,
                router_name: self.router_name,
                time,
                kind,
                prefix,
                next_hop,
            });
        }

        Ok(result)
    }
}

impl LogRecord for UfdmRecord {
    fn time(&self) -> f64 {
        self.time
    }
}

#[cfg(test)]
mod test_prefixes {
    use super::*;

    #[test]
    fn add() {
        GenericLogParser::new_offline_from::<UfdmLogParser, _>().test_line(
            "2024 Nov 18 09:14:39.191295 urib: urib_fill_ufdm_route - 100.0.54.0/24 add nh 1.0.7.1 nh_flags 0x3 ext_nh_flag 0x0",
            Some((UfdmKind::Add, ["100.0.54.0/24", "1.0.7.1"])))
    }

    #[test]
    fn del() {
        GenericLogParser::new_offline_from::<UfdmLogParser, _>().test_line(
            "2024 Nov 19 14:23:22.315641 urib: 100.0.54.0/24 0 next hops, length 0 del route",
            Some((UfdmKind::Del, ["100.0.54.0/24"])),
        )
    }
}
