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
    parse_ip, parse_num, parse_pfx, GenericLog, GenericLogParser, LogParser, LogParserError,
    LogRecord,
};

pub struct BgpPrefixesLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<PrefixesLineKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum PrefixesLineKind {
    MarkForDeletion,
    NewBestPath,
    BRibAdd,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BgpPrefixesRecord {
    pub rid: RouterId,
    pub router_name: Option<Router>,
    pub time: f64,
    pub kind: PrefixesLineKind,
    pub prefix: Ipv4Net,
    pub peer: Ipv4Addr,
    /// Only available for NewBestPath
    pub new_best_next_hop: Option<Ipv4Addr>,
    /// Only available for BRibAdd
    pub brib_num_new: Option<usize>,
    /// Only available for BRibAdd
    pub brib_num_change: Option<usize>,
    /// Only available for BRibAdd
    pub brib_num_undelete: Option<usize>,
}

#[async_trait::async_trait]
impl LogParser<BgpPrefixesRecord, PrefixesLineKind> for BgpPrefixesLogParser {
    fn description() -> &'static str {
        "BGP Prefixes"
    }

    fn re() -> Vec<(PrefixesLineKind, Regex)> {
        vec![
            (
                PrefixesLineKind::MarkForDeletion,
                Regex::new(
                    r"^\[M 27\] \[bgp\] E_DEBUG \[bgp_brib_delete_path:4036\] \(default\) PFX: \[IPv4 Unicast\] Marking path for dest (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) from peer (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) as deleted, pflags = 0x[0-9a-f]*$",
                ).unwrap(),
            ),
            (
                PrefixesLineKind::NewBestPath,
                Regex::new(
                    r"^\[M 27\] \[bgp\] E_DEBUG \[bgp_set_bestpath:4861\] \(default\) PFX: \[IPv4 Unicast\] Selected new bestpath (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) flags=0x[0-9a-f]* rid=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) nh=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) bestpath flags=0x[0-9a-f]*$",
                ).unwrap(),
            ),
            (
                PrefixesLineKind::BRibAdd,
                Regex::new(
                    r"^\[M 27\] \[bgp\] E_DEBUG \[bgp_brib_add:3878\] \(default\) PFX: \[IPv4 Unicast\] \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\): returning from bgp_brib_add, new_path: (\d+), change: (\d+), undelete: (\d+), history: \d+, force: \d+, \(pflags=0x[0-9a-f]+\), \(pflags2=0x[0-9a-f]+\), orphan_mac_changed: \d+, mpls \d+, dci_pip_orphan_mac_changed: \d+, dci_pip_peer_orphan_mac_changed: \d+ fhs_dhcp_lease_time: \d+$",
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
                "show bgp event-history prefixes",
                Self::re(),
                0,
                true,
            )
            .await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<BgpPrefixesRecord>, LogParserError> {
        let mut result: Vec<BgpPrefixesRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        for GenericLog { kind, time, groups } in logs {
            // first and second groups are always prefix and peer
            let Some(prefix) = groups.get(1).and_then(parse_pfx) else {
                continue;
            };
            let Some(peer) = groups.get(2).and_then(parse_ip) else {
                continue;
            };
            let mut new_best_next_hop = None;
            let mut brib_num_new = None;
            let mut brib_num_change = None;
            let mut brib_num_undelete = None;
            match kind {
                PrefixesLineKind::NewBestPath => {
                    new_best_next_hop = groups.get(3).and_then(parse_ip);
                }
                PrefixesLineKind::BRibAdd => {
                    brib_num_new = groups.get(3).and_then(parse_num);
                    brib_num_change = groups.get(4).and_then(parse_num);
                    brib_num_undelete = groups.get(5).and_then(parse_num);
                }
                _ => {}
            }

            result.push(BgpPrefixesRecord {
                rid: self.rid,
                router_name: self.router_name,
                time,
                kind,
                prefix,
                peer,
                new_best_next_hop,
                brib_num_new,
                brib_num_change,
                brib_num_undelete,
            });
        }

        Ok(result)
    }
}

impl LogRecord for BgpPrefixesRecord {
    fn time(&self) -> f64 {
        self.time
    }
}

#[cfg(test)]
mod test_prefixes {
    use super::*;

    #[test]
    fn mark_for_deletion() {
        GenericLogParser::new_offline_from::<BgpPrefixesLogParser, _>().test_line(
            "2024-11-18T14:45:53.568531000+00:00 [M 27] [bgp] E_DEBUG [bgp_brib_delete_path:4036] (default) PFX: [IPv4 Unicast] Marking path for dest 100.0.71.0/24 from peer 1.0.5.1 as deleted, pflags = 0x11",
            Some((
            PrefixesLineKind::MarkForDeletion,
            ["100.0.71.0/24", "1.0.5.1"],
        )))
    }

    #[test]
    fn new_best_path() {
        GenericLogParser::new_offline_from::<BgpPrefixesLogParser, _>().test_line(
            "2024-11-18T14:44:45.433846000+00:00 [M 27] [bgp] E_DEBUG [bgp_set_bestpath:4861] (default) PFX: [IPv4 Unicast] Selected new bestpath 100.0.60.0/24 flags=0x2155872280 rid=1.0.5.1 nh=1.0.5.1 bestpath flags=0x2018",
            Some((PrefixesLineKind::NewBestPath, ["100.0.60.0/24", "1.0.5.1", "1.0.5.1"]))
        )
    }

    #[test]
    fn brib_add() {
        GenericLogParser::new_offline_from::<BgpPrefixesLogParser, _>().test_line(
            "2024-11-18T14:44:45.431581000+00:00 [M 27] [bgp] E_DEBUG [bgp_brib_add:3878] (default) PFX: [IPv4 Unicast] (100.0.79.0/24 (1.0.5.1)): returning from bgp_brib_add, new_path: 2, change: 1, undelete: 0, history: 0, force: 0, (pflags=0x2010), (pflags2=0x80000), orphan_mac_changed: 0, mpls 0, dci_pip_orphan_mac_changed: 0, dci_pip_peer_orphan_mac_changed: 0 fhs_dhcp_lease_time: 0",
            Some((PrefixesLineKind::BRibAdd, ["100.0.79.0/24", "1.0.5.1", "2", "1", "0"]))
        )
    }
}

pub struct BgpUribLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<UribLineKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum UribLineKind {
    Add,
    Delete,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BgpUribRecord {
    pub rid: RouterId,
    pub router_name: Option<Router>,
    pub time: f64,
    pub kind: UribLineKind,
    pub prefix: Ipv4Net,
    pub peer: Ipv4Addr,
    /// Only available for Add.
    pub next_hop: Option<Ipv4Addr>,
}

#[async_trait::async_trait]
impl LogParser<BgpUribRecord, UribLineKind> for BgpUribLogParser {
    fn description() -> &'static str {
        "BGP URIB"
    }

    fn re() -> Vec<(UribLineKind, Regex)> {
        vec![
            (
                UribLineKind::Add,
                Regex::new(
                    r"^\[M 27\] \[bgp\] E_DEBUG \[bgp_urib_nh_add:4631\] \(default\) URIB: \[IPv4 Unicast\] Adding path to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), nhtable=0x[0-9a-f]+, iod=[^,]*, nh=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), metric \d+, nhflags=0x[0-9a-f]+, extcommlen=\d+, pref=\d+, tag=\d+ \(URIB\)$",
                ).unwrap(),
            ),
            (
                UribLineKind::Delete,
                Regex::new(
                    r"^\[M 27\] \[bgp\] E_DEBUG \[bgp_urib_nh_del:5100\] \(default\) URIB: \[IPv4 Unicast\] Deleting path to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}) via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), nhtable=0x[0-9a-f]+, iod=[^,]*, nhflags=0x[0-9a-f]+, sortkey=\d+\.\d+\.\d+\.\d+, srv6_sid=[0-9a-f:]+ \(URIB\)$",
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
                "show bgp event-history urib",
                Self::re(),
                0,
                true,
            )
            .await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<BgpUribRecord>, LogParserError> {
        let mut result: Vec<BgpUribRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        for GenericLog { kind, time, groups } in logs {
            // first and second groups are always prefix and peer
            let Some(prefix) = groups.get(1).and_then(parse_pfx) else {
                continue;
            };
            let Some(peer) = groups.get(2).and_then(parse_ip) else {
                continue;
            };
            let mut next_hop = None;
            if kind == UribLineKind::Add {
                next_hop = groups.get(3).and_then(parse_ip);
            }

            result.push(BgpUribRecord {
                rid: self.rid,
                router_name: self.router_name,
                time,
                kind,
                prefix,
                peer,
                next_hop,
            });
        }

        Ok(result)
    }
}

impl LogRecord for BgpUribRecord {
    fn time(&self) -> f64 {
        self.time
    }
}

#[cfg(test)]
mod test_urib {
    use super::*;

    #[test]
    fn add() {
        GenericLogParser::new_offline_from::<BgpUribLogParser, _>().test_line(
            "2024-11-18T14:44:45.432692000+00:00 [M 27] [bgp] E_DEBUG [bgp_urib_nh_add:4631] (default) URIB: [IPv4 Unicast] Adding path to 100.0.33.0/24 via 1.0.5.1, nhtable=0x1, iod=, nh=1.0.5.1, metric 0, nhflags=0x10, extcommlen=0, pref=200, tag=100 (URIB)",
            Some((
            UribLineKind::Add,
            ["100.0.33.0/24", "1.0.5.1", "1.0.5.1"],
        )))
    }

    #[test]
    fn delete() {
        GenericLogParser::new_offline_from::<BgpUribLogParser, _>().test_line(
            "2024-11-18T14:45:53.569538000+00:00 [M 27] [bgp] E_DEBUG [bgp_urib_nh_del:5100] (default) URIB: [IPv4 Unicast] Deleting path to 100.0.81.0/24 via 1.0.5.1, nhtable=0x1, iod=, nhflags=0x000010, sortkey=0.0.0.0, srv6_sid=0:: (URIB)",
            Some((UribLineKind::Delete, ["100.0.81.0/24", "1.0.5.1"]))
        )
    }
}
