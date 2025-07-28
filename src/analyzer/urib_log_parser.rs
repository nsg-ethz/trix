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

pub struct UribLogParser {
    add_parser: UribAddLogParser,
    del_parser: UribDelLogParser,
    mod_parser: UribModLogParser,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum UribKind {
    Add,
    Delete,
    Modify,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UribRecord {
    pub rid: RouterId,
    pub router_name: Option<Router>,
    pub time: f64,
    pub kind: UribKind,
    pub prefix: Ipv4Net,
    /// Only available on Add and Delete, but not for Modify
    pub next_hop: Option<Ipv4Addr>,
    /// Only available on Modify
    pub add_count: Option<usize>,
    /// Only available on Modify
    pub del_count: Option<usize>,
}

pub struct UribAddLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<()>,
}

impl LogRecord for UribRecord {
    fn time(&self) -> f64 {
        self.time
    }
}

#[async_trait::async_trait]
impl LogParser<UribRecord, UribKind> for UribLogParser {
    fn description() -> &'static str {
        "URIB"
    }
    async fn new(
        rid: RouterId,
        router_name: Option<Router>,
        session: CiscoSession,
    ) -> Result<Self, LogParserError> {
        Ok(Self {
            add_parser: UribAddLogParser::new(rid, router_name, session.clone()).await?,
            del_parser: UribDelLogParser::new(rid, router_name, session.clone()).await?,
            mod_parser: UribModLogParser::new(rid, router_name, session).await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<UribRecord>, LogParserError> {
        let mut logs = self.add_parser.parse_new(raw_log_root.clone()).await?;
        logs.extend(self.del_parser.parse_new(raw_log_root.clone()).await?);
        logs.extend(self.mod_parser.parse_new(raw_log_root).await?);

        Ok(logs)
    }

    fn re() -> Vec<(UribKind, Regex)> {
        vec![
            (UribKind::Add, UribAddLogParser::re().pop().unwrap().1),
            (UribKind::Delete, UribDelLogParser::re().pop().unwrap().1),
            (UribKind::Modify, UribModLogParser::re().pop().unwrap().1),
        ]
    }
}

#[async_trait::async_trait]
impl LogParser<UribRecord, ()> for UribAddLogParser {
    fn description() -> &'static str {
        "Urib add-route"
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
                "show routing event-history add-route",
                Self::re(),
                0,
                false,
            )
            .await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<UribRecord>, LogParserError> {
        let mut result: Vec<UribRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        for GenericLog { time, groups, .. } in logs {
            // first and second groups are always prefix and peer
            let Some(prefix) = groups.get(1).and_then(parse_pfx) else {
                continue;
            };
            let Some(nh) = groups.get(2).and_then(parse_ip) else {
                continue;
            };

            result.push(UribRecord {
                rid: self.rid,
                router_name: self.router_name,
                time,
                kind: UribKind::Add,
                prefix,
                next_hop: Some(nh),
                add_count: None,
                del_count: None,
            });
        }

        Ok(result)
    }

    fn re() -> Vec<((), Regex)> {
        vec![((), Regex::new(
            r"^\[M 27\] \[urib\] E_DEBUG \[urib_trace_binary:213\] RTE, vrf=[a-z0-9]+, event=add, nh_type=[a-zA-Z0-9]+, pib=bgp-\d+, if_name=[a-zA-Z0-9-\/]*, nh_vrf=[a-zA-Z0-9]+, address=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}), nh_addr=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/32, nh_bl=\d+, metric=\d+\/\d+, route_type=[a-zA-Z0-9]+, tag=[0-9a-f]+, is_clone=[a-zA-Z0-9]+, nh_flags=[0-9a-f]+, remote_sid=[0-9a-f:]+, vxlan_info=[a-zA-Z0-9]*$"
        ).unwrap())]
    }
}

pub struct UribDelLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<()>,
}

#[async_trait::async_trait]
impl LogParser<UribRecord, ()> for UribDelLogParser {
    fn description() -> &'static str {
        "Urib delete-route"
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
                "show routing event-history delete-route",
                Self::re(),
                0,
                false,
            )
            .await?,
        })
    }

    async fn parse_new(
        &mut self,
        raw_log_root: Option<PathBuf>,
    ) -> Result<Vec<UribRecord>, LogParserError> {
        let mut result: Vec<UribRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        for GenericLog { time, groups, .. } in logs {
            // first and second groups are always prefix and peer
            let Some(prefix) = groups.get(1).and_then(parse_pfx) else {
                continue;
            };
            let Some(nh) = groups.get(2).and_then(parse_ip) else {
                continue;
            };

            result.push(UribRecord {
                rid: self.rid,
                router_name: self.router_name,
                time,
                kind: UribKind::Delete,
                prefix,
                next_hop: Some(nh),
                add_count: None,
                del_count: None,
            });
        }

        Ok(result)
    }

    fn re() -> Vec<((), Regex)> {
        vec![((), Regex::new(
            r"^\[M 27\] \[urib\] E_DEBUG \[urib_trace_binary:213\] RTE, vrf=[a-z0-9]+, event=del, nh_type=[a-zA-Z0-9]+, pib=bgp-\d+, if_name=[a-zA-Z0-9-\/]*, nh_vrf=[a-zA-Z0-9]+, address=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}), nh_addr=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/32, nh_bl=\d+, metric=\d+\/\d+, route_type=[a-zA-Z0-9]+, tag=[0-9a-f]+, is_clone=[a-zA-Z0-9]+, nh_flags=[0-9a-f]+, remote_sid=[0-9a-f:]+, vxlan_info=[a-zA-Z0-9]*$"
        ).unwrap())]
    }
}

pub struct UribModLogParser {
    rid: RouterId,
    router_name: Option<Router>,
    parser: GenericLogParser<()>,
}

#[async_trait::async_trait]
impl LogParser<UribRecord, ()> for UribModLogParser {
    fn description() -> &'static str {
        "Urib modify-route"
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
                "show routing event-history modify-route",
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
    ) -> Result<Vec<UribRecord>, LogParserError> {
        let mut result: Vec<UribRecord> = Vec::new();

        let logs = self.parser.parse_new(raw_log_root).await?;

        for GenericLog { time, groups, .. } in logs {
            // first and second groups are always prefix and peer
            let Some(prefix) = groups.get(1).and_then(parse_pfx) else {
                continue;
            };
            let Some(add_count) = groups.get(2).and_then(parse_num) else {
                continue;
            };
            let Some(del_count) = groups.get(3).and_then(parse_num) else {
                continue;
            };

            result.push(UribRecord {
                rid: self.rid,
                router_name: self.router_name,
                time,
                kind: UribKind::Modify,
                prefix,
                next_hop: None,
                add_count: Some(add_count),
                del_count: Some(del_count),
            });
        }

        Ok(result)
    }

    fn re() -> Vec<((), Regex)> {
        vec![((), Regex::new(r"^\[M 27\] \[urib\] E_DEBUG \[urib_trace_binary:213\] MOD SUM, vrf=[a-zA-Z0-9-]+, event=rt mod, pib=bgp-\d+, address=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}), add_count=(\d+), del_count=(\d+), sort_key=\d+, prefix_flags=0x[0-9a-f]+$").unwrap())]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn add() {
        GenericLogParser::new_offline_from::<UribAddLogParser, _>()
            .test_line(
                "2024-11-18T12:25:57.130633000+00:00 [M 27] [urib] E_DEBUG [urib_trace_binary:213] RTE, vrf=default, event=add, nh_type=rnh, pib=bgp-65535, if_name=, nh_vrf=default, address=100.38.129.0/24, nh_addr=1.0.5.1/32, nh_bl=0, metric=200/0, route_type=internal, tag=00000064, is_clone=N, nh_flags=00000010, remote_sid=0::, vxlan_info=",
                Some(((), ["100.38.129.0/24", "1.0.5.1"]))
            );

        GenericLogParser::new_offline_from::<UribAddLogParser, _>()
            .test_line::<0>(
                "2024-11-18T14:35:40.127951000+00:00 [M 27] [urib] E_DEBUG [urib_trace_binary:213] RTE, vrf=default, event=add, nh_type=nh, pib=broadcast, if_name=Ethernet1/54, nh_vrf=default, address=1.0.7.7/32, nh_addr=1.0.7.7/0, nh_bl=0, metric=0/0, route_type=unknown, tag=00000000, is_clone=N, nh_flags=0000000d, remote_sid=0::, vxlan_info=",
                None,
            );
    }

    #[test]
    fn delete() {
        GenericLogParser::new_offline_from::<UribDelLogParser, _>()
            .test_line(
                "2024-11-18T14:45:53.572240000+00:00 [M 27] [urib] E_DEBUG [urib_trace_binary:213] RTE, vrf=default, event=del, nh_type=rnh, pib=bgp-65535, if_name=, nh_vrf=default, address=100.0.80.0/24, nh_addr=1.0.5.1/32, nh_bl=0, metric=200/0, route_type=internal, tag=00000064, is_clone=N, nh_flags=00000010, remote_sid=0::, vxlan_info=",
                Some(((), ["100.0.80.0/24", "1.0.5.1"]))
            );
        GenericLogParser::new_offline_from::<UribDelLogParser, _>()
            .test_line::<0>(
                "2024-11-18T14:42:03.245147000+00:00 [M 27] [urib] E_DEBUG [urib_trace_binary:213] RTE, vrf=default, event=del, nh_type=nh, pib=ospf-10, if_name=Ethernet1/50, nh_vrf=default, address=1.0.9.1/32, nh_addr=1.128.0.37/0, nh_bl=0, metric=110/7, route_type=intra, tag=00000000, is_clone=N, nh_flags=00000000, remote_sid=0::, vxlan_info=",
                None
            )
    }

    #[test]
    fn modify() {
        GenericLogParser::new_offline_from::<UribModLogParser, _>()
            .test_line(
                "2024-11-18T14:41:31.111327000+00:00 [M 27] [urib] E_DEBUG [urib_trace_binary:213] MOD SUM, vrf=default, event=rt mod, pib=bgp-65535, address=100.0.92.0/24, add_count=1, del_count=0, sort_key=0, prefix_flags=0x2",
                Some(((), ["100.0.92.0/24", "1", "0"]))
            );
        GenericLogParser::new_offline_from::<UribModLogParser, _>()
            .test_line::<0>(
                "2024-11-18T14:41:59.065328000+00:00 [M 27] [urib] E_DEBUG [urib_trace_binary:213] MOD SUM, vrf=default, event=rt mod, pib=ospf-10, address=1.128.0.24/30, add_count=1, del_count=0, sort_key=0, prefix_flags=0x0",
                None
            );
    }
}
