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
//! Module defining record data types to (de-)serialize BGP and DP updates to CSV.
use std::net::Ipv4Addr;

use mac_address::MacAddress;
use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serialize, Serializer};

use bgpsim::types::RouterId;

use crate::Prefix;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    strum::Display,
    strum::EnumIter,
    strum_macros::EnumString,
)]
/// Routers available on the Abilene topology.
pub enum Router {
    Atlanta,
    #[serde(rename = "Atlanta_ext")]
    #[strum(serialize = "Atlanta_ext")]
    AtlantaExt,
    Chicago,
    #[serde(rename = "Chicago_ext")]
    #[strum(serialize = "Chicago_ext")]
    ChicagoExt,
    Denver,
    #[serde(rename = "Denver_ext")]
    #[strum(serialize = "Denver_ext")]
    DenverExt,
    Houston,
    #[serde(rename = "Houston_ext")]
    #[strum(serialize = "Houston_ext")]
    HoustonExt,
    Indianapolis,
    #[serde(rename = "Indianapolis_ext")]
    #[strum(serialize = "Indianapolis_ext")]
    IndianapolisExt,
    KansasCity,
    #[serde(rename = "KansasCity_ext")]
    #[strum(serialize = "KansasCity_ext")]
    KansasCityExt,
    LosAngeles,
    #[serde(rename = "LosAngeles_ext")]
    #[strum(serialize = "LosAngeles_ext")]
    LosAngelesExt,
    NewYork,
    #[serde(rename = "NewYork_ext")]
    #[strum(serialize = "NewYork_ext")]
    NewYorkExt,
    Seattle,
    #[serde(rename = "Seattle_ext")]
    #[strum(serialize = "Seattle_ext")]
    SeattleExt,
    Sunnyvale,
    #[serde(rename = "Sunnyvale_ext")]
    #[strum(serialize = "Sunnyvale_ext")]
    SunnyvaleExt,
    WashingtonDC,
    #[serde(rename = "WashingtonDC_ext")]
    #[strum(serialize = "WashingtonDC_ext")]
    WashingtonDCExt,
}

impl Router {
    pub fn is_external(&self) -> bool {
        match self {
            Self::Atlanta
            | Self::Chicago
            | Self::Denver
            | Self::Houston
            | Self::Indianapolis
            | Self::KansasCity
            | Self::LosAngeles
            | Self::NewYork
            | Self::Seattle
            | Self::Sunnyvale
            | Self::WashingtonDC => false,

            Self::AtlantaExt
            | Self::ChicagoExt
            | Self::DenverExt
            | Self::HoustonExt
            | Self::IndianapolisExt
            | Self::KansasCityExt
            | Self::LosAngelesExt
            | Self::NewYorkExt
            | Self::SeattleExt
            | Self::SunnyvaleExt
            | Self::WashingtonDCExt => true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// Parsed BGP update messages in a usable format.
pub struct Record {
    #[serde(rename = "frame.time_epoch")]
    pub time: f64,
    #[serde(default)]
    pub link_src: Option<RouterId>,
    #[serde(default)]
    pub link_dst: Option<RouterId>,
    #[serde(rename = "eth.src")]
    pub src_mac: MacAddress,
    #[serde(rename = "eth.dst")]
    pub dst_mac: MacAddress,
    #[serde(default)]
    pub link_src_name: Option<Router>,
    #[serde(default)]
    pub link_dst_name: Option<Router>,
    #[serde(
        rename = "bgp.mp_unreach_nlri_ipv4_prefix",
        serialize_with = "serialize_list",
        deserialize_with = "deserialize_list"
    )]
    pub unreach: Vec<Ipv4Addr>,
    #[serde(
        rename = "bgp.mp_reach_nlri_ipv4_prefix",
        serialize_with = "serialize_list",
        deserialize_with = "deserialize_list"
    )]
    pub reach: Vec<Ipv4Addr>,
    #[serde(default)]
    pub path_length: Option<usize>,
    #[serde(default)]
    pub next_hop: Option<Ipv4Addr>,
    #[serde(default)]
    pub local_preference: Option<u32>,
    #[serde(default)]
    pub src: Option<RouterId>,
    #[serde(default)]
    pub dst: Option<RouterId>,
    #[serde(rename = "ip.src")]
    pub src_ip: Ipv4Addr,
    #[serde(rename = "ip.dst")]
    pub dst_ip: Ipv4Addr,
    #[serde(default)]
    pub src_name: Option<Router>,
    #[serde(default)]
    pub dst_name: Option<Router>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Timestamps when the forwarding next-hop of a router changes for a prefix.
pub struct FWRecord {
    pub time: f64,
    pub src: RouterId,
    pub src_name: Option<Router>,
    pub prefix: Ipv4Addr,
    #[serde(default)]
    pub seq: Option<u64>,
    pub next_hop: Option<RouterId>,
    pub next_hop_name: Option<Router>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
/// Timestamps when the forwarding next-hop of a router changes for a prefix.
pub struct PathRecord {
    pub time: f64,
    pub src: RouterId,
    pub src_name: Option<Router>,
    pub prefix: Ipv4Addr,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(
        serialize_with = "serialize_rid_list",
        deserialize_with = "deserialize_rid_list"
    )]
    pub path: Vec<RouterId>,
    #[serde(
        serialize_with = "serialize_option_list",
        deserialize_with = "deserialize_option_list"
    )]
    pub path_names: Vec<Option<Router>>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Timestamps when the reachability of router for a prefix changes.
pub struct DPRecord {
    pub time: f64,
    pub src: RouterId,
    pub src_name: Option<Router>,
    pub prefix: Ipv4Addr,
    pub reachable: bool,
}

fn serialize_rid_list<S: Serializer>(list: &[RouterId], serializer: S) -> Result<S::Ok, S::Error> {
    // Join the Ipv4Addr addresses as a comma-separated string
    let list_str = list
        .iter()
        .map(|x| x.index().to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Serialize the resulting string
    serializer.serialize_str(&list_str)
}

fn serialize_option_list<S: Serializer, T: ToString>(
    list: &[Option<T>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // Join the Ipv4Addr addresses as a comma-separated string
    let list_str = list
        .iter()
        .map(|x| x.as_ref().map(|y| y.to_string()).unwrap_or("".to_string()))
        .collect::<Vec<_>>()
        .join(",");

    // Serialize the resulting string
    serializer.serialize_str(&list_str)
}

fn serialize_list<S: Serializer, T: ToString>(
    list: &[T],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // Join the Ipv4Addr addresses as a comma-separated string
    let list_str = list
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Serialize the resulting string
    serializer.serialize_str(&list_str)
}

fn deserialize_rid_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RouterId>, D::Error> {
    let buf = String::deserialize(deserializer)?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    Ok(buf
        .split(',')
        .map(|x| RouterId::new(x.parse::<usize>().unwrap()))
        .collect())
}

fn deserialize_option_list<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<Option<T>>, D::Error> {
    let buf = String::deserialize(deserializer)?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    buf.split(',')
        .map(|x| {
            Ok(if x.is_empty() {
                None
            } else {
                Some(T::deserialize(x.into_deserializer())?)
            })
        })
        .collect()
}

fn deserialize_list<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    let buf = String::deserialize(deserializer)?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    buf.split(',')
        .map(|x| T::deserialize(x.into_deserializer()))
        .collect()
}

/// Record for CPU measurements taken on the cisco routers. Fields `cpu`, `cpuX`, and
/// `bgp_cpu` given in `[%]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CpuRecord {
    pub rid: RouterId,
    pub router_name: Option<Router>,
    pub timestamp: f64,
    /// The sum of the CPU usage of all 8 cores. The maximum is 800.0.
    pub cpu: f64,
    pub cpu1: f64,
    pub cpu2: f64,
    pub cpu3: f64,
    pub cpu4: f64,
    pub cpu5: f64,
    pub cpu6: f64,
    pub cpu7: f64,
    pub cpu8: f64,
    pub bgp_cpu: f64,
    pub ipfib_cpu: f64,
    pub urib_cpu: f64,
}

#[derive(Debug, Deserialize, Serialize)]
/// Violation times with accuracies as computed from a time series of forwarding states.
pub struct EvaluationRecord {
    /// Model identifier for input source and `FibQueueingModel` used to get this data point.
    pub model: String,
    pub sample_id: String,
    pub num_prefixes: usize,
    pub scenario: String,
    pub rid: RouterId,
    pub router: Option<Router>,
    pub prefix: Prefix,
    pub measured: f64,
    pub baseline: f64,
    pub computed: f64,
    /// (signed) error with baseline algorithm w.r.t. ground truth
    pub err_baseline: f64,
    /// (signed) error with interval algorithm w.r.t. ground truth
    pub err: f64,
    /// relative error with baseline algorithm w.r.t. average of ground truth and computed value
    pub rel_err_baseline: f64,
    /// relative error with interval algorithm w.r.t. average of ground truth and computed value
    pub rel_err: f64,
    /// absolute error with baseline algorithm w.r.t. ground truth
    pub abs_err_baseline: f64,
    /// absolute error with interval algorithm w.r.t. ground truth
    pub abs_err: f64,
    /// relative error with baseline algorithm w.r.t. total convergence time
    pub rel_err_total_baseline: f64,
    /// relative error with interval algorithm w.r.t. total convergence time
    pub rel_err_total: f64,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_path_record() {
        let x = PathRecord {
            time: 0.0,
            src: 0.into(),
            src_name: None,
            prefix: Ipv4Addr::new(127, 0, 0, 1),
            seq: None,
            path: vec![0.into(), 1.into(), 2.into()],
            path_names: vec![Some(Router::LosAngeles), None, Some(Router::LosAngelesExt)],
        };

        let mut csv = csv::WriterBuilder::new()
            .has_headers(true)
            .delimiter(b';')
            .from_writer(vec![]);
        csv.serialize(&x).unwrap();
        csv.flush().unwrap();
        let ser = String::from_utf8(csv.into_inner().unwrap()).unwrap();
        assert_eq!(ser, "time;src;src_name;prefix;seq;path;path_names\n0.0;0;;127.0.0.1;;0,1,2;LosAngeles,,LosAngeles_ext\n".to_string());

        let mut csv = csv::ReaderBuilder::new()
            .delimiter(b';')
            .from_reader(ser.as_bytes());
        let de: PathRecord = csv.deserialize().next().unwrap().unwrap();
        assert_eq!(de, x);
    }
}
