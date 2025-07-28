//! Module to evaluate BGP reaction times from a router

use std::{collections::HashMap, net::Ipv4Addr};

use serde::{Deserialize, Serialize};

use bgpsim::types::RouterId;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Router {
    pub rid: RouterId,
    pub ip: Ipv4Addr,
    pub prober_src_ip: Ipv4Addr,
    pub mac_prefix: String,
}

pub type ReactionTimesMap<P> = HashMap<(usize, usize, usize, P), Vec<ReactionTime>>;
pub type CPReactionTimesMap<P> = HashMap<(usize, usize, P), Vec<f64>>;
pub type LastDPReactionTimesMap = HashMap<usize, Vec<f64>>;
pub type DPReactionTimesMap = HashMap<usize, Vec<f64>>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ReactionTime {
    #[serde(deserialize_with = "csv::invalid_option")]
    pub first_cp_reaction: Option<f64>,
    #[serde(deserialize_with = "csv::invalid_option")]
    pub last_cp_reaction: Option<f64>,
    #[serde(deserialize_with = "csv::invalid_option")]
    pub cp_reaction_increment: Option<f64>,
    #[serde(deserialize_with = "csv::invalid_option")]
    pub dp_reaction: Option<f64>,
}

#[cfg(test)]
mod test {}
