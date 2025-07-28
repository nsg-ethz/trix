//! Module to handle BGP messages from BGPseer experiment traffic

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::Path,
    str::FromStr,
};

use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize};

use bgpsim::types::Prefix;

use crate::pcap_utils::{PacketFilter, PcapFilter};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BGPMessage<P: Prefix> {
    pub timestamp: f64,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_mac: String,
    pub dst_mac: String,
    pub tcp_seq: usize,
    #[serde(deserialize_with = "deserialize_prefix_list")]
    pub prefixes: Vec<P>,
    // a `BGPMessage` is delivered if this is not the first time we see the packet on the link,
    // i.e., it successfully went through the delayer
    pub delivered: bool,
}

fn deserialize_prefix_list<'de, D, P: Prefix>(de: D) -> Result<Vec<P>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(parse_prefix_list::<P>(&String::deserialize(de)?))
}

fn parse_prefix_list<P: Prefix>(prefix_list: &str) -> Vec<P> {
    prefix_list
        .split(',')
        .filter_map(|x| Ipv4Addr::from_str(x).ok().map(P::from))
        .collect_vec()
}

pub type BGPParseError = String;
pub fn parse_bgp_message_with_delayers<P: Prefix>(
    msg: &str,
    lookup_prefixes: &mut HashMap<(Ipv4Addr, Ipv4Addr, usize), Vec<P>>,
    delayer_tracking: &mut HashSet<(Ipv4Addr, Ipv4Addr, String, String, usize)>,
) -> Result<BGPMessage<P>, BGPParseError> {
    parse_bgp_message_vec_with_delayers::<P>(
        msg.split(';').map(|x| x.to_string()).collect_vec(),
        lookup_prefixes,
        delayer_tracking,
    )
}

pub fn parse_bgp_message_vec<P: Prefix>(
    inputs: Vec<String>,
) -> Result<BGPMessage<P>, BGPParseError> {
    parse_bgp_message_vec_with_delayers::<P>(inputs, &mut HashMap::new(), &mut HashSet::new())
}

pub fn parse_bgp_message_vec_with_delayers<P: Prefix>(
    inputs: Vec<String>,
    lookup_prefixes: &mut HashMap<(Ipv4Addr, Ipv4Addr, usize), Vec<P>>,
    delayer_tracking: &mut HashSet<(Ipv4Addr, Ipv4Addr, String, String, usize)>,
) -> Result<BGPMessage<P>, BGPParseError> {
    if inputs.len() < 7 {
        log::error!("Trying to parse BGPMessage from {inputs:?}");
        return Err(BGPParseError::from(
            "Not enough fields to parse a BGPMessage!",
        ));
    }

    log::trace!("Parsing BGPMessage from {inputs:?}");

    let timestamp = inputs[0].parse().unwrap();
    let src_ip = Ipv4Addr::from_str(&inputs[1]).unwrap();
    let dst_ip = Ipv4Addr::from_str(&inputs[2]).unwrap();
    let src_mac = inputs[3].clone();
    let dst_mac = inputs[4].clone();
    let tcp_seq = inputs[5].parse().unwrap();

    // read prefixes from tshark, and update the lookup dictionary or vice versa
    let mut prefixes = parse_prefix_list(&inputs[6]);
    if !prefixes.is_empty() {
        let tmp = lookup_prefixes.insert((src_ip, dst_ip, tcp_seq), prefixes.clone());
        assert!(tmp.is_none());
    } else if let Some(xs) = lookup_prefixes.get(&(src_ip, dst_ip, tcp_seq)) {
        prefixes.clone_from(xs);
    }

    // delivered if this is not the first time we see the packet on the link
    let delivered =
        !delayer_tracking.insert((src_ip, dst_ip, src_mac.clone(), dst_mac.clone(), tcp_seq));

    Ok(BGPMessage {
        timestamp,
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        tcp_seq,
        prefixes,
        delivered,
    })
}

pub enum BGPFilter {
    Announcements,
    Withdraws,
}

impl BGPFilter {
    fn _filter(&self, pcap_path: &Path) -> impl Iterator<Item = Vec<String>> {
        PcapFilter::All(PacketFilter {
            port: Some(179),
            filter: "!bgp.type || bgp.type == 2".to_string(),
            outputs: [
                "frame.time_epoch",
                "ip.src",
                "ip.dst",
                "eth.src",
                "eth.dst",
                "tcp.seq",
                match self {
                    Self::Announcements => "bgp.mp_reach_nlri_ipv4_prefix",
                    Self::Withdraws => "bgp.mp_unreach_nlri_ipv4_prefix",
                },
            ]
            .into_iter()
            .map(|x| x.to_string())
            .collect_vec(),
            ..Default::default()
        })
        .filter(pcap_path)
        .into_iter()
    }

    /// Filter a pcap file with the given `BGPFilter` and parse the result as `BGPMessage`s.
    pub fn filter<'a, P: Prefix>(
        &self,
        pcap_path: &'a Path,
    ) -> impl Iterator<Item = BGPMessage<P>> + 'a {
        self._filter(pcap_path)
            .filter_map(|msg| parse_bgp_message_vec(msg).ok())
    }

    /// Filter a pcap file with the given `BGPFilter` and parse the result as `BGPMessage`s. This
    /// function is delayer-aware, i.e., it can handle duplicate packets that would normally not be
    /// parsed by tshark as it identifies them as TCP retransmissions.
    pub fn filter_with_delayers<'a, P: Prefix>(
        &self,
        pcap_path: &'a Path,
        lookup_prefixes: &'a mut HashMap<(Ipv4Addr, Ipv4Addr, usize), Vec<P>>,
        delayer_tracking: &'a mut HashSet<(Ipv4Addr, Ipv4Addr, String, String, usize)>,
    ) -> impl Iterator<Item = BGPMessage<P>> + 'a {
        self._filter(pcap_path).filter_map(|msg| {
            parse_bgp_message_vec_with_delayers::<P>(msg, lookup_prefixes, delayer_tracking).ok()
        })
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use bgpsim::types::Ipv4Prefix as P;

    use super::{parse_prefix_list, BGPMessage};

    #[test]
    fn parsing() {
        assert_eq!(
            parse_prefix_list::<P>("100.0.0.0,100.0.1.0,100.0.2.0"),
            vec![P::from(0), P::from(1), P::from(2)]
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn serde_BGPMessage() {
        let msg: BGPMessage<P> = BGPMessage {
            timestamp: 0.0,
            src_ip: Ipv4Addr::new(1, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 0, 0, 2),
            src_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            dst_mac: "ab:cd:ef:ab:cd:ef".to_string(),
            tcp_seq: 1337,
            prefixes: vec![P::from(0), P::from(1)],
            delivered: true,
        };

        // test serialization
        let serialized = serde_json::to_string_pretty(&msg).unwrap();
        assert_eq!(
            serialized,
            r#"{
  "timestamp": 0.0,
  "src_ip": "1.0.0.1",
  "dst_ip": "1.0.0.2",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "dst_mac": "ab:cd:ef:ab:cd:ef",
  "tcp_seq": 1337,
  "prefixes": [
    "100.0.0.0/24",
    "100.0.1.0/24"
  ],
  "delivered": true
}"#
            .to_string(),
        );
    }
}
