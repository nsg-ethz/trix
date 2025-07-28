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
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::Ipv4Addr,
    path::Path,
    str::FromStr,
};

use anyhow::{ensure, Context};
use trix::{
    analyzer::{CiscoAnalyzerData, HardwareMapping},
    experiments::Filter,
    prelude::{Analyzer, TimingModel},
    records::{FWRecord, PathRecord, Router},
    util::{self, PathBufExt},
    Prefix,
};
use trix_utils::pcap_utils::PROBER_PACKET_SIZE;
use bgpsim::{prelude::SimplePrefix, types::RouterId};
use clap::Parser;
use itertools::Itertools;
use mac_address::MacAddress;
use pcap_file::pcap::{PcapPacket, PcapReader};
use pnet_packet::{ethernet, ip, ipv4, Packet};
use rayon::iter::ParallelIterator;

pub const PROBER_SRC_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Overwrite the input path for data.
    //#[arg(short, long, default_value = "./data/")]
    #[arg(short, long, default_value = "./data/")]
    data_root: String,
    /// Overwrite the topology filter for extracting BGP updates.
    #[arg(short, long, default_value = "Abilene")]
    topo: String,
    /// Overwrite the scenario filter for extracting BGP updates.
    #[arg(short, long, default_value = "")]
    scenario: String,
    /// Overwrite the scenario_end filter for extracting BGP updates.
    #[arg(short = 'e', long = "scenario-end", default_value = "")]
    scenario_end: String,
    /// Overwrite the scenario_end filter for extracting BGP updates.
    #[arg(short = 'i', long = "sample", default_value = "")]
    sample_id: String,
    /// Replace the existing files
    #[arg(long = "replace")]
    replace: bool,
}

#[allow(unused)]
fn main() -> anyhow::Result<()> {
    util::init_logging();

    let args = Args::parse();

    util::par_map_data(
        args.data_root.clone(),
        Filter {
            topo: args.topo.clone(),
            scenario: args.scenario.clone(),
            scenario_end: args.scenario_end.clone(),
            sample_id: "".to_string(),
        },
        |topo_name, scenario_name, eval_path| match process_directory(
            topo_name,
            scenario_name,
            eval_path,
            &args,
        ) {
            Ok(_) => {}
            Err(e) => {
                log::error!("Error processing {topo_name}/{scenario_name}:\n{e:?}\n\n")
            }
        },
    )
    .collect::<Vec<_>>();
    Ok(())
}

fn process_directory(
    topo_name: &str,
    scenario_name: &str,
    eval_path: &Path,
    args: &Args,
) -> anyhow::Result<()> {
    // evaluate the data captured by the cisco_analyzer
    let analyzer_csv_path = eval_path.then("cisco_analyzer.csv");
    if !analyzer_csv_path.exists() {
        log::trace!("Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet.");
        return Ok(());
    }
    log::trace!("Loading: {topo_name}/{scenario_name}/cisco_analyzer.csv");
    let analyzer_csv = std::fs::File::open(analyzer_csv_path.clone())?;
    let mut csv = csv::Reader::from_reader(analyzer_csv);

    let analyzer = util::get_analyzer(topo_name, scenario_name)
        .map_err(|e| anyhow::Error::msg(e.to_string()))
        .with_context(|| {
            format!("Cannot build `Analyzer` for experiment in {analyzer_csv_path:?}")
        })?;

    let with_delayer = !scenario_name.contains("Delay0");

    for record in csv.deserialize() {
        let record: CiscoAnalyzerData = record?;
        let timestamp = record.execution_timestamp.clone();
        let skip_record_file = eval_path.then_pcap("skip_{}", &record.execution_timestamp);
        log::trace!("Reading from CSV:\n{record:#?}");

        if !record.execution_timestamp.contains(&args.sample_id) {
            log::trace!(
                "skipping {} due to filter on sample_id...",
                record.pcap_filename
            );
            continue;
        }

        match process_sample(&analyzer, record, eval_path, args.replace, with_delayer) {
            Ok(()) => {}
            Err(e) => {
                log::error!(
                    "Error processing {topo_name}/{scenario_name}/{timestamp}. Error:\n{e:?}\n\n",
                );
                // write the skip file
                std::fs::write(skip_record_file, format!("{e:?}\n").into_bytes())
                    .context("Write skip file")?;
            }
        }
    }

    Ok(())
}

fn process_sample(
    analyzer: &Analyzer<TimingModel<SimplePrefix>>,
    record: CiscoAnalyzerData,
    eval_path: &Path,
    replace: bool,
    with_delayer: bool,
) -> anyhow::Result<()> {
    let ts = &record.execution_timestamp;

    // make sure that no packets were dropped in the capture
    if record.packets_dropped != 0 {
        return Err(anyhow::Error::msg(format!(
            "Packet capture dropped {} packets",
            record.packets_dropped
        )));
    }
    let pcap_file = eval_path.then(&record.pcap_filename);
    let violations_file = eval_path.then_pcap("violations_new_{}.csv", ts);
    let path_record_file = eval_path.then_pcap("path_updates_new_{}.csv", ts);
    let fw_record_file = eval_path.then_pcap("fw_updates_new_{}.csv", ts);
    let skip_record_file = eval_path.then_pcap("skip_{}", ts);

    let output_exists =
        violations_file.exists() && path_record_file.exists() && fw_record_file.exists();
    let skip_exists = skip_record_file.exists();

    if (output_exists || skip_exists) && !replace {
        log::debug!("Skipping {:?}, as it was already processed", pcap_file);
        return Ok(());
    }

    // open hardware mapping
    let serialized_hardware_mapping =
        std::fs::read_to_string(eval_path.then(&record.hardware_mapping_filename))
            .context("Cannot read the hardware mapping!")?;
    let mapping: HardwareMapping = serde_json::from_str(&serialized_hardware_mapping)
        .context("Cannot deserialize the hardware mapping")?;
    let lut = Lut::from(mapping);

    let mut pcap_reader = PcapReader::new(flate2::read::GzDecoder::new(
        std::fs::File::open(&pcap_file).context("Cannot open the pcap file")?,
    ))
    .context("Cannot read the PCAP")?;

    let mut packets: HashMap<Flow, PacketData> = HashMap::new();
    let mut unparsed_packets: HashMap<Flow, Vec<Metadata>> = HashMap::new();

    let mut first_timestamp = -1.0;
    let mut last_timestamp = 0.0;

    log::info!("Reading {pcap_file:?}!");

    while let Some(next_packet) = pcap_reader.next_packet() {
        // skip packets that cannot be parsed
        let packet = next_packet.context("Cannot parse a PCAP packet")?;
        let Some(meta) = packet_metadata(packet) else {
            continue;
        };

        if first_timestamp < 0.0 {
            first_timestamp = meta.time;
        }
        last_timestamp = meta.time;

        let flow = Flow::from(meta);

        // insert the packet into the array. Only do so if the source mac is the prober mac (and is
        // thus the time at which the packet is injected)
        match packets.entry(flow) {
            Entry::Occupied(mut e) => {
                e.get_mut()
                    .push_next_path_segment(meta, &lut)
                    .with_context(|| format!("Cannot extend the path {}", e.get().fmt(&lut)))?;
            }
            Entry::Vacant(e) => {
                if meta.link.src.bytes() == PROBER_SRC_MAC {
                    let e =
                        e.insert(meta.new_packet_data(&lut).with_context(|| {
                            format!("Cannot create packet data of packet {meta}")
                        })?);
                    // now, push all unparsed packets of that flow into the thing, changing the
                    // timestamp to be equal to the current meta's timestamp
                    for mut unparsed_meta in unparsed_packets.remove(&flow).into_iter().flatten() {
                        unparsed_meta.time = meta.time;
                        e.push_next_path_segment(unparsed_meta, &lut)
                            .with_context(|| {
                                format!(
                                    "Cannot push unparsed packets to a new path {}",
                                    e.fmt(&lut)
                                )
                            })?;
                    }
                } else {
                    // Seen a packet in the middle of its path, without having seen its beginning.
                    // Remember that packet
                    unparsed_packets.entry(flow).or_default().push(meta);
                }
            }
        };
    }

    // cut off 1 second at each end to ensure we have seen each of the packets on their entire path
    let min_time = first_timestamp + 1.0;
    let max_time = last_timestamp - 1.0;

    // now, check the set of unparsed_packets. If there are packets with a timestamp inbetween
    // min_time and max_time, raise an error
    for metas in unparsed_packets.into_values() {
        for meta in metas {
            if meta.time > min_time && meta.time < max_time {
                return Err(anyhow::Error::msg(format!(
                    "Unparsed packet seen at {} , which is within {min_time} and {max_time}",
                    meta.time
                )));
            }
        }
    }

    type Paths = Vec<(Vec<RouterId>, u64, f64)>;
    let mut paths: HashMap<(RouterId, Ipv4Addr), Paths> = HashMap::new();

    // get the timing model
    let mut timing_model = analyzer.build_queue();

    // packets now contain all data
    for (flow, data) in packets.iter().sorted_by_key(|(k, _)| *k) {
        // skip that packet if the packet was seen in the first or last second
        if data.first_seen < min_time || data.first_seen > max_time {
            continue;
        }

        let path = data
            .try_generate_path(&lut, &mut timing_model, with_delayer)
            .with_context(|| format!("Invalid path {}\nPacket info: {:?}", data.fmt(&lut), flow))?;

        paths
            .entry((data.src, data.dst))
            .or_default()
            .push((path, flow.seq, data.first_seen));
    }

    // data validation
    for ps in paths.values() {
        let seen = ps.len() as u64;
        let expected = ps
            .iter()
            .map(|(_, idx, _)| idx)
            .minmax()
            .into_option()
            .map(|(min, max)| max - min)
            .unwrap_or(0);

        ensure!(
            10 * u64::abs_diff(seen, expected) < record.capture_frequency,
            "Haven't seen enough packets for the timespan! (seen: {seen}, expected: {expected})"
        );
    }

    // export naive ground truth for reachability violations
    let violations: Vec<(RouterId, Ipv4Addr, f64)> = paths
        .iter()
        .map(|((rid, prefix), ps)| {
            (
                *rid,
                *prefix,
                ps.iter()
                    .flat_map(|(rids, _idx, _t_first_seen)| {
                        rids.last().map(|rid| {
                            if analyzer.original_net.get_external_router(*rid).is_ok() {
                                1
                            } else {
                                0
                            }
                        })
                    })
                    .sum::<usize>() as f64
                    / record.capture_frequency as f64,
            )
        })
        .collect();
    write_csv(violations_file, violations, b',').context("Error writing the violations")?;

    // export all fw records
    let fw_records: Vec<FWRecord> = paths
        .iter()
        .flat_map(|((src, prefix), paths)| {
            paths.iter().map(|(p, seq, time)| FWRecord {
                time: *time,
                src: *src,
                src_name: lut.name.get(src).copied(),
                prefix: *prefix,
                seq: Some(*seq),
                next_hop: p.get(1).copied(),
                next_hop_name: p.get(1).and_then(|r| lut.name.get(r)).copied(),
            })
        })
        .collect();
    write_updates_csv(fw_record_file, fw_records, b',').context("Error writing the FW records")?;

    // export the paths
    let path_records: Vec<PathRecord> = paths
        .into_iter()
        .flat_map(|((src, prefix), paths)| {
            let src_name = lut.name.get(&src).copied();
            paths
                .into_iter()
                .map(|(path, seq, time)| (lut.path_name(&path), path, seq, time))
                .map(move |(path_names, path, seq, time)| PathRecord {
                    time,
                    src,
                    src_name,
                    prefix,
                    seq: Some(seq),
                    path,
                    path_names,
                })
        })
        .collect();
    write_updates_csv(path_record_file, path_records, b';')
        .context("Error writing the paths records")?;

    // delete the skip file if it exists
    if skip_record_file.exists() {
        std::fs::remove_file(skip_record_file).context("Cannot delete the skip_record file.")?;
    }

    log::info!("Finished processing sample {pcap_file:?}!");

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
struct Metadata {
    link: Link<MacAddress>,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    seq: u64,
    time: f64,
}

impl Metadata {
    fn next_path_segment(self, lut: &Lut) -> anyhow::Result<Option<(Link<RouterId>, f64)>> {
        let Some(link) = lut
            .neighbor
            .get(&self.link)
            .copied()
            .or_else(|| lut.last_mac_to_ext_rid.get(&self.link.src).copied())
        else {
            // ignore links that start from an external and go to a non-dead mac address
            let src_prefix = self
                .link
                .src
                .bytes()
                .into_iter()
                .take(4)
                .collect::<Vec<u8>>();
            let dst_prefix = self
                .link
                .dst
                .bytes()
                .into_iter()
                .take(2)
                .collect::<Vec<u8>>();
            if lut.externals_mac_prefixes.contains(&src_prefix) && dst_prefix != [0xde, 0xad] {
                return Ok(None);
            } else {
                return Err(anyhow::Error::msg(format!(
                    "Cannot find link {} in hardware mapping",
                    self.link
                )));
            }
        };
        Ok(Some((link, self.time)))
    }

    fn new_packet_data(self, lut: &Lut) -> anyhow::Result<PacketData> {
        Ok(PacketData {
            first_seen: self.time,
            src: *lut.prober_ip_to_rid.get(&self.src).ok_or_else(|| {
                anyhow::Error::msg(format!("Unknown prober source IP: {}", self.src))
            })?,
            dst: self.dst,
            path: Default::default(),
        })
    }
}

impl std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {}: seq {} (on link {})",
            self.src, self.dst, self.seq, self.link
        )
    }
}

impl From<Metadata> for Flow {
    fn from(value: Metadata) -> Self {
        Self {
            src: value.src,
            dst: value.dst,
            seq: value.seq,
        }
    }
}

fn packet_metadata(packet: PcapPacket<'_>) -> Option<Metadata> {
    if packet.orig_len < PROBER_PACKET_SIZE {
        return None;
    }

    // construct the packet
    let eth = ethernet::EthernetPacket::new(&packet.data)?;

    // check the type
    if eth.get_ethertype() != ethernet::EtherTypes::Ipv4 {
        return None;
    }

    let ip = ipv4::Ipv4Packet::new(eth.payload())?;

    // check the protocol is Test1
    if ip.get_next_level_protocol() != ip::IpNextHeaderProtocols::Test1 {
        return None;
    }

    // get the sequence number
    let seq = ip.payload().try_into().map(u64::from_be_bytes).ok()?;

    // get the packet metadata
    Some(Metadata {
        link: Link {
            src: MacAddress::from(eth.get_source().octets()),
            dst: MacAddress::from(eth.get_destination().octets()),
        },
        src: ip.get_source(),
        dst: ip.get_destination(),
        time: packet.timestamp.as_secs_f64(),
        seq,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Flow {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    seq: u64,
}

pub struct PacketData {
    first_seen: f64,
    src: RouterId,
    dst: Ipv4Addr,
    path: Vec<(Link<RouterId>, f64)>,
}

impl PacketData {
    fn fmt(&self, lut: &Lut) -> String {
        let name = |r| {
            lut.name
                .get(&r)
                .map(|x| x.to_string())
                .unwrap_or(format!("r{}", r.index()))
        };
        format!(
            "{{[{}] raw path: {} -> {}, [{}]}}",
            self.first_seen,
            name(self.src),
            self.dst,
            self.path
                .iter()
                .map(|(e, t)| format!(
                    "{} -> {} ({})",
                    name(e.src),
                    name(e.dst),
                    t - self.first_seen
                ))
                .join("; ")
        )
    }

    fn push_next_path_segment(&mut self, meta: Metadata, lut: &Lut) -> anyhow::Result<()> {
        match meta.next_path_segment(lut) {
            Ok(Some(seg)) => self.path.push(seg),
            Ok(None) => {}
            Err(e) => {
                Err(e).with_context(|| format!("Cannot get path segment of packet {meta}"))?
            }
        }
        Ok(())
    }

    fn try_generate_path_no_delayer(&self, lut: &Lut) -> anyhow::Result<Vec<RouterId>> {
        let mut path = vec![self.src];

        // no checks necessary if the path is immediately dropped
        if self.path.is_empty() {
            return Ok(Vec::new());
        }

        let mut cleaned_path = self.path.clone();
        for i1 in 1..path.len() {
            let (p1, t1) = cleaned_path[i1];
            let (p0, t0) = cleaned_path[i1 - 1];

            let time_diff = (t1 - t0).abs();
            let time_diff_is_small = time_diff < 0.0001;

            // swap p1 and p2 if their timestamp is equal, they are reversed (p1.src == p2.dst), and
            // p2 is equal to p0 (the packet before p1).
            if time_diff_is_small && p0.src == p1.dst {
                // swap the time first
                cleaned_path[i1].1 = t0;
                cleaned_path[i1 - 1].1 = t1;
                // swap the packet order
                cleaned_path.swap(i1 - 1, i1)
            }
        }

        let mut cur_time = self.first_seen;

        for (link, time) in cleaned_path {
            // 1. check that all times are increasing
            if time < cur_time {
                return Err(anyhow::Error::msg("Packet was time-traveling"));
            }

            // 2. Check that an external router can never be the source
            if lut.externals.contains(&link.src) {
                return Err(anyhow::Error::msg("Edge with source as an external router"));
            }

            // Check that the path always starts from the currently last router on the path
            if *path.last().unwrap() != link.src {
                return Err(anyhow::Error::msg(format!(
                        "Path is not a sequence of connected edges. next link: {link:?}, Path: {path:?}",
                    )));
            }
            path.push(link.dst);

            // update the current time
            cur_time = time;
        }

        Ok(path)
    }

    // The path will always have at least length 1
    fn try_generate_path(
        &self,
        lut: &Lut,
        timing_model: &mut TimingModel<Prefix>,
        with_delayer: bool,
    ) -> anyhow::Result<Vec<RouterId>> {
        if !with_delayer {
            return self.try_generate_path_no_delayer(lut);
        }
        let mut path = vec![self.src];

        // no checks necessary if the path is immediately dropped
        if self.path.is_empty() {
            return Ok(Vec::new());
        }

        let mut cleaned_path = self.path.clone();
        for i2 in 2..path.len() {
            let (p2, t2) = cleaned_path[i2];
            let (p1, t1) = cleaned_path[i2 - 1];
            let (p0, _) = cleaned_path[i2 - 2];

            let time_diff = (t2 - t1).abs();
            let time_diff_is_small = time_diff < 0.0001;

            // swap p1 and p2 if their timestamp is equal, they are reversed (p1.src == p2.dst), and
            // p2 is equal to p0 (the packet before p1).
            if time_diff_is_small && p1.src == p2.dst && p0 == p2 {
                // swap the time first
                cleaned_path[i2].1 = t1;
                cleaned_path[i2 - 1].1 = t2;
                // swap the packet order
                cleaned_path.swap(i2 - 1, i2)
            }
        }

        let mut cur_time = self.first_seen;
        let mut cur_link = None;
        let mut cur_link_count = 0;
        let mut delayer_time = 0.0;
        let mut exp_delayer_time = 0.0;

        for (link, time) in cleaned_path {
            // 1. check that all times are increasing
            if time < cur_time {
                return Err(anyhow::Error::msg("Packet was time-traveling"));
            }

            // 2. Check that an external router can never be the source
            if lut.externals.contains(&link.src) {
                return Err(anyhow::Error::msg("Edge with source as an external router"));
            }

            // 3. check that each inner link is seen twice
            if cur_link != Some(link) {
                if cur_link.is_some() && cur_link_count != 2 {
                    return Err(anyhow::Error::msg(format!(
                        "An internal link was seen {cur_link_count} times",
                    )));
                }
                cur_link = Some(link);
                cur_link_count = 1;
            } else {
                cur_link_count += 1;
            }

            // 4. Check that each delay is small enough
            if cur_link_count == 2 {
                delayer_time += time - cur_time;
                exp_delayer_time += timing_model.get_delay(link.src, link.dst);
            }

            // 5. push the destination of that link, but only if it was seen for the first time
            if cur_link_count == 1 {
                // Check that the path always starts from the currently last router on the path
                if *path.last().unwrap() != link.src {
                    return Err(anyhow::Error::msg(format!(
                        "Path is not a sequence of connected edges. next link: {link:?}, Path: {path:?}",
                    )));
                }
                path.push(link.dst);
            }

            // update the current time
            cur_time = time;
        }

        // 6. check that the last link is visited once if and only if it is an external router
        let exp_link_count = if lut.externals.contains(path.last().unwrap()) {
            1
        } else {
            2
        };
        if cur_link_count != exp_link_count {
            let msg = if cur_link_count == 1 && exp_link_count == 2 {
                "Packet was dropped by a delayer!".to_string()
            } else {
                format!(
                    "The last link was seen {cur_link_count} times instead of {exp_link_count}.",
                )
            };
            return Err(anyhow::Error::msg(msg));
        }

        let min_expected = exp_delayer_time * 0.5;
        let max_expected = exp_delayer_time * 3.0;

        // 7. Check that each delay is small enough
        if delayer_time < min_expected || delayer_time > max_expected {
            return Err(anyhow::Error::msg(format!(
                "The path delay is {delayer_time}, expected {exp_delayer_time} (between {min_expected} and {max_expected})"
            )));
        }

        Ok(path)
    }
}

struct Lut {
    prober_ip_to_rid: HashMap<Ipv4Addr, RouterId>,
    last_mac_to_ext_rid: HashMap<MacAddress, Link<RouterId>>,
    neighbor: HashMap<Link<MacAddress>, Link<RouterId>>,
    externals: HashSet<RouterId>,
    externals_mac_prefixes: HashSet<Vec<u8>>,
    name: HashMap<RouterId, Router>,
}

impl Lut {
    fn path_name(&self, path: &[RouterId]) -> Vec<Option<Router>> {
        path.iter().map(|r| self.name.get(r).copied()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link<T> {
    src: T,
    dst: T,
}

impl<T: std::fmt::Display> std::fmt::Display for Link<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

impl From<HardwareMapping> for Lut {
    fn from(hardware_mapping: HardwareMapping) -> Self {
        // allows to get the `RouterId` (rid) of an internal router from its corresponding
        // prober src ip address
        let prober_ip_to_rid = hardware_mapping
            .iter()
            // external routers do not send prober packets
            .filter(|(_, router)| !router.is_external)
            .map(|(rid, router)| (router.prober_src_ip.unwrap(), *rid))
            .collect();

        // allows to get rids of an internal router and its connected external router
        let last_mac_to_ext_rid = hardware_mapping
            .iter()
            // external routers do not send prober packets
            .filter(|(_, router)| router.is_external)
            .map(|(ext, router)| {
                assert!(router.ifaces.len() == 1);
                (
                    router.ifaces[0].neighbor_mac.unwrap(),
                    Link {
                        src: router.ifaces[0].neighbor,
                        dst: *ext,
                    },
                )
            })
            .collect();

        // allows to get rids of neighboring internal routers
        let neighbor = hardware_mapping
            .iter()
            .filter(|(_, router)| !router.is_external)
            .flat_map(|(rid, router)| {
                router
                    .ifaces
                    .iter()
                    .filter(|iface| iface.neighbor_mac.is_some())
                    .map(|iface| {
                        (
                            Link {
                                src: iface.mac.unwrap(),
                                dst: iface.neighbor_mac.unwrap(),
                            },
                            Link {
                                src: *rid,
                                dst: iface.neighbor,
                            },
                        )
                    })
            })
            .collect();

        let name = hardware_mapping
            .iter()
            .filter_map(|(rid, router)| Router::from_str(&router.name).ok().map(|n| (*rid, n)))
            .collect();

        let externals = hardware_mapping
            .iter()
            .filter(|(_, router)| router.is_external)
            .map(|(r, _)| *r)
            .collect();

        let externals_mac_prefixes = hardware_mapping
            .iter()
            .filter(|(_, router)| router.is_external)
            .flat_map(|(_, router)| router.ifaces.iter())
            .filter_map(|i| i.mac)
            .map(|mac| mac.bytes().into_iter().take(4).collect())
            .collect();

        Self {
            prober_ip_to_rid,
            last_mac_to_ext_rid,
            neighbor,
            externals,
            externals_mac_prefixes,
            name,
        }
    }
}

trait SerializableRecord: serde::Serialize {
    fn time(&self) -> f64;
    fn key(&self) -> (RouterId, Ipv4Addr);
    fn val(&self) -> &[RouterId];
}

impl SerializableRecord for FWRecord {
    fn time(&self) -> f64 {
        self.time
    }

    fn key(&self) -> (RouterId, Ipv4Addr) {
        (self.src, self.prefix)
    }

    fn val(&self) -> &[RouterId] {
        self.next_hop.as_slice()
    }
}

impl SerializableRecord for PathRecord {
    fn time(&self) -> f64 {
        self.time
    }

    fn key(&self) -> (RouterId, Ipv4Addr) {
        (self.src, self.prefix)
    }

    fn val(&self) -> &[RouterId] {
        self.path.as_slice()
    }
}

fn write_csv<R: serde::Serialize>(
    path: impl AsRef<Path>,
    data: Vec<R>,
    delimiter: u8,
) -> anyhow::Result<()> {
    let mut fw_writer = csv::WriterBuilder::new()
        .has_headers(true)
        .delimiter(delimiter)
        .from_writer(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path.as_ref())
                .context("Cannot create the file")?,
        );
    for record in data {
        fw_writer
            .serialize(record)
            .context("Cannot serialize a record")?;
    }
    Ok(())
}

fn write_updates_csv<R: SerializableRecord>(
    path: impl AsRef<Path>,
    mut data: Vec<R>,
    delimiter: u8,
) -> anyhow::Result<()> {
    data.sort_by(|a, b| a.time().total_cmp(&b.time()));
    let mut fw_writer = csv::WriterBuilder::new()
        .has_headers(true)
        .delimiter(delimiter)
        .from_writer(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path.as_ref())
                .context("Cannot create the file")?,
        );
    let mut last: HashMap<(RouterId, Ipv4Addr), Vec<RouterId>> = HashMap::new();
    for record in data {
        let this = record.val();
        match last.entry(record.key()) {
            Entry::Occupied(mut e) => {
                if e.get() == this {
                    continue;
                }
                e.insert(this.to_vec());
            }
            Entry::Vacant(e) => {
                e.insert(this.to_vec());
            }
        }
        fw_writer
            .serialize(record)
            .context("Cannot serialize a record")?;
    }
    Ok(())
}
