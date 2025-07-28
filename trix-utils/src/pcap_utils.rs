//! Module to handle PCAP files containing BGPseer experiment traffic

use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};

use ipnet::Ipv4Net;
use itertools::Itertools;
use pnet::util::MacAddr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use router_lab::hardware_mapping::RouterMapping;

use crate::serde::CiscoAnalyzerData;

pub const PROBER_PACKET_SIZE: u32 = 60;
pub const PROBER_SRC_MAC: &str = "de:ad:be:ef:00:00";

#[derive(Clone, Debug)]
pub enum PcapFilter {
    All(PacketFilter),
    First(PacketFilter),
    Last(PacketFilter),
}

impl PcapFilter {
    pub fn filter(&self, pcap_path: &Path) -> Vec<Vec<String>> {
        match self {
            Self::All(pf) => pf.filter_pcap(pcap_path),
            Self::First(pf) => {
                vec![pf.filter_pcap(pcap_path).into_iter().last().unwrap()]
            }
            Self::Last(pf) => vec![pf.filter_pcap(pcap_path).into_iter().last().unwrap()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    BGPAnnounce,
    BGPWithdraw,
}

#[derive(Clone, Debug, Default)]
pub struct PacketFilter {
    /// define the parsed fields of tshark
    pub outputs: Vec<String>,

    /// optional basic packet-filter options (tcpdump)
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
    pub src_mac_prefix: Option<MacPrefix>,
    pub dst_mac_prefix: Option<MacPrefix>,
    pub not_src_mac_prefix: Option<MacPrefix>,
    pub not_dst_mac_prefix: Option<MacPrefix>,
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub not_src_ip: Option<Ipv4Addr>,
    pub not_dst_ip: Option<Ipv4Addr>,
    pub src_net: Option<Ipv4Net>,
    pub dst_net: Option<Ipv4Net>,
    pub port: Option<u32>,

    /// tshark display filter
    pub filter: String,
}

#[derive(Clone, Debug)]
pub struct RouterFilter {
    pub mac_prefix: Option<MacPrefix>,
    pub ipv4: Option<Ipv4Addr>,
}

impl From<&RouterMapping> for RouterFilter {
    /// Extract data required for a `RouterFilter` from a `RouterMapping`. If interfaces are
    /// present, it will choose the first 4 bytes of the first interface listed as a mac_prefix.
    fn from(mapping: &RouterMapping) -> Self {
        RouterFilter {
            mac_prefix: mapping
                .ifaces
                .first()
                .and_then(|iface| iface.mac.map(|mac| MacPrefix::from(mac.to_string()))),
            ipv4: Some(mapping.ipv4),
        }
    }
}

/// Struct to allow extracting a mac prefix from a string such as "aa:bb:cc:dd:ee:ff".
#[derive(Clone, Debug)]
pub struct MacPrefix(String);

impl<T: AsRef<str>> From<T> for MacPrefix {
    fn from(value: T) -> MacPrefix {
        let mut mac_prefix = value.as_ref().split(':').collect_vec()[0..4].join("");
        mac_prefix.insert_str(0, "0x");
        MacPrefix(mac_prefix)
    }
}

impl PacketFilter {
    /// Create the most basic `PacketFilter`
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder API: Generic update function that can mutate all fields of the `PacketFilter`.
    pub fn update<F: FnOnce(&mut PacketFilter)>(&mut self, update_function: F) -> &mut Self {
        update_function(self);
        self
    }

    /// Builder API: Generic update function that can mutate all fields of the `PacketFilter`.
    pub fn update_fallible<E, F: FnOnce(&mut PacketFilter) -> Result<(), E>>(
        &mut self,
        update_function: F,
    ) -> Result<&mut Self, E> {
        update_function(self)?;
        Ok(self)
    }

    /// Builder API: Assign output fields.
    pub fn outputs(&mut self, outputs: Vec<String>) -> &mut Self {
        self.outputs = outputs;
        self
    }

    /// Builder API: Assign src_mac filter.
    pub fn src_mac(&mut self, src_mac: MacAddr) -> &mut Self {
        self.src_mac = Some(src_mac);
        self
    }

    /// Builder API: Assign dst_mac filter.
    pub fn dst_mac(&mut self, dst_mac: MacAddr) -> &mut Self {
        self.dst_mac = Some(dst_mac);
        self
    }

    /// Builder API: Assign src_mac_prefix filter.
    pub fn src_mac_prefix(&mut self, src_mac_prefix: MacPrefix) -> &mut Self {
        self.src_mac_prefix = Some(src_mac_prefix);
        self
    }

    /// Builder API: Assign dst_mac_prefix filter.
    pub fn dst_mac_prefix(&mut self, dst_mac_prefix: MacPrefix) -> &mut Self {
        self.dst_mac_prefix = Some(dst_mac_prefix);
        self
    }

    /// Builder API: Assign not_src_mac_prefix filter.
    pub fn not_src_mac_prefix(&mut self, not_src_mac_prefix: MacPrefix) -> &mut Self {
        self.not_src_mac_prefix = Some(not_src_mac_prefix);
        self
    }

    /// Builder API: Assign not_dst_mac_prefix filter.
    pub fn not_dst_mac_prefix(&mut self, not_dst_mac_prefix: MacPrefix) -> &mut Self {
        self.not_dst_mac_prefix = Some(not_dst_mac_prefix);
        self
    }

    /// Builder API: Assign src_ip filter.
    pub fn src_ip(&mut self, src_ip: Ipv4Addr) -> &mut Self {
        self.src_ip = Some(src_ip);
        self
    }

    /// Builder API: Assign not_src_ip filter.
    pub fn not_src_ip(&mut self, not_src_ip: Ipv4Addr) -> &mut Self {
        self.not_src_ip = Some(not_src_ip);
        self
    }

    /// Builder API: Assign dst_ip filter.
    pub fn dst_ip(&mut self, dst_ip: Ipv4Addr) -> &mut Self {
        self.dst_ip = Some(dst_ip);
        self
    }

    /// Builder API: Assign not_dst_ip filter.
    pub fn not_dst_ip(&mut self, not_dst_ip: Ipv4Addr) -> &mut Self {
        self.not_dst_ip = Some(not_dst_ip);
        self
    }

    /// Builder API: Assign src_net filter.
    pub fn src_net(&mut self, src_net: Ipv4Net) -> &mut Self {
        self.src_net = Some(src_net);
        self
    }

    /// Builder API: Assign dst_net filter.
    pub fn dst_net(&mut self, dst_net: Ipv4Net) -> &mut Self {
        self.dst_net = Some(dst_net);
        self
    }

    /// Allows to append the filter `String`
    fn append_filter(&mut self, filter: &str) -> &mut Self {
        if !self.filter.is_empty() {
            self.filter += " && ";
            self.filter += filter;
        } else {
            self.filter = filter.to_string();
        }
        self
    }

    /// Builder API: match on the sender of the packets
    pub fn from_router(&mut self, router_info: impl Into<RouterFilter>) -> &mut Self {
        let router_info = router_info.into();
        if self.src_ip.is_none() {
            self.src_ip = router_info.ipv4;
        } else if router_info.ipv4.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        if self.src_mac_prefix.is_none() {
            self.src_mac_prefix = router_info.mac_prefix;
        } else if router_info.mac_prefix.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        self
    }

    /// Builder API: anti-match on the sender of the packets
    pub fn not_from_router(&mut self, router_info: impl Into<RouterFilter>) -> &mut Self {
        let router_info = router_info.into();
        if self.not_src_ip.is_none() {
            self.not_src_ip = router_info.ipv4;
        } else if router_info.ipv4.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        if self.not_src_mac_prefix.is_none() {
            self.not_src_mac_prefix = router_info.mac_prefix;
        } else if router_info.mac_prefix.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        self
    }

    /// Builder API: match on the receiver of the packets
    pub fn to_router(&mut self, router_info: impl Into<RouterFilter>) -> &mut Self {
        let router_info = router_info.into();
        if self.dst_ip.is_none() {
            self.dst_ip = router_info.ipv4;
        } else if router_info.ipv4.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        if self.dst_mac_prefix.is_none() {
            self.dst_mac_prefix = router_info.mac_prefix;
        } else if router_info.mac_prefix.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        self
    }

    /// Builder API: anti-match on the receiver of the packets
    pub fn not_to_router(&mut self, router_info: impl Into<RouterFilter>) -> &mut Self {
        let router_info = router_info.into();
        if self.not_dst_ip.is_none() {
            self.not_dst_ip = router_info.ipv4;
        } else if router_info.ipv4.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        if self.not_dst_mac_prefix.is_none() {
            self.not_dst_mac_prefix = router_info.mac_prefix;
        } else if router_info.mac_prefix.is_some() {
            panic!("builder api should not reassign filter values!");
        }
        self
    }

    /// Builder API: match on the sender subnet of the packets
    pub fn from_net(&mut self, net_info: impl Into<Ipv4Net>) -> &mut Self {
        let net_info = net_info.into();
        if self.src_net.is_none() {
            self.src_net = Some(net_info);
        } else {
            panic!("builder api should not reassign filter values!");
        }
        self
    }

    /// Builder API: match on the receiver subnet of the packets
    pub fn to_net(&mut self, net_info: impl Into<Ipv4Net>) -> &mut Self {
        let net_info = net_info.into();
        if self.dst_net.is_none() {
            self.dst_net = Some(net_info);
        } else {
            panic!("builder api should not reassign filter values!");
        }
        self
    }

    /// Builder API: Filter by message type.
    pub fn message_type(&mut self, msg_type: MessageType) -> &mut Self {
        match msg_type {
            MessageType::BGPAnnounce => {
                self.bgp_announce();
            }
            MessageType::BGPWithdraw => {
                self.bgp_withdraw();
            }
        }
        self
    }

    /// Builder API: Filter for BGP packets on port 179 and ignorie keep-alive messages.
    pub(crate) fn _bgp(&mut self) -> &mut Self {
        if self.port.is_none() {
            self.port = Some(179);
        } else {
            panic!("builder api should not reassign filter values!");
        }

        self.append_filter("(!bgp.type || bgp.type == 2)");

        self
    }

    /// Builder API: Filter for BGP packets (ignoring keep-alive messages) containing
    /// announcements.
    pub fn bgp_announce(&mut self) -> &mut Self {
        self._bgp();

        self.outputs = [
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "eth.src",
            "eth.dst",
            "tcp.seq",
            "bgp.mp_reach_nlri_ipv4_prefix",
        ]
        .into_iter()
        .map(|x| x.to_string())
        .collect_vec();

        self
    }

    /// Builder API: Filter for BGP packets (ignoring keep-alive messages) containing withdraws.
    pub fn bgp_withdraw(&mut self) -> &mut Self {
        self._bgp();

        self.outputs = [
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "eth.src",
            "eth.dst",
            "tcp.seq",
            "bgp.mp_unreach_nlri_ipv4_prefix",
        ]
        .into_iter()
        .map(|x| x.to_string())
        .collect_vec();

        self
    }

    /// Build a basic packet filter according to the defined `PacketFilter` and return a
    /// well-parenthesized filter `String` for use with `tcpdump`.
    pub fn tcpdump_filter(&self) -> String {
        let mut filter_parts = Vec::new();

        // add each component if defined
        if let Some(src_mac) = self.src_mac {
            filter_parts.push("ether src ".to_string() + &src_mac.to_string());
        }
        if let Some(dst_mac) = self.dst_mac {
            filter_parts.push("ether dst ".to_string() + &dst_mac.to_string());
        }
        if let Some(src_mac_prefix) = &self.src_mac_prefix {
            filter_parts.push("ether[6:4] == ".to_string() + &src_mac_prefix.0);
        }
        if let Some(dst_mac_prefix) = &self.dst_mac_prefix {
            filter_parts.push("ether[0:4] == ".to_string() + &dst_mac_prefix.0);
        }
        if let Some(not_src_mac_prefix) = &self.not_src_mac_prefix {
            filter_parts.push("ether[6:4] != ".to_string() + &not_src_mac_prefix.0);
        }
        if let Some(not_dst_mac_prefix) = &self.not_dst_mac_prefix {
            filter_parts.push("ether[0:4] != ".to_string() + &not_dst_mac_prefix.0);
        }
        if let Some(src_ip) = self.src_ip {
            filter_parts.push("src ".to_string() + &src_ip.to_string());
        }
        if let Some(dst_ip) = self.dst_ip {
            filter_parts.push("dst ".to_string() + &dst_ip.to_string());
        }
        if let Some(not_src_ip) = self.not_src_ip {
            filter_parts.push("not src ".to_string() + &not_src_ip.to_string());
        }
        if let Some(not_dst_ip) = self.not_dst_ip {
            filter_parts.push("not dst ".to_string() + &not_dst_ip.to_string());
        }
        if let Some(src_net) = self.src_net {
            filter_parts.push("src net ".to_string() + &src_net.to_string());
        }
        if let Some(dst_net) = self.dst_net {
            filter_parts.push("dst net ".to_string() + &dst_net.to_string());
        }
        if let Some(port) = self.port {
            filter_parts.push("port ".to_string() + &port.to_string());
        }

        if filter_parts.is_empty() {
            "".to_string()
        } else {
            // combine to a well-parenthesized filter string
            "((".to_string() + &filter_parts.join(") and (") + "))"
        }
    }

    /// Filter a pcap file according to the defined `PacketFilter` and return a `Vec<Vec<String>>`
    /// containing all the specified `output` fields in order.
    ///
    /// For speeding up the processing, the pcap file is first prefiltered by `tcpdump` with all
    /// basic packet filters, and then piped into `tshark` to allow decoding more protocols.
    pub fn filter_pcap(&self, pcap_path: &Path) -> Vec<Vec<String>> {
        #[rustfmt::skip]
        let tcpdump_args = [
            "-r", &pcap_path.to_string_lossy(),
            &self.tcpdump_filter(),
            "-w", "-",
        ];
        #[rustfmt::skip]
        let tshark_args = [
            "-r", "-",
            "-Y", &self.filter,
            "-T", "fields",
            "-E", "separator=;",
        ].into_iter().chain(
                    self.outputs
                        .iter()
                        .flat_map(|output| ["-e", output.as_str()].into_iter()),
        ).collect_vec();

        log::debug!(
            "Running:\ntcpdump '{}' | tshark '{}'",
            tcpdump_args.join("' '"),
            tshark_args.join("' '")
        );

        // run pre-filter with tcpdump
        let tcpdump = Command::new("tcpdump")
            .args(tcpdump_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        // extract output fields with tshark
        let tshark = Command::new("tshark")
            .args(tshark_args)
            .stdin(std::process::Stdio::from(tcpdump.stdout.unwrap()))
            .output()
            .unwrap()
            .stdout;

        // split into rows and columns
        String::from_utf8_lossy(&tshark)
            .split('\n')
            .filter(|line| !line.is_empty())
            .map(|line| line.split(';').map(|x| x.to_owned()).collect_vec())
            .collect_vec()
    }
}

/// List all scenarios matching the filters.
pub fn get_scenarios(
    filter_topo: &str,
    filter_scenario: &str,
    filter_scenario_not: &str,
    filter_scenario_end: &str,
) -> Vec<(String, String, PathBuf, PathBuf, csv::Reader<fs::File>)> {
    fs::read_dir("./experiments/")
        .expect("./experiments/ cannot be read")
        .flat_map(|topo_dir| {
            let topo_path = topo_dir.unwrap().path();

            fs::read_dir(topo_path.display().to_string())
                .unwrap()
                .map(move |scenario_dir| {
                    (
                        topo_path.clone(),
                        scenario_dir
                            .unwrap()
                            .path()
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .to_string(),
                    )
                })
                .filter(|(topo_path, scenario)| {
                    topo_path.display().to_string().contains(filter_topo)
                        && scenario.contains(filter_scenario)
                        && !scenario.contains(filter_scenario_not)
                        && scenario.ends_with(filter_scenario_end)
                })
        })
        .unique()
        .filter_map(|(topo_path, scenario)| {
            let mut scenario_path = topo_path.clone();
            scenario_path.push(&scenario);
            scenario_path.push("scenario.json");
            if !scenario_path.exists() {
                log::trace!("Skipping non-existent scenario from {scenario_path:?}");
                return None; // `return None;` in a `filter_map(...)` is equivalent to `continue;`
            }

            // get the correct output folder name
            scenario_path.pop(); // remove "scenario.json"
            let scenario_name = scenario_path.file_name().unwrap();
            let topo_name = topo_path.file_name().unwrap();

            //let data_root = "./data/";
            let data_root = "/media/roschmi-data-hdd/orval-backup/data/";
            let mut data_path = PathBuf::from(data_root);
            data_path.push(format!("{}", topo_name.to_string_lossy()));
            data_path.push(format!("{}", scenario_name.to_string_lossy()));

            if !data_path.exists() {
                return None; // `return None;` in a `filter_map(...)` is equivalent to `continue;`
            }

            // evaluate the data captured by the cisco_analyzer
            let mut analyzer_csv_path = data_path.clone();
            analyzer_csv_path.push("cisco_analyzer.csv");
            if !analyzer_csv_path.exists() {
                log::trace!(
                    "Skipping scenario from {analyzer_csv_path:?} as it has no captured data yet."
                );
                return None; // `return None;` in a `filter_map(...)` is equivalent to `continue;`
            }
            log::info!("Loading: {scenario_path:?}");
            let analyzer_csv = fs::File::open(analyzer_csv_path).unwrap();
            let csv = csv::Reader::from_reader(analyzer_csv);

            Some((
                topo_name.to_string_lossy().to_string(),
                scenario_name.to_string_lossy().to_string(),
                scenario_path,
                data_path,
                csv,
            ))
        })
        .collect_vec()
}

/// Process data in parallel for all experiments grouped by scenario.
///
/// Selects scenarios matching the filters and applies the given function.
///
/// Callback signature:
/// ```ignore
/// fn process_scenario(
///     topo_name: String,
///     scenario_name: String,
///     data_path: PathBuf,
///     csv: csv::Reader<fs::File>
/// )
/// ```
pub fn process_scenarios<F, T>(
    tmp_pcap_dir: &Path,
    filter_topo: &str,
    filter_scenario: &str,
    filter_scenario_not: &str,
    filter_scenario_end: &str,
    process_scenario: F,
) -> Result<Vec<T>, Box<dyn std::error::Error>>
where
    F: Fn(String, String, PathBuf, PathBuf, csv::Reader<fs::File>) -> T + Send + Sync,
    T: Clone + Send,
{
    fs::create_dir_all(tmp_pcap_dir)?;

    // get all (topo, scenario) combinations
    Ok(get_scenarios(
        filter_topo,
        filter_scenario,
        filter_scenario_not,
        filter_scenario_end,
    )
    .into_par_iter()
    .map(
        |(topo_name, scenario_name, scenario_path, data_path, csv)| {
            process_scenario(topo_name, scenario_name, scenario_path, data_path, csv)
        },
    )
    .collect::<Vec<_>>())
}

/// List all pcaps matching the filters.
pub fn get_pcaps(
    filter_topo: &str,
    filter_scenario: &str,
    filter_scenario_not: &str,
    filter_scenario_end: &str,
) -> Vec<(PathBuf, CiscoAnalyzerData)> {
    get_scenarios(
        filter_topo,
        filter_scenario,
        filter_scenario_not,
        filter_scenario_end,
    )
    .into_iter()
    .flat_map(|(_, _, _, data_path, mut csv)| {
        let mut result = Vec::new();
        for record in csv.deserialize() {
            let record: CiscoAnalyzerData = record.unwrap();
            log::trace!("Reading from CSV:\n{record:#?}");

            /*
            if !record.execution_timestamp.contains(filter_sample_id) {
                log::trace!(
                    "skipping {} due to filter on sample_id...",
                    record.pcap_filename
                );
                continue;
            }
            */

            if record.packets_dropped != 0 {
                log::trace!(
                    "skipping {} due to dropped packets...",
                    record.pcap_filename
                );
                continue;
            }

            let mut orig_pcap_path = data_path.clone();
            orig_pcap_path.push(&record.pcap_filename);

            result.push((orig_pcap_path, record));
        }
        result.into_iter()
    })
    .collect_vec()
}

/// Process pcaps in parallel for all experiments matching the filters.
///
/// Copies pcaps to `tmp_pcap_dir` and applies the given function.
pub fn process_pcaps<F, T>(
    tmp_pcap_dir: &Path,
    filter_topo: &str,
    filter_scenario: &str,
    filter_scenario_not: &str,
    filter_scenario_end: &str,
    process_pcap: F,
) -> Result<Vec<T>, Box<dyn std::error::Error>>
where
    F: Fn(&PathBuf) -> T + Send + Sync,
    T: Clone + Send,
{
    fs::create_dir_all(tmp_pcap_dir)?;

    // get all (topo, scenario) combinations
    Ok(get_pcaps(
        filter_topo,
        filter_scenario,
        filter_scenario_not,
        filter_scenario_end,
    )
    .into_par_iter()
    .map(|(orig_pcap_path, record)| {
        /*
        #[cfg(feature = "incremental")]
        if reaction_times
            .iter()
            .any(|s| s.sample_id == record.execution_timestamp)
        {
            log::trace!(
                "skipping {} due to incremental processing...",
                record.pcap_filename
            );
            continue;
        }
        */
        let pcap_path = copy_and_unzip_pcap(&orig_pcap_path, tmp_pcap_dir, &record.pcap_filename);

        let result = process_pcap(&pcap_path);

        // remove the unzipped pcap file again
        let _ = Command::new("rm")
            .arg(pcap_path.to_string_lossy().to_string())
            .output();

        result
    })
    .collect::<Vec<_>>())
}

/// Copies pcap to `tmp_pcap_dir` and unzips the file using `gunzip`.
pub fn copy_and_unzip_pcap(
    orig_pcap_path: &Path,
    tmp_pcap_dir: &Path,
    pcap_filename: &str,
) -> PathBuf {
    // set new location for faster unzip
    let mut pcap_path = tmp_pcap_dir.to_path_buf();
    pcap_path.push(pcap_filename);

    // unzip the pcap file
    let _ = Command::new("cp")
        .args([
            &orig_pcap_path.to_string_lossy().to_string(),
            &pcap_path.to_string_lossy().to_string(),
        ])
        .output();

    log::trace!("unzipping {pcap_path:?}");
    let _ = Command::new("gunzip")
        .args(["-k", pcap_path.to_string_lossy().as_ref()])
        .output();
    // drop the .gz part of the filename
    pcap_path.set_extension("");

    pcap_path
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn build_tcpdump_filter() {
        // define an empty `PacketFilter`
        let mut packet_filter = PacketFilter {
            ..Default::default()
        };
        assert_eq!(packet_filter.tcpdump_filter(), "".to_string());

        // add some property
        packet_filter.port = Some(8080);
        assert_eq!(packet_filter.tcpdump_filter(), "((port 8080))".to_string());

        // add another property
        packet_filter.src_ip = Some(Ipv4Addr::new(100, 0, 0, 1));
        assert_eq!(
            packet_filter.tcpdump_filter(),
            "((src 100.0.0.1) and (port 8080))".to_string()
        );

        // add an irrelevant property
        packet_filter.filter = "This should not matter at all.".to_string();
        assert_eq!(
            packet_filter.tcpdump_filter(),
            "((src 100.0.0.1) and (port 8080))".to_string()
        );
    }

    #[test]
    fn mac_prefix() {
        assert_eq!(MacPrefix::from("aa:bb:cc:dd").0, "0xaabbccdd");
        assert_eq!(MacPrefix::from("aa:bb:cc:dd:ee:ff").0, "0xaabbccdd");
    }
}
