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
    collections::{BTreeMap, HashMap},
    fs,
    net::Ipv4Addr,
    path::Path,
};

use itertools::Itertools;
use plotly::{
    common::{DashType, Fill, HoverInfo, HoverOn, Line, Marker, MarkerSymbol, Mode, Visible},
    layout::{Axis, HoverMode},
    Plot, Scatter,
};

use trix::{records::*, util::PathBufExt};

#[derive(Debug, Default, Clone)]
struct TimeSeries<T> {
    t: Vec<f64>,
    y: Vec<T>,
}

impl<T> FromIterator<(f64, T)> for TimeSeries<T> {
    fn from_iter<I: IntoIterator<Item = (f64, T)>>(iter: I) -> Self {
        let (t, y) = iter.into_iter().multiunzip();
        Self { t, y }
    }
}

impl<T> IntoIterator for TimeSeries<T> {
    type Item = (f64, T);

    type IntoIter = std::iter::Zip<std::vec::IntoIter<f64>, std::vec::IntoIter<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.t.into_iter().zip(self.y)
    }
}

impl<'a, T> IntoIterator for &'a TimeSeries<T> {
    type Item = (&'a f64, &'a T);

    type IntoIter = std::iter::Zip<std::slice::Iter<'a, f64>, std::slice::Iter<'a, T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.t.iter().zip(self.y.iter())
    }
}

impl<T> TimeSeries<T> {
    pub fn push(&mut self, t: f64, y: T) {
        self.t.push(t);
        self.y.push(y);
    }
}

#[derive(Debug, Default)]
struct CpuTrace {
    t: Vec<f64>,
    total_cpu: Vec<f64>,
    bgp_cpu: Vec<f64>,
    urib_cpu: Vec<f64>,
    ipfib_cpu: Vec<f64>,
    text: Vec<String>,
}

impl CpuTrace {
    pub fn push(
        &mut self,
        t: f64,
        total_cpu: f64,
        bgp_cpu: f64,
        urib_cpu: f64,
        ipfib_cpu: f64,
        text: String,
    ) {
        self.t.push(t);
        self.total_cpu.push(total_cpu);
        self.bgp_cpu.push(bgp_cpu);
        self.urib_cpu.push(urib_cpu);
        self.ipfib_cpu.push(ipfib_cpu);
        self.text.push(text);
    }
}

type BGPUpdateData = BTreeMap<(Option<Router>, Option<Router>), Vec<TimeSeries<usize>>>;
type ReachabilityData = HashMap<Ipv4Addr, HashMap<Router, TimeSeries<f64>>>;
type FWUpdateData = HashMap<Ipv4Addr, HashMap<Router, (TimeSeries<usize>, TimeSeries<usize>)>>;
type TextUpdateData<T = usize> = HashMap<Ipv4Addr, HashMap<Router, TimeSeries<(T, String)>>>;
type CpuUtilData = HashMap<Router, CpuTrace>;

struct FwRecordsLine {
    data: Vec<TimeSeries<usize>>,
    log_source: &'static str,
    log_source_prefix: &'static str,
    model: String,
    dash_type: DashType,
    mix_color: &'static str,
}
type FwRecordsData = BTreeMap<Option<Router>, Vec<FwRecordsLine>>;

/// Visualize the BGP messages given in a CSV file, where each row corresponds to a serialized
/// `Record`. Panics if there are more prefixes than specified as an argument. Otherwise, produces
/// a plot in the same directory as the given .csv file path, adding the suffix .html.
#[allow(clippy::too_many_arguments)]
pub fn visualize_bgp_updates(
    scenario_name: impl AsRef<str>,
    eval_root: impl AsRef<Path>,
    timestamp: impl AsRef<str>,
    num_prefixes: usize,
    show: bool,
    t0: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = eval_root.as_ref();
    let ts = timestamp.as_ref();

    // make sure the file exists
    if !root.then_pcap("bgp_updates_{}.csv", ts).exists() {
        log::debug!("Skipping sample, as bgp_updates could not be parsed properly.");
        return Ok(());
    }

    log::info!(
        "Generating plot for {} at {ts}",
        root.as_os_str().to_string_lossy()
    );

    let n = num_prefixes + 10;
    let scenario_name = scenario_name.as_ref().replace('_', ", ");

    let (mut tend, prefix_order, bgp_plots) =
        prepare_bgp_updates(root.then_pcap("bgp_updates_{}.csv", ts), t0, n)?;
    tend += 1.0;
    let reach_plots = prepare_reachability(
        root.then_pcap("dp_updates_{}.csv", ts),
        t0,
        tend,
        &prefix_order,
    )?;
    let fw_update_plots = prepare_fw_updates(
        root.then_pcap("fw_updates_new_{}.csv", ts),
        t0,
        tend,
        &prefix_order,
    )?;
    let path_update_plots = prepare_path_updates(
        root.then_pcap("path_updates_new_{}.csv", ts),
        t0,
        tend,
        &prefix_order,
    )?;
    let (cpu_util_plots, cpu_zero_offset) = prepare_cpu_util(
        root.then_ts("cpu_monitor_{}.csv", ts),
        t0,
        tend,
        &prefix_order,
    )?;
    let fw_records_group = prepare_fw_records_group(
        root.then_ts("time_series_of_forwarding_states_{}", ts),
        t0,
        tend,
        &prefix_order,
    )?;

    // store the prefix order to json
    fs::write(
        root.then_ts("prefix_order_{}.json", ts),
        serde_json::to_string_pretty(&prefix_order)?,
    )?;

    // generate the plot
    let mut plot = Plot::new();

    plot.set_layout(
        plot.layout()
            .clone()
            .title(format!(
                "<b>BGP and Forwarding Updates ({scenario_name})</b>"
            ))
            .y_axis(Axis::new().show_grid(false))
            .hover_mode(HoverMode::X)
            .height(1000),
    );

    // add all bgp updates
    for ((src, dst), line_list) in bgp_plots {
        for (i, line) in line_list.into_iter().enumerate() {
            store_line(
                root,
                ts,
                format!("bgp_updates_{}_to_{}_{i}", src.unwrap(), dst.unwrap()),
                &line,
            )?;
            let trace = Scatter::new(line.t, line.y)
                .name(format!(
                    "{} -> {}, msg {}",
                    src.unwrap(),
                    dst.unwrap(),
                    i + 1
                ))
                .line(Line::new().color(color(dst)))
                .hover_info(HoverInfo::None)
                .visible(
                    if format!("{dst:?}").contains("LosAngeles")
                        || format!("{dst:?}").contains("KansasCity")
                    {
                        Visible::True
                    } else {
                        Visible::LegendOnly
                    },
                );
            plot.add_trace(trace);
        }
    }

    // add all fw updates as groups
    for (router, lines) in fw_records_group {
        let color = color(router);
        for line in lines {
            let group = format!("{:?}: {}", router.unwrap(), line.log_source);
            for (i, section) in line.data.into_iter().enumerate() {
                store_line(
                    root,
                    ts,
                    format!(
                        "{}_{}_{}_{i}",
                        line.log_source_prefix,
                        line.model,
                        router.unwrap()
                    ),
                    &section,
                )?;
                let cpu_trace = Scatter::new(section.t, section.y)
                    .name(format!("{}: {} ({})", line.log_source, line.model, i + 1))
                    .mode(Mode::Lines)
                    .line(
                        Line::new()
                            .color(color_mix(color, line.mix_color))
                            .width(2.0)
                            .dash(line.dash_type.clone()),
                    )
                    .connect_gaps(false)
                    .legend_group(group.clone())
                    .legend_group_title(group.clone())
                    .visible(Visible::LegendOnly);
                plot.add_trace(cpu_trace);
            }
        }
    }

    // add the lines for all prefixes as light gray
    for p in reach_plots.keys() {
        let ord = prefix_order[p];
        let trace = Scatter::new(vec![0.0, tend], vec![ord, ord])
            .name(p.to_string())
            .mode(Mode::Lines)
            .hover_info(HoverInfo::Name)
            .hover_on(HoverOn::PointsAndFills)
            .legend_group("prefixes")
            .legend_group_title("Prefixes")
            .line(Line::new().color("#a3a3a3").width(0.5));
        plot.add_trace(trace)
    }

    // add all violation lines
    for (src, p, line) in reach_plots
        .into_iter()
        .flat_map(|(p, reach_plots)| {
            reach_plots
                .into_iter()
                .map(move |(src, line)| (src, p, line))
        })
        .sorted_by_key(|(src, p, _)| (*src, *p))
    {
        // skip empyt lines
        if line.t.len() < 2 {
            continue;
        }
        let trace = Scatter::new(line.t, line.y)
            .name(format!("violation for {p} at {src:?}"))
            .mode(Mode::Lines)
            .line(Line::new().color(color(Some(src))).width(4.0))
            .opacity(0.4)
            .legend_group(format!("violation-{src:?}"))
            .visible(Visible::LegendOnly);
        plot.add_trace(trace);
    }

    // add all fw update markers
    // type FWUpdateData = HashMap<Ipv4Addr, HashMap<Router, (TimeSeries<usize>, TimeSeries<usize>)>>;
    for (src, update, drop) in fw_update_plots
        .into_values()
        .flatten()
        .into_group_map_by(|(router, _)| *router)
        .into_iter()
        .map(|(src, lines)| {
            let (reach, unreach): (Vec<_>, Vec<_>) = lines.into_iter().map(|(_, x)| x).multiunzip();
            (
                src,
                reach
                    .into_iter()
                    .flatten()
                    .sorted_by(|(t1, _), (t2, _)| t1.total_cmp(t2))
                    .collect::<TimeSeries<_>>(),
                unreach
                    .into_iter()
                    .flatten()
                    .sorted_by(|(t1, _), (t2, _)| t1.total_cmp(t2))
                    .collect::<TimeSeries<_>>(),
            )
        })
    {
        if !update.t.is_empty() {
            store_line(root, ts, format!("fw_updates_update_{src}"), &update)?;
            let trace = Scatter::new(update.t, update.y)
                .name(format!("FW updates at {src:?}"))
                .mode(Mode::Markers)
                .marker(
                    Marker::new()
                        .color(color(Some(src)))
                        .symbol(MarkerSymbol::Circle)
                        .size(10),
                )
                .opacity(0.4)
                .legend_group(format!("forwarding-{src:?}"))
                .visible(if src == Router::LosAngeles {
                    Visible::True
                } else {
                    Visible::LegendOnly
                });
            plot.add_trace(trace)
        }
        if !drop.t.is_empty() {
            store_line(root, ts, format!("fw_updates_drop_{src}"), &drop)?;
            let trace = Scatter::new(drop.t, drop.y)
                .name(format!("FW blackhole at {src:?}"))
                .mode(Mode::Markers)
                .marker(
                    Marker::new()
                        .color(color(Some(src)))
                        .symbol(MarkerSymbol::X)
                        .size(10),
                )
                .opacity(0.4)
                .legend_group(format!("forwarding-{src:?}"))
                .visible(if src == Router::LosAngeles {
                    Visible::True
                } else {
                    Visible::LegendOnly
                });
            plot.add_trace(trace)
        }
    }

    // add all path update markers
    for (src, p, update) in path_update_plots
        .into_iter()
        .flat_map(|(p, reach_plots)| {
            reach_plots
                .into_iter()
                .map(move |(src, line)| (src, p, line))
        })
        .sorted_by_key(|(src, p, _)| (*src, *p))
    {
        if !update.t.is_empty() {
            let (ys, texts) = update.y.into_iter().unzip();
            let trace = Scatter::new(update.t, ys)
                .name(format!("Path updates for {p} at {src:?}"))
                .text_array(texts)
                .hover_info(HoverInfo::Text)
                .mode(Mode::Markers)
                .marker(
                    Marker::new()
                        .color(color(Some(src)))
                        .symbol(MarkerSymbol::TriangleUp)
                        .size(5),
                )
                .legend_group(format!("path-{src:?}"))
                .visible(Visible::LegendOnly);
            plot.add_trace(trace)
        }
    }

    // add all CPU utilization lines
    for (router, data) in cpu_util_plots {
        if data.t.is_empty() {
            continue;
        }
        #[rustfmt::skip]
        let cpu_zero_trace = Scatter::new(
            vec![data.t[0], tend],
            vec![cpu_zero_offset, cpu_zero_offset],
        )
            .name(format!("CPU zero at {router:?}"))
            .mode(Mode::Lines)
            .hover_info(HoverInfo::Name)
            .hover_on(HoverOn::PointsAndFills)
            .legend_group(format!("CPU {router:?}"))
            .legend_group_title(format!("CPU {router:?}"))
            .line(Line::new().color("#a3a3a3").width(0.5))
            .visible(if router == Router::LosAngeles {
                Visible::True
            } else {
                Visible::LegendOnly
            });
        plot.add_trace(cpu_zero_trace);
        let bgp_trace = Scatter::new(data.t.clone(), data.bgp_cpu)
            .name(format!("BGP cpu utilization at {router:?}"))
            .text_array(data.text.clone())
            .hover_info(HoverInfo::Text)
            .mode(Mode::Lines)
            .line(
                Line::new()
                    .color(color(Some(router)))
                    .width(1.0)
                    .dash(DashType::Dash),
            )
            .fill(Fill::ToNextY)
            .fill_color(color(Some(router)))
            .legend_group(format!("CPU {router:?}"))
            .legend_group_title(format!("CPU {router:?}"))
            .visible(if router == Router::LosAngeles {
                Visible::True
            } else {
                Visible::LegendOnly
            });
        plot.add_trace(bgp_trace);
        let urib_trace = Scatter::new(data.t.clone(), data.urib_cpu)
            .name(format!("urib cpu utilization at {router:?}"))
            .text_array(data.text.clone())
            .hover_info(HoverInfo::Text)
            .mode(Mode::Lines)
            .line(
                Line::new()
                    .color(color(Some(router)))
                    .width(1.0)
                    .dash(DashType::Dash),
            )
            .fill(Fill::ToNextY)
            .fill_color(color_opacity(Some(router), 0.5))
            .legend_group(format!("CPU {router:?}"))
            .legend_group_title(format!("CPU {router:?}"))
            .visible(if router == Router::LosAngeles {
                Visible::True
            } else {
                Visible::LegendOnly
            });
        plot.add_trace(urib_trace);
        let ipfib_trace = Scatter::new(data.t.clone(), data.ipfib_cpu)
            .name(format!("ipfib cpu utilization at {router:?}"))
            .text_array(data.text.clone())
            .hover_info(HoverInfo::Text)
            .mode(Mode::Lines)
            .line(
                Line::new()
                    .color(color(Some(router)))
                    .width(1.0)
                    .dash(DashType::Dash),
            )
            .fill(Fill::ToNextY)
            .fill_color(color_opacity(Some(router), 0.25))
            .legend_group(format!("CPU {router:?}"))
            .legend_group_title(format!("CPU {router:?}"))
            .visible(if router == Router::LosAngeles {
                Visible::True
            } else {
                Visible::LegendOnly
            });
        plot.add_trace(ipfib_trace);
        let cpu_trace = Scatter::new(data.t.clone(), data.total_cpu)
            .name(format!("Total CPU utilization at {router:?}"))
            .text_array(data.text.clone())
            .hover_info(HoverInfo::Text)
            .mode(Mode::Lines)
            .line(Line::new().color(color(Some(router))).width(2.0))
            .fill(Fill::ToNextY)
            .fill_color(color_opacity(Some(router), 0.1))
            .legend_group(format!("CPU {router:?}"))
            .legend_group_title(format!("CPU {router:?}"))
            .visible(if router == Router::LosAngeles {
                Visible::True
            } else {
                Visible::LegendOnly
            });
        plot.add_trace(cpu_trace);
    }

    let plot_path = root.then_ts("plot_{}.html", ts);
    plot.write_html(&plot_path);

    log::info!(
        "Written plot to: {}",
        plot_path.as_os_str().to_string_lossy()
    );

    if show {
        plot.show();
    }

    Ok(())
}

pub fn color(r: Option<Router>) -> &'static str {
    match r {
        Some(Router::Atlanta) => "#2563eb",
        Some(Router::AtlantaExt) => "#1e3a8a",
        Some(Router::Chicago) => "#7c3aed",
        Some(Router::ChicagoExt) => "#4c1d95",
        Some(Router::Denver) => "#c026d3",
        Some(Router::DenverExt) => "#701a75",
        Some(Router::Indianapolis) => "#e11d48",
        Some(Router::IndianapolisExt) => "#881337",
        Some(Router::KansasCity) => "#16a34a",
        Some(Router::KansasCityExt) => "#14532d",
        Some(Router::LosAngeles) => "#dc2626",
        Some(Router::LosAngelesExt) => "#7f1d1d",
        Some(Router::NewYork) => "#d97706",
        Some(Router::NewYorkExt) => "#78350f",
        Some(Router::Seattle) => "#78716c",
        Some(Router::SeattleExt) => "#292524",
        Some(Router::Houston) => "#65a30d",
        Some(Router::HoustonExt) => "#365314",
        Some(Router::Sunnyvale) => "#059669",
        Some(Router::SunnyvaleExt) => "#064e3b",
        Some(Router::WashingtonDC) => "#0891b2",
        Some(Router::WashingtonDCExt) => "#164e63",
        None => "#000000",
    }
}

pub fn split_rgb(color: &str) -> (u8, u8, u8) {
    let hex = color.trim_start_matches('#');
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap();
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap();
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap();
    (r, g, b)
}

pub fn color_opacity(r: Option<Router>, opacity: f64) -> String {
    let (r, g, b) = split_rgb(color(r));
    format!("rgba({}, {}, {}, {})", r, g, b, opacity)
}

pub fn color_mix(c1: &str, c2: &str) -> String {
    let (r1, g1, b1) = split_rgb(c1);
    let (r2, g2, b2) = split_rgb(c2);

    let r = (r1 / 2) + (r2 / 2);
    let g = (g1 / 2) + (g2 / 2);
    let b = (b1 / 2) + (b2 / 2);

    format!("#{:02X}{:02X}{:02X}", r, g, b)
}

#[allow(clippy::type_complexity)]
fn prepare_bgp_updates(
    bgp_updates_csv_path: impl AsRef<Path>,
    t0: f64,
    n: usize,
) -> Result<(f64, HashMap<Ipv4Addr, usize>, BGPUpdateData), Box<dyn std::error::Error>> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(b';')
        .from_path(bgp_updates_csv_path)?;

    let mut tend = 0.0;
    let mut prefix_order = HashMap::<Ipv4Addr, usize>::with_capacity(n);
    #[allow(clippy::type_complexity)]
    let mut raw_data: BTreeMap<(Option<Router>, Option<Router>), Vec<Vec<f64>>> =
        Default::default();

    for result in rdr.deserialize() {
        let mut record: Record = result?;

        if record.reach.is_empty() && record.unreach.is_empty() {
            continue;
        }

        // handle the time
        record.time -= t0;
        if record.time > tend {
            tend = record.time;
        }

        // create the index for all prefixes
        for addr in record.reach.iter().chain(record.unreach.iter()) {
            let idx = prefix_order.len();
            if idx >= n {
                return Err(String::from("Too many prefixes in the trace!").into());
            }
            prefix_order.entry(*addr).or_insert(idx);
        }

        let session_data = raw_data
            .entry((record.src_name, record.dst_name))
            .or_default();

        // go through each updated prefix
        for addr in record.reach.iter().chain(record.unreach.iter()) {
            let idx = prefix_order[addr];
            // insert it into the array, by how many time it was already seen
            for seen in 0usize.. {
                if session_data.len() == seen {
                    session_data.push(vec![f64::NAN; n]);
                }
                let arr = session_data.get_mut(seen).unwrap();
                if arr[idx].is_nan() {
                    arr[idx] = record.time;
                    break;
                }
            }
        }
    }

    let data = raw_data
        .into_iter()
        .map(|(k, raw)| {
            (
                k,
                raw.into_iter()
                    .map(|arr| {
                        let mut data = arr.into_iter().zip(0..n).collect::<Vec<_>>();
                        data.sort_by(|(t1, _), (t2, _)| t1.total_cmp(t2));
                        let (t, y) = data.into_iter().unzip();
                        TimeSeries { t, y }
                    })
                    .collect(),
            )
        })
        .collect();

    Ok((tend, prefix_order, data))
}

fn prepare_reachability(
    dp_reachability_csv_path: impl AsRef<Path>,
    t0: f64,
    tend: f64,
    prefix_order: &HashMap<Ipv4Addr, usize>,
) -> Result<ReachabilityData, Box<dyn std::error::Error>> {
    let path = dp_reachability_csv_path.as_ref();
    if !path.exists() {
        return Ok(ReachabilityData::new());
    };
    let mut rdr = csv::ReaderBuilder::new().from_path(path)?;

    let mut raw_data: HashMap<Ipv4Addr, HashMap<Router, Vec<(f64, bool)>>> = HashMap::new();
    for result in rdr.deserialize() {
        let mut record: DPRecord = result?;
        let Some(src) = record.src_name else {
            continue;
        };
        record.prefix = ipnet::Ipv4Net::new(record.prefix, 24).unwrap().network();
        record.time = (record.time - t0).max(0.0).min(tend);
        raw_data
            .entry(record.prefix)
            .or_default()
            .entry(src)
            .or_default()
            .push((record.time, record.reachable))
    }

    fn transform(ord: usize, tend: f64, mut raw: Vec<(f64, bool)>) -> TimeSeries<f64> {
        let mut ts = TimeSeries::<f64> {
            t: Vec::new(),
            y: Vec::new(),
        };
        let nan = f64::NAN;
        let y = ord as f64;
        let val = |x: bool| if x { nan } else { y };
        if let Some((_, reach)) = raw.first().cloned() {
            raw.insert(0, (0.0, reach));
            ts.push(0.0, val(reach))
        }
        if let Some((_, reach)) = raw.last().cloned() {
            raw.push((tend, reach));
        }
        for (&(told, before), &(t, after)) in raw.iter().tuple_windows() {
            match (before, after) {
                // still unreachable. Just draw the point
                (false, false) => ts.push(t, y),
                // just became unreachable. Draw the point in between this and the last with nan,
                // and then the actual value
                (true, false) => {
                    ts.push((told + t) / 2.0, nan);
                    ts.push(t, y);
                }
                // Just became reachable again. Draw the last point
                (false, true) => ts.push(t, y),
                // remains reachable. Nothing to do
                (true, true) => {}
            }
        }

        ts
    }

    // process the raw data into a format that we can print
    Ok(raw_data
        .into_iter()
        .map(|(p, x)| {
            let ord = prefix_order[&p];
            (
                p,
                x.into_iter()
                    .map(|(s, raw)| (s, transform(ord, tend, raw)))
                    .collect(),
            )
        })
        .collect())
}

fn prepare_fw_updates(
    fw_csv_path: impl AsRef<Path>,
    t0: f64,
    _tend: f64,
    prefix_order: &HashMap<Ipv4Addr, usize>,
) -> Result<FWUpdateData, Box<dyn std::error::Error>> {
    let path = fw_csv_path.as_ref();
    if !path.exists() {
        return Ok(FWUpdateData::new());
    };
    let mut rdr = csv::ReaderBuilder::new().from_path(path)?;

    let mut data = FWUpdateData::new();
    for result in rdr.deserialize() {
        let mut record: FWRecord = result?;
        let Some(src) = record.src_name else {
            continue;
        };
        record.prefix = ipnet::Ipv4Net::new(record.prefix, 24).unwrap().network();
        record.time -= t0;
        // only take fw updates starting after t0
        if record.time < 0.0 {
            continue;
        }
        let ord = prefix_order[&record.prefix];
        let (change, drop) = data
            .entry(record.prefix)
            .or_default()
            .entry(src)
            .or_default();
        if record.next_hop.is_none() {
            drop.push(record.time, ord);
        } else {
            change.push(record.time, ord);
        }
    }

    Ok(data)
}

fn prepare_path_updates(
    path_csv_path: impl AsRef<Path>,
    t0: f64,
    _tend: f64,
    prefix_order: &HashMap<Ipv4Addr, usize>,
) -> Result<TextUpdateData, Box<dyn std::error::Error>> {
    let path = path_csv_path.as_ref();
    if !path.exists() {
        return Ok(TextUpdateData::new());
    };
    let mut rdr = csv::ReaderBuilder::new().delimiter(b';').from_path(path)?;

    let mut data = TextUpdateData::new();
    for result in rdr.deserialize() {
        let mut record: PathRecord = result?;
        let Some(src) = record.src_name else {
            continue;
        };
        record.prefix = ipnet::Ipv4Net::new(record.prefix, 24).unwrap().network();
        record.time -= t0;
        // only take path updates starting after t0
        if record.time < 0.0 {
            continue;
        }
        let ord = prefix_order[&record.prefix];
        data.entry(record.prefix)
            .or_default()
            .entry(src)
            .or_default()
            .push(
                record.time,
                (ord, {
                    let mut res = record.prefix.to_string();
                    res.push_str(": ");
                    res.push_str(
                        &record
                            .path_names
                            .into_iter()
                            .map(|x| x.map(|y| y.to_string()).unwrap_or("?".to_string()))
                            .join("->"),
                    );
                    res
                }),
            );
    }

    Ok(data)
}

fn prepare_cpu_util(
    cpu_util_csv_path: impl AsRef<Path>,
    t0: f64,
    tend: f64,
    prefix_order: &HashMap<Ipv4Addr, usize>,
) -> Result<(CpuUtilData, f64), Box<dyn std::error::Error>> {
    let path = cpu_util_csv_path.as_ref();
    if !path.exists() {
        return Ok((CpuUtilData::new(), 0.0));
    };
    let mut rdr = csv::ReaderBuilder::new().from_path(path)?;

    let num_prefixes = prefix_order.len() as f64;
    let norm = num_prefixes / 2_000.0;
    let offset = -800.0 * norm;

    let mut data = CpuUtilData::new();
    for result in rdr.deserialize() {
        let record: CpuRecord = result?;
        let Some(router) = record.router_name else {
            continue;
        };
        let t = record.timestamp - t0;
        // only take path updates starting after t0
        if t < 0.0 || t > tend {
            continue;
        }
        let total_cpu = record.cpu * norm + offset;
        let bgp_cpu = record.bgp_cpu * norm + offset;
        let urib_cpu = bgp_cpu + record.urib_cpu * norm;
        let ipfib_cpu = urib_cpu + record.ipfib_cpu * norm;
        let text = format!(
            "Router: {:?}\nTotal: {}%\nBGP: {}%\nipfib: {}%\nurib: {}%\nCPU1: {}%\nCPU2: {}%\nCPU3: {}%\nCPU4: {}%\nCPU5: {}%\nCPU6: {}%\nCPU7: {}%\nCPU8:{}%",
            router, record.cpu, record.bgp_cpu, record.ipfib_cpu, record.urib_cpu, record.cpu1, record.cpu2, record.cpu3, record.cpu4, record.cpu5, record.cpu6, record.cpu7, record.cpu8
        );
        data.entry(router)
            .or_default()
            .push(t, total_cpu, bgp_cpu, urib_cpu, ipfib_cpu, text);
    }

    Ok((data, offset))
}

fn prepare_fw_records_group(
    root: impl AsRef<Path>,
    t0: f64,
    tend: f64,
    prefix_order: &HashMap<Ipv4Addr, usize>,
) -> Result<FwRecordsData, Box<dyn std::error::Error>> {
    let root = root.as_ref();
    let files = std::fs::read_dir(root)?
        .filter_map(|f| f.ok())
        .filter(|e| e.metadata().map(|x| x.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect::<Vec<_>>();

    let mut result = FwRecordsData::new();
    for (prefix, log_source, dash_type, mix_color) in [
        //("bgpsim", "BGPsim model", DashType::Dot, "#d97706"),
        ("bgp_messages", "BGP Messages", DashType::Dot, "#e0e0e0"),
        ("bgp_log", "BGP log", DashType::Dot, "#e0e0e0"),
        ("urib", "URIB log", DashType::Dash, "#a0a0a0"),
        ("ufdm", "UFDM log", DashType::DashDot, "#606060"),
        ("ipfib", "IPFIB log", DashType::LongDashDot, "#202020"),
    ] {
        // find all models compiled for this log source
        for model in files
            .iter()
            .filter_map(|f| f.strip_prefix(prefix))
            .filter_map(|f| f.strip_suffix(".csv"))
        {
            let filename = format!("{prefix}{model}.csv");
            let model = if model.is_empty() {
                "none"
            } else {
                model.strip_prefix('_').unwrap_or(model)
            };
            let raw_data = prepare_fw_record(root.then(filename), t0, tend, prefix_order)?;
            for (router, data) in raw_data {
                result.entry(router).or_default().push(FwRecordsLine {
                    data,
                    log_source,
                    log_source_prefix: prefix,
                    model: model.to_string(),
                    dash_type: dash_type.clone(),
                    mix_color,
                })
            }
        }
    }
    Ok(result)
}

type FwRecordsRaw = BTreeMap<Option<Router>, Vec<TimeSeries<usize>>>;

fn prepare_fw_record(
    path: impl AsRef<Path>,
    t0: f64,
    tend: f64,
    prefix_order: &HashMap<Ipv4Addr, usize>,
) -> Result<FwRecordsRaw, Box<dyn std::error::Error>> {
    let path = path.as_ref();
    let mut rdr = csv::ReaderBuilder::new().from_path(path)?;

    let mut data = FwRecordsRaw::default();
    for result in rdr.deserialize() {
        let mut record: FWRecord = result?;
        let prefix = record.prefix;

        record.time -= t0;

        // only take ipfib updates starting after t0
        if record.time < 0.0 || record.time > tend {
            continue;
        }
        let Some(idx) = prefix_order.get(&prefix).copied() else {
            log::debug!("Could not find prefix {prefix:?} in prefix_order. Skip!");
            continue;
        };

        // get the updated data array
        let lines = data.entry(record.src_name).or_default();

        // check if the last line has an idx larger than the current entry. If so, start a new line
        if lines
            .last()
            .map(|line| *line.y.last().unwrap() <= idx)
            .unwrap_or(false)
        {
            // continue on the same line
            let line = lines.last_mut().unwrap();
            // fill up the array with NAN until we reach the idx
            let mut running_idx = *line.y.last().unwrap() + 1;
            while running_idx < idx {
                line.push(f64::NAN, running_idx);
                running_idx += 1;
            }
            line.push(record.time, idx);
        } else {
            // create a new line
            let mut new_ts = TimeSeries::default();
            new_ts.push(record.time, idx);
            lines.push(new_ts);
        }
    }

    Ok(data)
}

fn store_line<T: serde::Serialize + Clone>(
    root: &Path,
    ts: &str,
    line_name: impl AsRef<str>,
    line: &TimeSeries<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Serialize)]
    struct Record<T> {
        time: f64,
        value: T,
    }
    let folder = root.then_ts("plot_{}_data", ts);
    std::fs::create_dir_all(&folder)?;
    let mut writer = csv::Writer::from_path(folder.then(format!("{}.csv", line_name.as_ref())))?;
    for (time, value) in line.t.iter().copied().zip(line.y.iter().cloned()) {
        writer.serialize(Record { time, value })?;
    }
    Ok(())
}
