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
//! Test for loop freedom
//!
//! The network creates k potential loops in *parallel*, and the property checks if any of those
//! exist at some point in time.

use bgpsim::{
    builder::{constant_link_weight, NetworkBuilder},
    event::{ModelParams, SimpleTimingModel},
    policies::FwPolicy,
    prelude::*,
    route_map::{RouteMapBuilder, RouteMapDirection},
};

use crate::{Analyzer, TransientPolicy};

use super::check_diff;

const PRECISION: f64 = 0.02;
const CONFIDENCE: f64 = 0.95;

#[allow(clippy::type_complexity)]
fn get_net(
    k: usize,
) -> Result<
    (
        Network<SinglePrefix, BasicEventQueue<SinglePrefix>>,
        Vec<TransientPolicy>,
        RouterId,
        RouterId,
        Vec<RouterId>,
    ),
    NetworkError,
> {
    let mut net = Network::default();
    let s = net.add_router("s");
    let t = net.add_router("t");
    let s_ext = net.add_external_router("s_ext", 100);
    let t_ext = net.add_external_router("t_ext", 200);
    net.add_link(s, s_ext);
    net.add_link(t, t_ext);
    net.set_bgp_route_map(
        s,
        t,
        RouteMapDirection::Incoming,
        RouteMapBuilder::new().order(10).deny().build(),
    )?;

    let mut props = Vec::new();
    let mut us = Vec::new();

    for i in 0..k {
        let u = net.add_router(format!("u_{}", i));
        let v = net.add_router(format!("v_{}", i));
        net.add_link(s, u);
        net.add_link(u, v);
        net.add_link(v, t);
        props.push(TransientPolicy::Atomic(FwPolicy::LoopFree(u, SinglePrefix)));
        props.push(TransientPolicy::Atomic(FwPolicy::LoopFree(v, SinglePrefix)));
        us.push(u);
    }

    net.build_link_weights(constant_link_weight, 1.0)?;
    net.build_ebgp_sessions()?;
    net.build_ibgp_full_mesh()?;
    net.advertise_external_route(s_ext, SinglePrefix, &[100, 100, 100, 42], None, None)?;

    Ok((net, props, t_ext, t, us))
}

#[test]
fn p_one_half() {
    eprintln!();
    for k in 1..=8 {
        p_one_half_iter(k);
    }
}

fn p_one_half_iter(k: usize) {
    eprint!("LoopFree p=50.0%, k={:>02}, ", k);

    let (net, props, t_ext, _, _) = get_net(k).unwrap();
    let net = net
        .swap_queue(SimpleTimingModel::new(ModelParams::new(
            1.0, 1.0, 1.0, 1.0, 0.1,
        )))
        .unwrap();

    let analyzer = Analyzer::new(
        net,
        |net: _| net.advertise_external_route(t_ext, SinglePrefix, &[200, 42], None, None),
        props,
        CONFIDENCE,
        PRECISION,
    )
    .unwrap();
    let result = analyzer.analyze();

    check_diff(
        0.5f64.powi(k as i32),
        result.p_satisfied,
        PRECISION,
        result.n_samples,
    );
}

#[test]
fn p_one_eigths() {
    eprintln!();
    for k in 1..=8 {
        p_one_eigths_iter(k);
    }
}

fn p_one_eigths_iter(k: usize) {
    eprint!("LoopFree p=87.5%, k={:>02}, ", k);

    let (net, props, t_ext, t, us) = get_net(k).unwrap();
    let mut net = net
        .swap_queue(SimpleTimingModel::new(ModelParams::new(
            1.0, 1.0, 1.0, 1.0, 0.1,
        )))
        .unwrap();

    let q = net.queue_mut();
    us.into_iter()
        .for_each(|u| q.set_parameters(t, u, ModelParams::new(1.5, 1.0, 1.0, 1.0, 0.1)));

    let analyzer = Analyzer::new(
        net,
        |net| net.advertise_external_route(t_ext, SinglePrefix, &[200, 42], None, None),
        props,
        CONFIDENCE,
        PRECISION,
    )
    .unwrap();

    let result = analyzer.analyze();

    check_diff(
        0.875f64.powi(k as i32),
        result.p_satisfied,
        PRECISION,
        result.n_samples,
    );
}
