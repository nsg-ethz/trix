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
//! Test for waypoints
//!
//! The network creates k different possible paths from s to some external router, but only the
//! original and the final one satisfy the waypoint constraints.

use std::iter::{once, repeat};

use bgpsim::{
    builder::{constant_link_weight, NetworkBuilder},
    event::{ModelParams, SimpleTimingModel},
    policies::{FwPolicy, PathCondition},
    prelude::*,
};
use itertools::iproduct;

use crate::{Analyzer, TransientPolicy};

use super::check_diff;

const PRECISION: f64 = 0.01;
const CONFIDENCE: f64 = 0.95;

#[allow(clippy::type_complexity)]
fn get_net(
    k: usize,
) -> Result<
    (
        Network<SinglePrefix, SimpleTimingModel<SinglePrefix>>,
        RouterId,
        RouterId,
        RouterId,
    ),
    NetworkError,
> {
    let mut net = Network::default();
    let s = net.add_router("s");
    let x = net.add_router("x");
    let t0 = net.add_router("t0");
    let t1 = net.add_router("t1");
    let t0_ext = net.add_external_router("t0_ext", 200);
    let t1_ext = net.add_external_router("t1_ext", 201);

    net.advertise_external_route(t0_ext, SinglePrefix, vec![200, 42], None, None)?;
    net.advertise_external_route(t1_ext, SinglePrefix, vec![201, 201, 42], None, None)?;

    net.add_link(s, x);
    net.add_link(x, t0);
    net.add_link(x, t1);
    net.add_link(t0_ext, t0);
    net.add_link(t1_ext, t1);

    let mut ts = vec![t1];

    for k in 2..=k {
        let tk = net.add_router(format!("t{}", k));
        let tk_ext = net.add_external_router(format!("t{}_ext", k), 200 + k);
        net.add_link(tk, tk_ext);
        net.add_link(tk, s);
        net.advertise_external_route(
            tk_ext,
            SinglePrefix,
            repeat(200 + k).take(3).chain(once(42)),
            None,
            None,
        )?;
        ts.push(tk);
    }

    net.build_link_weights(constant_link_weight, 1.0)?;
    net.build_ebgp_sessions()?;
    net.build_ibgp_full_mesh()?;

    let mut net = net
        .swap_queue(SimpleTimingModel::new(ModelParams::new(
            10.0, 1.0, 1.0, 1.0, 0.1,
        )))
        .unwrap();
    let q = net.queue_mut();
    for (ta, tb) in iproduct!(&ts, &ts) {
        if ta != tb {
            q.set_parameters(*ta, *tb, ModelParams::new(100.0, 1.0, 1.0, 1.0, 0.1))
        }
    }
    for tk in ts {
        q.set_parameters(t0, tk, ModelParams::new(10.0, 0.0, 1.0, 1.0, 0.1))
    }

    Ok((net, s, x, t0_ext))
}

#[test]
fn node_waypoints() {
    eprintln!();
    for k in 1..=8 {
        node_waypoints_iter(k);
    }
}

fn node_waypoints_iter(k: usize) {
    eprint!("NodeWpts p=50.0%, k={:>02}, ", k);

    let (net, s, x, t0_ext) = get_net(k).unwrap();

    let props = vec![TransientPolicy::Atomic(FwPolicy::PathCondition(
        s,
        SinglePrefix,
        PathCondition::Node(x),
    ))];

    let analyzer = Analyzer::new(
        net,
        |net: _| net.retract_external_route(t0_ext, SinglePrefix),
        props,
        CONFIDENCE,
        PRECISION,
    )
    .unwrap();
    let result = analyzer.analyze();

    check_diff(
        1.0f64 / (k as f64),
        result.p_satisfied,
        PRECISION,
        result.n_samples,
    );
}

#[test]
fn edge_waypoints() {
    eprintln!();
    for k in 1..=8 {
        edge_waypoints_iter(k);
    }
}

fn edge_waypoints_iter(k: usize) {
    eprint!("EdgeWpts p=50.0%, k={:>02}, ", k);

    let (net, s, x, t0_ext) = get_net(k).unwrap();

    let props = vec![TransientPolicy::Atomic(FwPolicy::PathCondition(
        s,
        SinglePrefix,
        PathCondition::Edge(s, x),
    ))];

    let analyzer = Analyzer::new(
        net,
        |net: _| net.retract_external_route(t0_ext, SinglePrefix),
        props,
        CONFIDENCE,
        PRECISION,
    )
    .unwrap();
    let result = analyzer.analyze();

    check_diff(
        1.0f64 / (k as f64),
        result.p_satisfied,
        PRECISION,
        result.n_samples,
    );
}
