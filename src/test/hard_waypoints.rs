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
//! It is difficult to do.

use std::iter::{once, repeat};

use bgpsim::{
    builder::{constant_link_weight, NetworkBuilder},
    event::{ModelParams, SimpleTimingModel},
    policies::{FwPolicy, PathCondition},
    prelude::*,
    route_map::{RouteMapBuilder, RouteMapDirection},
};
use itertools::{iproduct, Itertools};

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
        (RouterId, RouterId),
        (RouterId, RouterId),
        Vec<RouterId>,
    ),
    NetworkError,
> {
    let mut net = Network::default();
    let t0 = net.add_router("t0");
    let t1 = net.add_router("t1");
    let t0_ext = net.add_external_router("t0_ext", 200);
    let t1_ext = net.add_external_router("t1_ext", 201);
    let w1 = net.add_router("w1");

    net.advertise_external_route(t0_ext, SinglePrefix, vec![200, 42], None, None)?;
    net.advertise_external_route(t1_ext, SinglePrefix, vec![201, 201, 42], None, None)?;

    net.add_link(t0, t0_ext);
    net.add_link(t1, t1_ext);
    net.add_link(w1, t0);
    net.add_link(w1, t1);

    let mut ws = vec![w1];
    let mut ts = vec![t1];

    for k in 2..=k {
        let wk = net.add_router(format!("w{}", k));
        let tk = net.add_router(format!("t{}", k));
        let tk_ext = net.add_external_router(format!("t{}_ext", k), 200 + k);
        net.add_link(wk, tk);
        net.add_link(tk, tk_ext);
        net.add_link(wk, *ws.last().unwrap());
        net.advertise_external_route(
            tk_ext,
            SinglePrefix,
            repeat(200 + k).take(3).chain(once(42)),
            None,
            None,
        )?;
        net.set_bgp_route_map(
            tk,
            t1,
            RouteMapDirection::Incoming,
            RouteMapBuilder::new().order(10).deny().build(),
        )?;
        ws.push(wk);
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
    for wk in ws.iter().copied() {
        q.set_parameters(t0, wk, ModelParams::new(10.0, 0.0, 1.0, 1.0, 0.1))
    }

    Ok((net, (t0, t0_ext), (t1, t1_ext), ws))
}

fn get_p_satisfy_k2() -> f64 {
    let mut num_viol = 0;
    let mut num_tot = 0;
    for v in (0..5).permutations(5) {
        let (s1, s2, s3, w1, w2) = (v[0], v[1], v[2], v[3], v[4]);
        num_tot += 1;
        if s3 < s1.min(s2) || (w2 < w1 && w1 > s1.min(s2)) {
            num_viol += 1;
        }
    }
    1.0 - ((num_viol as f64) / (num_tot as f64))
}

#[ignore]
// this test-case uses strict checking which is no longer supported with the current Analyzer.
// TODO: split up into features
#[test]
fn hard_waypoints() {
    let k = 2;

    let (net, (_, t0_ext), _, ws) = get_net(k).unwrap();

    let wk = *ws.last().unwrap();

    let props = ws[..ws.len() - 1]
        .iter()
        .map(|w| {
            TransientPolicy::Strict(FwPolicy::PathCondition(
                wk,
                SinglePrefix,
                PathCondition::Node(*w),
            ))
        })
        .collect();

    let analyzer = Analyzer::new(
        net,
        |net| net.retract_external_route(t0_ext, SinglePrefix),
        props,
        CONFIDENCE,
        PRECISION,
    )
    .unwrap();
    let result = analyzer.analyze();

    println!("{}", get_p_satisfy_k2());
    check_diff(
        get_p_satisfy_k2(),
        result.p_satisfied,
        PRECISION,
        result.n_samples,
    );
}
