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
use trix::{
    analyzer::Analyzer, event::AnalyzerEvent, transient_specification::TransientPolicy, Prefix as P,
};
use bgpsim::{
    builder::{constant_link_weight, NetworkBuilder},
    event::{ModelParams, SimpleTimingModel},
    policies::FwPolicy,
    prelude::*,
    route_map::{RouteMapBuilder, RouteMapDirection},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    half_half(0.01)?;
    half_half(0.005)?;
    one_eights(0.01)?;
    one_eights(0.005)?;
    Ok(())
}

fn one_eights(precision: f64) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\nRunning with probability 12.5% for a single loop, precision = {}%",
        precision * 100.0
    );

    for k in 1..10 {
        let p_exp = (1.0f64 - 1.0f64 / 8.0f64).powi(k);
        println!("expected p_sat: {:>7.3}%", p_exp * 100.0,);

        let mut net = Network::default();
        let s = net.add_router("s");
        let t = net.add_router("t");
        let s_ext = net.add_external_router("s_ext", 100);
        let t_ext = net.add_external_router("t_ext", 200);
        let prefix = P::from(0);
        net.add_link(s, s_ext)?;
        net.add_link(t, t_ext)?;
        net.set_bgp_route_map(
            s,
            t,
            RouteMapDirection::Incoming,
            RouteMapBuilder::new().order(10).deny().build(),
        )?;

        let mut props = Vec::new();
        let mut us = Vec::new();
        let mut vs = Vec::new();

        for i in 0..k {
            let u = net.add_router(format!("u_{}", i));
            let v = net.add_router(format!("v_{}", i));
            net.add_link(s, u)?;
            net.add_link(u, v)?;
            net.add_link(v, t)?;
            props.push(TransientPolicy::Atomic(FwPolicy::LoopFree(u, prefix)));
            props.push(TransientPolicy::Atomic(FwPolicy::LoopFree(v, prefix)));
            us.push(u);
            vs.push(v);
        }

        net.build_link_weights(constant_link_weight, 1.0)?;
        net.build_ebgp_sessions()?;
        net.build_ibgp_full_mesh()?;
        net.advertise_external_route(s_ext, prefix, [100, 100, 100, 42], None, None)?;

        let mut net = net
            .swap_queue(SimpleTimingModel::new(ModelParams::new(
                10.0, 1.0, 1.0, 1.0, 0.1,
            )))
            .unwrap();

        let q = net.queue_mut();
        us.into_iter()
            .for_each(|u| q.set_parameters(t, u, ModelParams::new(1.5, 1.0, 1.0, 1.0, 0.1)));
        vs.into_iter()
            .for_each(|v| q.set_parameters(t, v, ModelParams::new(1.0, 1.0, 1.0, 1.0, 0.2)));

        let analyzer = Analyzer::new(
            net,
            AnalyzerEvent::AnnounceRoute(vec![prefix], t_ext, vec![AsId(200), AsId(42)]),
            props,
            0.95,
            precision,
        )?;
        let result = analyzer.analyze();
        println!("{}", result);

        let diff = (result.p_satisfied - (p_exp)).abs();
        if diff < precision * 0.5 {
            println!(
                "diff: {}{:.3}%{}\n",
                termion::color::Fg(termion::color::Green),
                diff * 100.0,
                termion::color::Fg(termion::color::Reset),
            );
        } else {
            println!(
                "diff: {}{:.3}%{}\n",
                termion::color::Fg(termion::color::Red),
                diff * 100.0,
                termion::color::Fg(termion::color::Reset),
            );
        }
    }

    Ok(())
}

fn half_half(precision: f64) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\nRunning with probability 50% for a single loop, precision = {}%",
        precision * 100.0
    );

    for k in 1..10 {
        let p_exp = 0.5f64.powi(k);
        println!("expected p_sat: {:>7.3}%", p_exp * 100.0,);

        let mut net = Network::default();
        let s = net.add_router("s");
        let t = net.add_router("t");
        let s_ext = net.add_external_router("s_ext", 100);
        let t_ext = net.add_external_router("t_ext", 200);
        let prefix = P::from(0);
        net.add_link(s, s_ext)?;
        net.add_link(t, t_ext)?;
        net.set_bgp_route_map(
            s,
            t,
            RouteMapDirection::Incoming,
            RouteMapBuilder::new().order(10).deny().build(),
        )?;

        let mut props = Vec::new();

        for i in 0..k {
            let u = net.add_router(format!("u_{}", i));
            let v = net.add_router(format!("v_{}", i));
            net.add_link(s, u)?;
            net.add_link(u, v)?;
            net.add_link(v, t)?;
            props.push(TransientPolicy::Atomic(FwPolicy::LoopFree(u, prefix)));
            props.push(TransientPolicy::Atomic(FwPolicy::LoopFree(v, prefix)));
        }

        net.build_link_weights(constant_link_weight, 1.0)?;
        net.build_ebgp_sessions()?;
        net.build_ibgp_full_mesh()?;
        net.advertise_external_route(s_ext, prefix, [100, 100, 100, 42], None, None)?;

        let net = net
            .swap_queue(SimpleTimingModel::new(ModelParams::new(
                1.0, 1.0, 1.0, 1.0, 0.1,
            )))
            .unwrap();

        let analyzer = Analyzer::new(
            net,
            AnalyzerEvent::AnnounceRoute(vec![prefix], t_ext, vec![AsId(200), AsId(42)]),
            props,
            0.95,
            precision,
        )?;
        let result = analyzer.analyze();
        println!("{}", result);

        let diff = (result.p_satisfied - (p_exp)).abs();
        if diff < precision * 0.5 {
            println!(
                "diff: {}{:.3}%{}\n",
                termion::color::Fg(termion::color::Green),
                diff * 100.0,
                termion::color::Fg(termion::color::Reset),
            );
        } else {
            println!(
                "diff: {}{:.3}%{}\n",
                termion::color::Fg(termion::color::Red),
                diff * 100.0,
                termion::color::Fg(termion::color::Reset),
            );
        }
    }

    Ok(())
}
