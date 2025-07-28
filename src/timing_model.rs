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
// temporarily allow unused code to prevent unnecessary warnings
#![allow(unused)]

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    iter::zip,
};

use geoutils::Location;
use itertools::Itertools;
use ordered_float::NotNan;
use priority_queue::PriorityQueue;
use rand::distributions::Distribution;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use statrs::distribution::Empirical;

use bgpsim::{
    bgp::BgpEvent,
    event::{Event, EventQueue},
    prelude::OspfProcess,
    types::{NetworkDevice, PhysicalNetwork, Prefix, RouterId},
};

/// Timing model based on statistical information gathered in measurements from real hardware.
/// This timing model uses seconds as time unit.
///
/// If using geographic information for the propagation delays, note the following:
/// The delay of a message from `a` to `b` is computed as follows: First, we compute the message's
/// path through the network (based on the current IGP table). For each traversed link, we add the
/// delay based on the speed of light and the length of the link (deterministic), i.e. ignoring
/// queuing delays. In addition, we sample from the empirical distribution of BGP processing params
/// for the specific router model.
///
/// If a distance between two nodes is not specified, the propagation delay will be chosen to be
/// 100us. If there is no actual path in IGP, then the delay will be chosen to be 100s (such that
/// convergence will still happen eventually).
///
/// # Performance
/// The `TimingModel` requires every path through the network within OSPF to be recomputed upon
/// *every* event. For instance, if you use the [`crate::builder::NetworkBuilder`] to build a large
/// network, the paths will be recomputed for each individual modification. If you establish an iBGP
/// full-mesh (which requires `O(n^2)` commands), then it will recompute all paths `O(n^2)` times,
/// which results in `O(n^4)` operations. To counteract this issue, create the network with the
/// [`crate::event::BasicEventQueue`], and build the initial configuration. Then, swap out the
/// queue using [`crate::network::Network::swap_queue`] before simulating the specific event.

pub enum TimingModelVariants {
    /// Basic model sampling a reaction time from basic hardware measurements for each individual
    /// event (on a per-prefix basis).
    Basic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: for<'a> serde::Deserialize<'a>"))]
pub struct TimingModel<P: Prefix> {
    // delivery queue contains the event and the current next_hop of the packet
    #[allow(clippy::type_complexity)]
    delivery_queue: PriorityQueue<(Event<P, NotNan<f64>>, RouterId), Reverse<NotNan<f64>>>,
    processing_queue: PriorityQueue<Event<P, NotNan<f64>>, Reverse<NotNan<f64>>>,
    #[serde(with = "crate::serde_generic_hashmap")]
    messages: HashMap<(RouterId, RouterId), (usize, NotNan<f64>)>,
    // Do not serialize the timing model, load that fresh from disk upon deserialization.
    #[serde(skip, default = "_init_processing_dist")]
    processing_dist: Empirical,
    #[serde(with = "crate::serde_generic_hashmap")]
    next_hops: HashMap<(RouterId, RouterId), RouterId>,
    fixed_next_hops: bool,
    #[serde(default, with = "crate::serde_generic_hashmap::in_option")]
    distances: Option<HashMap<(RouterId, RouterId), NotNan<f64>>>,
    #[serde(default, with = "crate::serde_generic_hashmap::in_option")]
    delays: Option<HashMap<(RouterId, RouterId), NotNan<f64>>>,
    current_time: NotNan<f64>,
}

const BASIC_TIMING_MODEL_DEFAULT_DELAY: f64 = 0.0001;
const BASIC_TIMING_MODEL_MAX_DELAY: f64 = 10.0;
/// Speed of light in a fiber cable is ~2/3 of the speed of light
/// https://en.wikipedia.org/wiki/Fiber-optic_cable#Propagation_speed_and_delay
const SPEED_OF_LIGHT: f64 = 0.66 * 299_792_458.0;

fn _init_processing_dist() -> Empirical {
    let processing_params: Vec<f64> = include_str!("../timing-model/data.csv")
        .lines()
        .map(|line| line.split(',').next().unwrap().parse::<f64>().unwrap() / 1000.0)
        .collect();
    Empirical::from_vec(processing_params)
}

impl<P: Prefix> TimingModel<P> {
    /// Create a new, empty model queue with given default parameters and geographic locations
    pub fn from_geo_location(geo_location: &HashMap<RouterId, Location>) -> Self {
        // compute the distance between all pairs of routers.
        let distances = Some(
            geo_location
                .iter()
                .flat_map(|l1| geo_location.iter().map(move |l2| (l1, l2)))
                .map(|((r1, p1), (r2, p2))| {
                    (
                        (*r1, *r2),
                        NotNan::new(
                            p1.distance_to(p2)
                                .unwrap_or_else(|_| p1.haversine_distance_to(p2))
                                .meters(),
                        )
                        .unwrap(),
                    )
                })
                .collect(),
        );

        Self {
            delivery_queue: PriorityQueue::new(),
            processing_queue: PriorityQueue::new(),
            messages: HashMap::new(),
            processing_dist: _init_processing_dist(),
            next_hops: HashMap::new(),
            fixed_next_hops: false,
            distances,
            delays: None,
            current_time: NotNan::default(),
        }
    }

    /// Create a new, empty model queue with given default parameters and delays in [µs]
    pub fn from_delays<V>(delays: &HashMap<(RouterId, RouterId), V>) -> Self
    where
        V: Into<f64> + Clone,
    {
        let delays = Some(HashMap::from_iter(delays.clone().into_iter().flat_map(
            |((from, to), t)| {
                // make sure to make all delays a `NotNan`
                let delay = NotNan::new(t.into()).unwrap();
                let mut res = vec![((from, to), delay)];
                // set the reverse option if it is not set differently
                if !delays.contains_key(&(to, from)) {
                    res.push(((to, from), delay));
                }
                res
            },
        )));

        Self {
            delivery_queue: PriorityQueue::new(),
            processing_queue: PriorityQueue::new(),
            messages: HashMap::new(),
            processing_dist: _init_processing_dist(),
            next_hops: HashMap::new(),
            fixed_next_hops: false,
            distances: None,
            delays,
            current_time: NotNan::default(),
        }
    }

    /// Set the distance between two nodes in light seconds
    pub fn set_distance(&mut self, src: RouterId, dst: RouterId, dist: f64) {
        if let Some(distances) = &mut self.distances {
            let dist = NotNan::new(dist).unwrap();
            distances.insert((src, dst), dist);
            distances.insert((dst, src), dist);
        } else {
            panic!("no distances set!");
        }
    }

    /// Get the direct delay between two nodes in [s]
    ///
    /// NOTE: This function assumes the reduced speed of light observed in optical network cables.
    pub fn get_delay(&mut self, src: RouterId, dst: RouterId) -> f64 {
        if let Some(distances) = &self.distances {
            distances
                .get(&(src, dst))
                .map(|x| *x.as_ref() / SPEED_OF_LIGHT)
                .unwrap_or(BASIC_TIMING_MODEL_DEFAULT_DELAY)
        } else if let Some(delays) = &self.delays {
            delays
                .get(&(src, dst))
                .map(|x| *x.as_ref() / 1_000_000.0)
                .unwrap_or(BASIC_TIMING_MODEL_DEFAULT_DELAY)
        } else {
            panic!("no distances or delays set!");
        }
    }

    /// Reset the current time to zero. This function will only have an effect if the
    /// queue is empty. Otherwise, nothing will happen.
    pub fn reset_time(&mut self) {
        if self.is_empty() {
            self.current_time = Default::default();
        }
    }

    /// Sample the time to get from source to target
    #[inline]
    fn propagation_time(&mut self, source: RouterId, target: RouterId) -> NotNan<f64> {
        NotNan::new(match self.next_hops.get(&(source, target)) {
            Some(next_hop) => self.get_delay(source, *next_hop),
            None => BASIC_TIMING_MODEL_DEFAULT_DELAY,
        })
        .unwrap()
    }

    /// This function needs to be called whenever you want to advance the queue's `current_time` to
    /// obtain the next processed event. It will deliver all events that are currently in transit
    /// but will reach their destination before the next event finishes processing. Therefore, we
    /// are guaranteed to enqueue packets for processing in the correct order.
    fn internal_advance_current_time(&mut self) {
        let mut next_processed = self.processing_queue.peek();
        let mut next_delivery = self.delivery_queue.peek();

        let mut rng = thread_rng();

        // As long as there is another delivery and
        // - there is either no processed event enqueued, or
        // - the next enqueued delivery happens before that,
        // deliver new events and sample their processing times.
        //
        // NOTE: we use the `.ge()` function here, because the type is a `Reverse(_)`.
        while next_delivery.is_some()
            && (next_processed.is_none() || next_delivery.unwrap().1.ge(next_processed.unwrap().1))
        {
            // get the next delivered event from the delivery_queue
            let (mut delivery, time) = self.delivery_queue.pop().unwrap();
            let Reverse(arrival_time) = time;

            // match on the next delivered event
            match delivery {
                (
                    Event::Bgp {
                        p: _,
                        src,
                        dst,
                        e: _,
                    },
                    nh,
                ) if dst != nh => {
                    // get the next_hop
                    let next_hop = *self.next_hops.get(&(nh, dst)).unwrap();
                    // compute the propagation time
                    let next_arrival_time = arrival_time + self.propagation_time(nh, next_hop);
                    // enqueue with the computed time
                    self.delivery_queue
                        .push((delivery.0, next_hop), Reverse(next_arrival_time));
                }
                (
                    Event::Bgp {
                        p: ref mut t,
                        src,
                        dst,
                        ref e,
                    },
                    _,
                ) => {
                    // compute the next time
                    let session = (src, dst);
                    // sample a processing time for the packet
                    let processing_time = NotNan::new(match e {
                        BgpEvent::Withdraw(_) => 0.0004,
                        BgpEvent::Update(_) => 0.000233,
                    })
                    .unwrap();
                    //NotNan::new(self.processing_dist.sample(&mut rng)).unwrap();
                    let mut next_time = arrival_time + processing_time;

                    // check if there is already something enqueued for this session
                    if let Some((ref mut num, ref mut time)) = self.messages.get_mut(&session) {
                        // start processing earliest when previous message is delivered
                        if *num > 0 && *time > arrival_time {
                            next_time = *time + processing_time;
                        }
                        *num += 1;
                        *time = next_time;
                    } else {
                        self.messages.insert(session, (1, next_time));
                    }
                    *t = next_time;

                    // enqueue with the computed time
                    self.processing_queue.push(delivery.0, Reverse(next_time));
                }
                (
                    Event::Ospf {
                        p: _,
                        src: _,
                        dst: _,
                        area: _,
                        e: _,
                    },
                    _,
                ) => unreachable!(),
            }

            // prepare to check whether the next packet is delivered before the (possibly updated)
            // next processed processed event
            next_processed = self.processing_queue.peek();
            next_delivery = self.delivery_queue.peek();
        }
    }

    pub fn fix_next_hops<Ospf: OspfProcess>(
        &mut self,
        routers: &HashMap<RouterId, NetworkDevice<P, Ospf>>,
    ) {
        self.update_next_hops(routers);
        self.fixed_next_hops = true;
    }

    fn update_next_hops<Ospf: OspfProcess>(
        &mut self,
        routers: &HashMap<RouterId, NetworkDevice<P, Ospf>>,
    ) {
        assert!(!self.fixed_next_hops);
        // update all next_hops
        for src in routers.keys() {
            for dst in routers.keys() {
                if let Some(next_hop) = routers.get(src).and_then(|r| match r {
                    NetworkDevice::InternalRouter(r) => {
                        Some(r.ospf.get(*dst)).and_then(|nhs| nhs.first())
                    }
                    NetworkDevice::ExternalRouter(r) => r.get_bgp_sessions().iter().next(),
                }) {
                    self.next_hops.insert((*src, *dst), *next_hop);
                }
            }
        }
    }
}

impl<P: Prefix> PartialEq for TimingModel<P> {
    /// Note that this is a very strict implementation that compares two `TimingModel`s
    /// literally. It may be that they encode exactly the same state, but in one queue an event has
    /// already been scheduled for processing. In some sense, this is required to check for
    /// equality, since the actual processing time would be sampled with randomness from the other
    /// queue and it would most likely not coincide.
    fn eq(&self, other: &Self) -> bool {
        self.processing_queue.iter().collect::<Vec<_>>()
            == other.processing_queue.iter().collect::<Vec<_>>()
            && self.delivery_queue.iter().collect::<Vec<_>>()
                == other.delivery_queue.iter().collect::<Vec<_>>()
    }
}

impl<P: Prefix> EventQueue<P> for TimingModel<P> {
    type Priority = NotNan<f64>;

    fn push<Ospf: OspfProcess>(
        &mut self,
        event: Event<P, Self::Priority>,
        _routers: &HashMap<RouterId, NetworkDevice<P, Ospf>>,
        _net: &PhysicalNetwork,
    ) {
        // match on the event
        match event {
            Event::Bgp {
                p: _,
                src,
                dst,
                e: _,
            } => {
                // get the next_hop
                let next_hop = *self.next_hops.get(&(src, dst)).unwrap();
                // compute the propagation time
                let arrival_time = self.current_time + self.propagation_time(src, next_hop);
                // enqueue with the computed time
                self.delivery_queue
                    .push((event, next_hop), Reverse(arrival_time));
            }
            Event::Ospf {
                p: _,
                src: _,
                dst: _,
                area: _,
                e: _,
            } => unreachable!(),
        }
    }

    fn pop(&mut self) -> Option<Event<P, Self::Priority>> {
        self.internal_advance_current_time();
        let (event, _) = self.processing_queue.pop()?;
        self.current_time = *event.priority();
        match event {
            Event::Bgp {
                p: _,
                src,
                dst,
                e: _,
            } => {
                if let Some((num, _)) = self.messages.get_mut(&(src, dst)) {
                    *num -= 1;
                }
            }
            Event::Ospf {
                p: _,
                src: _,
                dst: _,
                area: _,
                e: _,
            } => unreachable!(),
        }
        Some(event)
    }

    fn peek(&self) -> Option<&Event<P, Self::Priority>> {
        unimplemented!("This queue operates in a dual-queue mode, one for the delivery times of messages, and one for the completion of processing a message. Therefore, whenever we want to determine a next element, we might already need to select an item for processing even though another message might actually arrive first, and therefore modify the queues already. However, this would be somewhat unexpected behavior from a function called `peek` and require a mutable reference `&mut self`.");
    }

    fn len(&self) -> usize {
        self.delivery_queue.len() + self.processing_queue.len()
    }

    fn is_empty(&self) -> bool {
        self.delivery_queue.is_empty() && self.processing_queue.is_empty()
    }

    fn clear(&mut self) {
        self.delivery_queue.clear();
        self.processing_queue.clear();
        self.messages.clear();
        self.current_time = NotNan::default();
    }

    fn get_time(&self) -> Option<f64> {
        Some(self.current_time.into_inner())
    }

    /// Store all current forwarding next_hops from the network.
    fn update_params<Ospf: OspfProcess>(
        &mut self,
        routers: &HashMap<RouterId, NetworkDevice<P, Ospf>>,
        _net: &PhysicalNetwork,
    ) {
        if !self.fixed_next_hops {
            // clear old next_hops
            self.next_hops.clear();
            self.update_next_hops(routers);

            // HACKY WORKAROUND (because we cannot access the Network.routers object to give a
            // &HashMap reference to `fix_next_hops`: fix next hops after first update as there are
            // no more changes.
            self.fixed_next_hops = true;
        }
    }

    unsafe fn clone_events(&self, conquered: Self) -> Self {
        TimingModel {
            delivery_queue: self.delivery_queue.clone(),
            processing_queue: self.processing_queue.clone(),
            messages: self.messages.clone(),
            current_time: self.current_time,
            ..conquered
        }
    }
}
