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
//! Module to process FW records and apply a simple queuing model based on how fast the FIB can
//! write updates.

use std::collections::HashMap;

use bgpsim::types::RouterId;

use crate::records::FWRecord;

/// Model parameters
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FibQueuingModel {
    time_nh: f64,
    time_drop: f64,
    delay: f64,
    name: &'static str,
}

pub struct FibQueuingModelIterator<I> {
    iter: I,
    last_write: HashMap<RouterId, f64>,
    model: FibQueuingModel,
}

pub trait Maybe<T> {
    fn map<F: FnMut(T) -> T>(self, f: F) -> Self;
}

impl<T> Maybe<T> for T {
    fn map<F: FnMut(T) -> T>(self, mut f: F) -> Self {
        f(self)
    }
}

impl<T> Maybe<T> for Option<T> {
    fn map<F: FnMut(T) -> T>(self, f: F) -> Self {
        self.map(f)
    }
}

impl<T, E> Maybe<T> for Result<T, E> {
    fn map<F: FnMut(T) -> T>(self, f: F) -> Self {
        self.map(f)
    }
}

impl FibQueuingModel {
    // Apply a sequence of FW records according to the given model.
    pub fn apply<I: IntoIterator<IntoIter = J>, J>(&self, iter: I) -> FibQueuingModelIterator<J> {
        FibQueuingModelIterator {
            iter: iter.into_iter(),
            last_write: Default::default(),
            model: *self,
        }
    }
}

impl<I, T> Iterator for FibQueuingModelIterator<I>
where
    I: Iterator<Item = T>,
    T: Maybe<FWRecord>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.iter.next()?;
        Some(record.map(|mut record| {
            let last_write = self.last_write.entry(record.src).or_insert(f64::MIN);
            let process_start_time = f64::max(*last_write, record.time + self.model.delay);
            let process_duration = match record.next_hop {
                Some(_) => self.model.time_nh,
                None => self.model.time_drop,
            };
            let written_time = process_start_time + process_duration;
            record.time = written_time;
            *last_write = written_time;
            record
        }))
    }
}

impl std::fmt::Display for FibQueuingModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}_nh-{:.0}us_drop-{:.0}us_delay-{:.0}ms",
            self.name,
            self.time_nh * 1e6,
            self.time_drop * 1e6,
            self.delay * 1e3
        )
    }
}

pub const NO_QUEUING: FibQueuingModel = FibQueuingModel {
    name: "no-queuing",
    time_nh: 0.0,
    time_drop: 0.0,
    delay: 0.0,
};

pub const NX9K: FibQueuingModel = FibQueuingModel {
    name: "nx9k",
    time_nh: 0.000_060_037_916,   // from brrtt
    time_drop: 0.000_060_037_916, // from brrtt

    delay: 0.0,
};

pub const NX9K_ASYMMETRIC: FibQueuingModel = FibQueuingModel {
    name: "nx9k-asymmetric",
    time_drop: 0.000_060_037_916, // from brrtt
    // time_nh: 0.000_180_219_045,   // from brrtt
    time_nh: 0.000_100_491_079, // from single sample

    delay: 0.0,
};

pub const NX9K_BGP: FibQueuingModel = FibQueuingModel {
    name: "nx9k-bgp",
    delay: 0.0701,
    ..NX9K
};

pub const NX9K_URIB: FibQueuingModel = FibQueuingModel {
    name: "nx9k-urib",
    delay: 0.0554,
    ..NX9K
};

pub const NX9K_UFDM: FibQueuingModel = FibQueuingModel {
    name: "nx9k-ufdm",
    delay: 0.0133,
    ..NX9K
};

pub const NX9K_IPFIB: FibQueuingModel = FibQueuingModel {
    name: "nx9k-ipfib",
    delay: 0.0075,
    ..NX9K
};
