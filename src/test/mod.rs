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
//! Test cases to test how accurate we are.
//!
//! Use the following commands to see the diffs:
//!
//! ```shell
//! cargo test --release -- --nocapture --test-threads 1 --quiet
//! ```

pub fn check_diff(exp: f64, acq: f64, precision: f64, n_iter: usize) {
    let diff = (exp - acq).abs();

    if diff < precision * 0.5 {
        eprintln!(
            "diff: {}{:.4}%{} with precision = {:.2}% and {} iterations",
            termion::color::Fg(termion::color::Green),
            diff * 100.0,
            termion::color::Fg(termion::color::Reset),
            precision * 100.0,
            n_iter
        );
    } else {
        eprintln!(
            "diff: {}{:.4}%{} with precision = {:.2}% and {} iterations",
            termion::color::Fg(termion::color::Red),
            diff * 100.0,
            termion::color::Fg(termion::color::Reset),
            precision * 100.0,
            n_iter,
        );
        panic!()
    }
}

mod hard_waypoints;
mod loop_free;
mod waypoints;
