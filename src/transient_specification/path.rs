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
//! Path utility to keep track of transiently experienced forwarding paths.

use std::iter::repeat;

use bgpsim::prelude::*;

use crate::Prefix;

/// Encode the three possible behaviors:
/// - `Route`, that leads to the destination
/// - `Loop`, that contains a path toward a loop and then the loop
/// - `BlackHole`, that leads to a device dropping traffic
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(unused)]
pub enum Path {
    /// Represents a path reaching the destination, passing a list of routers in order. Starts with
    /// the router that traffic emanates at. Ends at the external router.
    Route(Vec<RouterId>),
    /// Represents a path that leads to a loop in order. Starts with the router that traffic
    /// emanates at, the first list ends in the first router on the loop. The second list walks the
    /// loop precisely once, without duplicates, starting at the last entry of the first list.
    Loop(Vec<RouterId>, Vec<RouterId>),
    /// Represents a path not reaching the destination, passing a list of routers in order. Starts
    /// with the router that traffic emanates at. Ends at the router that drops the traffic.
    BlackHole(Vec<RouterId>),
}

#[allow(unused)]
impl Path {
    /// check if a `Path` is a `Route` to the destination
    pub fn is_route(&self) -> bool {
        matches!(self, Self::Route(_))
    }

    /// check if a `Path` ends in a `Loop`
    pub fn is_loop(&self) -> bool {
        matches!(self, Self::Loop(_, _))
    }

    /// check if a `Path` ends in a `BlackHole`
    pub fn is_black_hole(&self) -> bool {
        matches!(self, Self::BlackHole(_))
    }

    /// check if a `Path` traverses the given `RouterId`
    pub fn contains(&self, x: &RouterId) -> bool {
        match self {
            Self::Route(p) | Self::BlackHole(p) => p.contains(x),
            Self::Loop(p, l) => p.contains(x) || l.contains(x),
        }
    }

    /// Returns a `Vec<RouterId>` representation of the `Path`; potentially looses information.
    pub fn get_rid_vec(&self) -> Vec<RouterId> {
        match self {
            Self::Route(p) | Self::BlackHole(p) => p.clone(),
            Self::Loop(p, l) => {
                let mut result = p.clone();
                result.extend(l);
                result
            }
        }
    }

    /// Combine two `Path`s, assuming the first is a `Path::Route` and ends in the same router that
    /// the other `Path` starts with.
    ///
    /// Constructed paths might pass nodes twice, but that would only be a `Loop` if the traffic
    /// would loop thereon after. Hence, there is no check whether the combined path visits a node
    /// twice, as this should only happen if in the current forwarding state, there is no loop.
    pub fn combine_with(&self, other: &Self) -> Self {
        match self {
            Self::Route(p) => {
                let mut path = p.clone();
                match other {
                    Self::Route(p2) | Self::Loop(p2, _) | Self::BlackHole(p2) => {
                        assert_eq!(path[path.len() - 1], p2[0]);
                        path.pop();
                        path.extend(p2);

                        // combine to the according type as required
                        match other {
                            Self::Route(_) => Self::Route(path),
                            Self::BlackHole(_) => Self::BlackHole(path),
                            Self::Loop(_, l) => Self::Loop(path, l.clone()),
                        }
                    }
                }
            }
            _ => {
                unimplemented!("This function assumes that the first argument is a `Path::Route`!")
            }
        }
    }

    /// Split a `Path` at the given `RouterId`, returning a `Vec<RouterId>` that contains the path
    /// to (and including) the given `RouterId`.
    ///
    /// TODO: potentially optimize by using iterators/slices instead of cloning here
    pub fn split_first(&self, at: &RouterId) -> Option<Vec<RouterId>> {
        match self {
            Self::Route(p) | Self::BlackHole(p) => p
                .iter()
                .position(|rid| rid == at)
                .map(|position| self.split_at(position + 1)),
            Self::Loop(p, l) => p
                .iter()
                .chain(l.iter().skip(1))
                .position(|rid| rid == at)
                .map(|position| self.split_at(position + 1)),
        }
    }

    /// Split a `Path` at the given `RouterId`, returning a `Vec<_>` of indices after how many hops
    /// the path would reach the given router. Capped at length at most `bound`.
    fn _all_split_indices_bounded(&self, at: &RouterId, bound: usize) -> Vec<usize> {
        match self {
            // To make the types match up, we take path.iter() and chain an iterator of size 0 (due
            // to the tak 0). This chain will not change the path.iter().
            Self::Route(path) | Self::BlackHole(path) => path
                .iter()
                .chain(repeat(path.iter()).flatten().skip(1).take(0)),
            Self::Loop(path, loop_path) => path.iter().chain(
                repeat(loop_path.iter())
                    .flatten()
                    .skip(1)
                    .take(bound.saturating_sub(path.len())),
            ),
        }
        .enumerate()
        .filter_map(move |(position, rid)| (position < bound && rid == at).then_some(position))
        .collect::<Vec<_>>()
    }

    /// Split a `Path` at the given `RouterId`, returning an iterator for `Vec<RouterId>`, over all
    /// the possible paths taken to (and including) the given `RouterId` with length at most `bound`.
    ///
    /// TODO: Note that the iterator internally allocates the different options and only produces
    /// the respective `Path` instances on the fly.
    pub fn all_splits_bounded<'a>(
        &'a self,
        at: &'a RouterId,
        bound: usize,
    ) -> impl Iterator<Item = Vec<RouterId>> + 'a {
        self._all_split_indices_bounded(at, bound)
            .into_iter()
            .map(|position| self.split_at(position + 1))
    }

    /// Split a `Path` at the given `RouterId`, returning an iterator for `Vec<RouterId>`, over all
    /// the possible paths taken to (and including) the given `RouterId` with length at most
    /// `bound` in reverse order.
    ///
    /// TODO: Note that the iterator internally allocates the different options and only produces
    /// the respective `Path` instances on the fly.
    pub fn all_splits_bounded_rev<'a>(
        &'a self,
        at: &'a RouterId,
        bound: usize,
    ) -> impl Iterator<Item = Vec<RouterId>> + 'a {
        self._all_split_indices_bounded(at, bound)
            .into_iter()
            .rev()
            .map(|position| self.split_at(position + 1))
    }

    /// Split a `Path` at the given `position`, returning a `Vec<RouterId>` that contains the path
    /// to (but not including) the `RouterId` at the given `position`. If the `Path` is shorter
    /// than `position + 1` elements, either the same path is returned or, in case of a
    /// `Path::Loop`, the loop is appended.
    pub fn split_at(&self, position: usize) -> Vec<RouterId> {
        match self {
            Self::Route(p) | Self::BlackHole(p) => {
                if p.len() > position {
                    p[0..position].to_vec()
                } else {
                    p.clone()
                }
            }
            Self::Loop(p, l) => {
                let mut path;

                // check how much we need of the way to the loop
                if p.len() > position {
                    path = p[0..position].to_vec()
                } else {
                    path = p.clone();
                    path.pop();
                }

                // keep running around the loop if necessary
                while position > path.len() + l.len() {
                    path.extend(l);
                }
                // finish with the last chunk of the loop if necessary
                path.extend_from_slice(&l[0..position.checked_sub(path.len()).unwrap()]);

                path
            }
        }
    }
}

impl<'a, 'n, Q, Ospf: OspfImpl> bgpsim::formatter::NetworkFormatter<'a, 'n, Prefix, Q, Ospf>
    for Path
{
    type Formatter = String;

    fn fmt(&'a self, net: &'n Network<Prefix, Q, Ospf>) -> Self::Formatter {
        match self {
            Self::Route(p) => format!("Route({})", p.fmt(net)),
            Self::Loop(p, l) => format!("Loop({}, {})", p.fmt(net), l.fmt(net)),
            Self::BlackHole(p) => format!("BlackHole({})", p.fmt(net)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn path_manipulation() {
        let route = Path::Route(vec![0.into(), 1.into()]);
        let blackhole = Path::BlackHole(vec![1.into(), 2.into()]);
        let loopy = Path::Loop(vec![1.into(), 2.into()], vec![2.into(), 3.into()]);

        // combine_with
        assert_eq!(
            route.combine_with(&blackhole),
            Path::BlackHole(vec![0.into(), 1.into(), 2.into()])
        );
        assert_eq!(
            route.combine_with(&loopy),
            Path::Loop(vec![0.into(), 1.into(), 2.into()], vec![2.into(), 3.into()]),
        );

        // split_at
        assert_eq!(route.split_at(1), vec![0.into()]);

        assert_eq!(route.split_at(4), route.get_rid_vec());
        assert_eq!(blackhole.split_at(4), blackhole.get_rid_vec());
        assert_eq!(
            loopy.split_at(4),
            vec![1.into(), 2.into(), 3.into(), 2.into()]
        );
        assert_eq!(
            loopy.split_at(6),
            vec![1.into(), 2.into(), 3.into(), 2.into(), 3.into(), 2.into()]
        );

        // split
        assert_eq!(route.split_first(&0.into()), Some(vec![0.into()]));
        assert_eq!(route.split_first(&1.into()), Some(route.get_rid_vec()));
        assert_eq!(route.split_first(&9.into()), None);

        assert_eq!(blackhole.split_first(&1.into()), Some(vec![1.into()]));
        assert_eq!(
            blackhole.split_first(&2.into()),
            Some(blackhole.get_rid_vec())
        );
        assert_eq!(blackhole.split_first(&9.into()), None);

        assert_eq!(loopy.split_first(&1.into()), Some(vec![1.into()]));
        assert_eq!(loopy.split_first(&2.into()), Some(vec![1.into(), 2.into()]));
        assert_eq!(
            loopy.split_first(&3.into()),
            Some(vec![1.into(), 2.into(), 3.into()])
        );
        assert_eq!(loopy.split_first(&9.into()), None);

        // all_splits
        assert_eq!(
            route.all_splits_bounded(&1.into(), 10).collect::<Vec<_>>(),
            vec![vec![0.into(), 1.into()]]
        );
        assert_eq!(
            blackhole
                .all_splits_bounded(&1.into(), 10)
                .collect::<Vec<_>>(),
            vec![vec![1.into()]]
        );
        assert_eq!(
            loopy.all_splits_bounded(&1.into(), 10).collect::<Vec<_>>(),
            vec![vec![1.into()]]
        );
        assert_eq!(
            loopy.all_splits_bounded(&2.into(), 10).collect::<Vec<_>>(),
            vec![
                vec![1.into(), 2.into()],
                vec![1.into(), 2.into(), 3.into(), 2.into()],
                vec![1.into(), 2.into(), 3.into(), 2.into(), 3.into(), 2.into()],
                vec![
                    1.into(),
                    2.into(),
                    3.into(),
                    2.into(),
                    3.into(),
                    2.into(),
                    3.into(),
                    2.into()
                ],
                vec![
                    1.into(),
                    2.into(),
                    3.into(),
                    2.into(),
                    3.into(),
                    2.into(),
                    3.into(),
                    2.into(),
                    3.into(),
                    2.into()
                ],
            ]
        );
    }
}
