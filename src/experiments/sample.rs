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
//! Module to store processed information relating a single sample taken from the routing testbed.
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

use itertools::Itertools;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[allow(unused)]
pub struct Sample {
    /// The execution timestamp of this `Sample`.
    pub sample_id: String,
    /// prefix -> router_name -> ViolationInfo
    #[serde(serialize_with = "serialize_ordered")]
    pub violation_times: HashMap<String, HashMap<String, ViolationInfo>>,
}

/// Serialize a HashMap of HashMaps sorted by the keys
fn serialize_ordered<
    K: Serialize + Ord,
    K2: Clone + Hash + Serialize + Ord,
    V: Clone + Serialize,
    S: Serializer,
>(
    map: &HashMap<K, HashMap<K2, V>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(
        map.iter()
            .sorted_by(|(p, _), (p2, _)| p.cmp(p2))
            .map(|(prefix, prefix_map)| (prefix, BTreeMap::<K2, V>::from_iter(prefix_map.clone()))),
    )
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ViolationInfo {
    Time(f64),
    External(String),
    Route(Vec<String>),
}

impl PartialEq<f64> for ViolationInfo {
    fn eq(&self, other: &f64) -> bool {
        match self {
            Self::Time(x) => x == other,
            Self::External(_) | Self::Route(_) => false,
        }
    }
}

impl PartialEq<String> for ViolationInfo {
    fn eq(&self, other: &String) -> bool {
        match self {
            Self::External(x) => x == other,
            Self::Time(_) | Self::Route(_) => false,
        }
    }
}

impl PartialEq<Vec<String>> for ViolationInfo {
    fn eq(&self, other: &Vec<String>) -> bool {
        match self {
            Self::Time(_) | Self::External(_) => false,
            Self::Route(xs) => format!("{:?}", xs) == format!("{:?}", other),
        }
    }
}

impl PartialEq for ViolationInfo {
    fn eq(&self, other: &Self) -> bool {
        match other {
            Self::Time(x) => self == x,
            Self::External(x) => self == x,
            Self::Route(xs) => self == xs,
        }
    }
}

impl Eq for ViolationInfo {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize() {
        let sample = Sample {
            sample_id: "thisisasampleid".to_string(),
            violation_times: HashMap::from_iter([(
                "100.0.0.0/24".to_string(),
                HashMap::from_iter([
                    ("r0".to_string(), ViolationInfo::Time(0.001)),
                    (
                        "r0_ext_init".to_string(),
                        ViolationInfo::External("r0_ext".to_string()),
                    ),
                    (
                        "r0_ext_post".to_string(),
                        ViolationInfo::External("r1_ext".to_string()),
                    ),
                    (
                        "r0_route_init".to_string(),
                        ViolationInfo::Route(vec!["r0".to_string(), "r0_ext".to_string()]),
                    ),
                    (
                        "r0_route_post".to_string(),
                        ViolationInfo::Route(vec![
                            "r0".to_string(),
                            "r1".to_string(),
                            "r1_ext".to_string(),
                        ]),
                    ),
                    ("r1".to_string(), ViolationInfo::Time(0.0)),
                    (
                        "r1_ext_init".to_string(),
                        ViolationInfo::External("r1_ext".to_string()),
                    ),
                    (
                        "r1_ext_post".to_string(),
                        ViolationInfo::External("r1_ext".to_string()),
                    ),
                    (
                        "r1_route_init".to_string(),
                        ViolationInfo::Route(vec!["r1".to_string(), "r1_ext".to_string()]),
                    ),
                    (
                        "r1_route_post".to_string(),
                        ViolationInfo::Route(vec!["r1".to_string(), "r1_ext".to_string()]),
                    ),
                ]),
            )]),
        };
        let json = r#"
        {
            "sample_id": "thisisasampleid",
            "violation_times": {
                "100.0.0.0/24": {
                    "r0": 0.001,
                    "r0_ext_init": "r0_ext",
                    "r0_ext_post": "r1_ext",
                    "r0_route_init": ["r0", "r0_ext"],
                    "r0_route_post": ["r0", "r1", "r1_ext"],
                    "r1": 0.0,
                    "r1_ext_init": "r1_ext",
                    "r1_ext_post": "r1_ext",
                    "r1_route_init": ["r1", "r1_ext"],
                    "r1_route_post": ["r1", "r1_ext"]
                }
            }
        }"#;
        let expected: String = json.chars().filter(|c| !c.is_whitespace()).collect();

        let serialized = serde_json::to_string(&sample).unwrap();

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_deserialize() {
        let json = r#"
        {
            "sample_id": "thisisasampleid",
            "violation_times": {
                "100.0.0.0/24": {
                    "r0": 0.001,
                    "r0_ext_init": "r0_ext",
                    "r0_ext_post": "r1_ext",
                    "r0_route_init": ["r0", "r0_ext"],
                    "r0_route_post": ["r0", "r1", "r1_ext"],
                    "r1": 0.0,
                    "r1_ext_init": "r1_ext",
                    "r1_ext_post": "r1_ext",
                    "r1_route_init": ["r1", "r1_ext"],
                    "r1_route_post": ["r1", "r1_ext"]
                }
            }
        }"#;

        let sample: Sample = serde_json::from_str(json).unwrap();

        assert_eq!(sample.sample_id, "thisisasampleid".to_string());
        assert_eq!(sample.violation_times["100.0.0.0/24"].len(), 10);
        assert_eq!(sample.violation_times["100.0.0.0/24"]["r0"], 0.001);
        assert_eq!(sample.violation_times["100.0.0.0/24"]["r1"], 0.0);
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r0_ext_init"],
            "r0_ext".to_string()
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r0_ext_post"],
            "r1_ext".to_string()
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r0_route_init"],
            vec!["r0".to_string(), "r0_ext".to_string()]
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r0_route_post"],
            vec!["r0".to_string(), "r1".to_string(), "r1_ext".to_string()]
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r1_ext_init"],
            "r1_ext".to_string()
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r1_ext_post"],
            "r1_ext".to_string()
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r1_route_init"],
            vec!["r1".to_string(), "r1_ext".to_string()]
        );
        assert_eq!(
            sample.violation_times["100.0.0.0/24"]["r1_route_post"],
            vec!["r1".to_string(), "r1_ext".to_string()]
        );
    }

    #[test]
    fn test_reserialize() {
        let sample = Sample {
            sample_id: "thisisasampleid".to_string(),
            violation_times: HashMap::from_iter([(
                "100.0.0.0/24".to_string(),
                HashMap::from_iter([
                    ("r0".to_string(), ViolationInfo::Time(0.001)),
                    (
                        "r0_ext_init".to_string(),
                        ViolationInfo::External("r0_ext".to_string()),
                    ),
                    (
                        "r0_ext_post".to_string(),
                        ViolationInfo::External("r1_ext".to_string()),
                    ),
                    (
                        "r0_route_init".to_string(),
                        ViolationInfo::Route(vec!["r0".to_string(), "r0_ext".to_string()]),
                    ),
                    (
                        "r0_route_post".to_string(),
                        ViolationInfo::Route(vec![
                            "r0".to_string(),
                            "r1".to_string(),
                            "r1_ext".to_string(),
                        ]),
                    ),
                    ("r1".to_string(), ViolationInfo::Time(0.0)),
                    (
                        "r1_ext_init".to_string(),
                        ViolationInfo::External("r1_ext".to_string()),
                    ),
                    (
                        "r1_ext_post".to_string(),
                        ViolationInfo::External("r1_ext".to_string()),
                    ),
                    (
                        "r1_route_init".to_string(),
                        ViolationInfo::Route(vec!["r1".to_string(), "r1_ext".to_string()]),
                    ),
                    (
                        "r1_route_post".to_string(),
                        ViolationInfo::Route(vec!["r1".to_string(), "r1_ext".to_string()]),
                    ),
                ]),
            )]),
        };

        let serialized = serde_json::to_string(&sample).unwrap();
        let deserialized: Sample = serde_json::from_str(&serialized).unwrap();

        assert_eq!(sample, deserialized);
    }
}
