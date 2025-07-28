//! Module that allows to (de-)serialize a generic `HashMap` with `serde`.

use std::{collections::HashMap, hash::Hash};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Helper struct that allows (de-)serialization of a `HashMap` as this type.
///
/// Example:
/// ```ignore
/// serde_json::to_string_pretty(&SerializeHashmap::from(hashmap)).unwrap();
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializeHashmap<K, V>(
    #[serde(with = "super::generic_hashmap")]
    #[serde(bound(
        deserialize = "K: Hash + Eq, for<'de_k> K: Deserialize<'de_k>, for<'de_v> V: Deserialize<'de_v>",
        serialize = "K: Serialize, V: Serialize",
    ))]
    pub HashMap<K, V>,
);

impl<K, V> From<HashMap<K, V>> for SerializeHashmap<K, V> {
    fn from(hashmap: HashMap<K, V>) -> Self {
        Self(hashmap)
    }
}
impl<K, V> From<SerializeHashmap<K, V>> for HashMap<K, V> {
    fn from(val: SerializeHashmap<K, V>) -> Self {
        val.0
    }
}

/// Helper struct that allows (de-)serialization of a single entry.
#[derive(Deserialize, Serialize)]
struct Entry<K, V> {
    key: K,
    val: V,
}

/// Serialize a HashMap whose Key is a tuple of serializable
///
/// NOTE: taken from <https://github.com/serde-rs/json/issues/456>
pub fn serialize<K: Serialize, V: Serialize, S: Serializer>(
    map: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(map.iter().map(|(key, val)| Entry { key, val }))
}

/// Deserialize a HashMap whose Key is a tuple of serializable
///
/// NOTE: taken from <https://github.com/serde-rs/json/issues/456>
pub fn deserialize<'de, K: Deserialize<'de> + Eq + Hash, V: Deserialize<'de>, D>(
    deserializer: D,
) -> Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<Entry<K, V>>::deserialize(deserializer).map(|mut v| {
        v.drain(..)
            .map(|entry: Entry<K, V>| (entry.key, entry.val))
            .collect()
    })
}

pub mod in_option {
    use std::{collections::HashMap, hash::Hash};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Entry;

    // For untagged enums, serde will deserialize as the first variant that it possibly can.
    //
    // https://serde.rs/enum-representations.html#untagged
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MaybeOption<K, V> {
        // if it can be parsed as Option<()>, i.e., `None`, it will be
        #[allow(dead_code)]
        NoneValue(Option<()>),
        // otherwise try parsing as a generic `Vec<Entry<K, V>>` and turn it into a `HashMap` after
        SomeValue(Vec<Entry<K, V>>),
    }

    /// Serialize an `Option<HashMap>` whose Key is a tuple of serializable
    pub fn serialize<K: Serialize, V: Serialize, S: Serializer>(
        map: &Option<HashMap<K, V>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match map {
            Some(content) => super::serialize(content, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize an `Option<HashMap>` whose Key is a tuple of serializable
    pub fn deserialize<'de, K: Deserialize<'de> + Eq + Hash, V: Deserialize<'de>, D>(
        deserializer: D,
    ) -> Result<Option<HashMap<K, V>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match MaybeOption::<K, V>::deserialize(deserializer).unwrap() {
            MaybeOption::NoneValue(_) => Ok(None),
            MaybeOption::SomeValue(mut v) => Ok(Some(
                v.drain(..)
                    .map(|entry: Entry<K, V>| (entry.key, entry.val))
                    .collect(),
            )),
        }
    }
}
