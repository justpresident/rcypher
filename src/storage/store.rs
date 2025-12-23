use std::collections::BTreeMap;
use std::string::String;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::value::{EncryptedValue, ValueEntry};

#[derive(Debug, Serialize, Deserialize)]
pub struct Storage {
    pub data: BTreeMap<String, Vec<ValueEntry>>,
}

impl Storage {
    pub const fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn put(&mut self, key: String, value: EncryptedValue) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should go forward")
            .as_secs();

        self.put_ts(key, value, timestamp);
    }

    pub fn put_ts(&mut self, key: String, value: EncryptedValue, timestamp: u64) {
        self.data
            .entry(key)
            .or_default()
            .push(ValueEntry { value, timestamp });
    }

    /// Returns an iterator over key-value pairs matching the given regex pattern.
    ///
    /// # Sorting
    /// - Keys are returned in sorted order (guaranteed by `BTreeMap`)
    /// - Returns the latest value for each key (relies on entries being sorted
    ///   by timestamp during deserialization in `deserialize_storage_v4`)
    pub fn get(&self, pattern: &str) -> Result<impl Iterator<Item = (&str, &EncryptedValue)> + '_> {
        let re = Regex::new(&format!("^{pattern}$"))?;
        Ok(self
            .data
            .iter()
            .filter(move |(k, entries)| re.is_match(k) && !entries.is_empty())
            .filter_map(|(k, entries)| entries.last().map(|entry| (k.as_str(), &entry.value))))
    }

    /// Returns an iterator over all historical values for a given key.
    ///
    /// # Sorting
    /// Entries are returned in chronological order (oldest to newest).
    /// This ordering is guaranteed by timestamp sorting during deserialization
    /// in `deserialize_storage_v4`.
    pub fn history(&self, key: &str) -> Option<impl Iterator<Item = &ValueEntry> + '_> {
        self.data.get(key).map(|entries| entries.iter())
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    /// Returns an iterator over all keys matching the given regex pattern.
    ///
    /// # Sorting
    /// Keys are returned in sorted order (guaranteed by `BTreeMap`).
    pub fn search(&self, pattern: &str) -> Result<impl Iterator<Item = &str> + '_> {
        let re = Regex::new(pattern)?;
        Ok(self
            .data
            .keys()
            .filter(move |k| re.is_match(k))
            .map(String::as_str))
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}
