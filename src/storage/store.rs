use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::value::{EncryptedValue, ValueEntry};

#[derive(Debug, Serialize, Deserialize)]
pub struct Storage {
    pub data: HashMap<String, Vec<ValueEntry>>,
}

impl Storage {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
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

    pub fn get(&self, pattern: &str) -> Result<Vec<(String, EncryptedValue)>> {
        let re = Regex::new(&format!("^{pattern}$"))?;
        let mut results = Vec::new();

        for (key, entries) in &self.data {
            if re.is_match(key)
                && let Some(entry) = entries.last()
            {
                results.push((key.clone(), entry.value.clone()));
            }
        }

        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    pub fn history(&self, key: &str) -> Option<&Vec<ValueEntry>> {
        self.data.get(key)
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    pub fn search(&self, pattern: &str) -> Result<Vec<String>> {
        let re = Regex::new(pattern)?;
        let mut keys: Vec<String> = self
            .data
            .keys()
            .filter(|k| re.is_match(k))
            .cloned()
            .collect();
        keys.sort();
        Ok(keys)
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}
