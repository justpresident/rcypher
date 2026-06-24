use std::collections::BTreeMap;
use std::path::Path;
use std::string::String;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use regex::Regex;
use zeroize::Zeroizing;

use super::value::{EncryptedValue, ValueEntry};
use crate::crypto::Cypher;
use crate::file_io::{load_encrypted, save_encrypted};
use crate::version::DataContainerVersion;

/// The decrypted key-value data of a store: each key maps to its full,
/// timestamp-ordered history of encrypted values.
///
/// Convert to/from on-disk bytes with [`safe_serialize`](Self::safe_serialize) /
/// [`safe_deserialize`](Self::safe_deserialize); read or write an encrypted file
/// with [`load`](Self::load) / [`save`](Self::save).
#[derive(Debug)]
pub struct DataContainer {
    data: BTreeMap<String, Vec<ValueEntry>>,
}

impl DataContainer {
    pub const fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn put(&mut self, key: String, value: EncryptedValue) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
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
    ///   by timestamp during parsing in [`from_v4_bytes`](Self::from_v4_bytes))
    pub fn get(&self, pattern: &str) -> Result<impl Iterator<Item = (&str, &EncryptedValue)> + '_> {
        let re = Regex::new(&format!("^{pattern}$"))?;
        Ok(self
            .data
            .iter()
            .filter(move |(k, entries)| re.is_match(k) && !entries.is_empty())
            .filter_map(|(k, entries)| entries.last().map(|entry| (k.as_str(), &entry.value))))
    }

    /// The full history of `key`, oldest to newest, or `None` if it is absent.
    ///
    /// # Sorting
    /// Entries are chronological (oldest to newest), guaranteed by the timestamp
    /// sort in [`from_v4_bytes`](Self::from_v4_bytes).
    pub fn history(&self, key: &str) -> Option<&[ValueEntry]> {
        self.data.get(key).map(Vec::as_slice)
    }

    /// The latest entry stored under `key`, if any.
    pub fn latest(&self, key: &str) -> Option<&ValueEntry> {
        self.data.get(key).and_then(|entries| entries.last())
    }

    /// Iterates every key paired with its latest entry.
    pub fn iter_latest(&self) -> impl Iterator<Item = (&str, &ValueEntry)> + '_ {
        self.data
            .iter()
            .filter_map(|(k, entries)| entries.last().map(|e| (k.as_str(), e)))
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    /// An iterator over every stored key, in sorted order (`BTreeMap` order).
    pub fn keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.data.keys().map(String::as_str)
    }

    /// The number of distinct keys.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the container holds no keys.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Re-encrypts every stored value — across all keys and their full history —
    /// from the `from` cypher to the `to` cypher, in place.
    ///
    /// Used when a store's data-encryption key changes, e.g. converting a legacy
    /// single-password file to the current multi-factor format under a fresh key.
    /// Each decrypted plaintext lives only in a zeroizing buffer for the single
    /// re-encryption and is wiped before the next entry.
    pub fn reencrypt(&mut self, from: &Cypher, to: &Cypher) -> Result<()> {
        for entries in self.data.values_mut() {
            for entry in entries {
                let plaintext = entry.value.decrypt(from)?;
                entry.value = EncryptedValue::encrypt(to, &plaintext)?;
            }
        }
        Ok(())
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

    /// Loads and decrypts a data container from `path`, or an empty one if the
    /// file does not exist.
    pub fn load(cypher: &Cypher, path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let decrypted = load_encrypted(cypher, path)?;
        Self::safe_deserialize(&decrypted)
    }

    /// Serializes, encrypts, and writes this data container to `path`.
    pub fn save(&self, cypher: &Cypher, path: &Path) -> Result<()> {
        let serialized = self.safe_serialize()?;
        save_encrypted(cypher, &serialized, path)
    }

    /// Serializes this data container to the cleartext bytes later encrypted as
    /// the payload.
    ///
    /// The bytes carry the (cleartext) entry keys, so they are returned in a
    /// zeroizing buffer — the return type makes that non-optional, matching
    /// [`load_encrypted`], which returns the decrypted payload zeroizing.
    pub fn safe_serialize(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut result = Zeroizing::new(Vec::new());

        // Version
        result.extend_from_slice(&DataContainerVersion::Version4.tag());

        // Count elements
        let count: u32 = u32::try_from(self.data.values().map(Vec::len).sum::<usize>())
            .map_err(|_| anyhow::anyhow!("too many entries to serialize (max {})", u32::MAX))?;
        result.extend_from_slice(&count.to_be_bytes());

        // Serialize each entry
        for (key, entries) in &self.data {
            for entry in entries {
                let key_bytes = key.as_bytes();
                let val_bytes = entry.value.as_bytes();

                let key_len = u16::try_from(key_bytes.len()).map_err(|_| {
                    anyhow::anyhow!("key too long to serialize (max {} bytes)", u16::MAX)
                })?;
                result.extend_from_slice(&key_len.to_be_bytes());
                result.extend_from_slice(key_bytes);
                let val_len = u32::try_from(val_bytes.len()).map_err(|_| {
                    anyhow::anyhow!("value too long to serialize (max {} bytes)", u32::MAX)
                })?;
                result.extend_from_slice(&val_len.to_be_bytes());
                result.extend_from_slice(val_bytes);
                // We store only seconds (truncating to u32; valid until year 2106)
                #[allow(clippy::cast_possible_truncation)]
                result.extend_from_slice(&(entry.timestamp as u32).to_be_bytes());
            }
        }

        Ok(result)
    }

    /// Parses the on-disk payload, dispatching on its leading version tag.
    pub fn safe_deserialize(data: &[u8]) -> Result<Self> {
        match DataContainerVersion::probe_data(data)? {
            DataContainerVersion::Version4 => Self::from_v4_bytes(data),
        }
    }

    /// Parses the version-4 on-disk body (the leading two bytes are its tag).
    fn from_v4_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            bail!("data too short");
        }

        let count = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let mut container = Self::new();
        let mut pos = 6;

        for _ in 0..count {
            if pos + 2 > data.len() {
                bail!("Corrupted file: unexpected end");
            }

            let key_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + key_len > data.len() {
                bail!("Corrupted file: key overflow");
            }
            let key = String::from_utf8(data[pos..pos + key_len].to_vec())?;
            pos += key_len;

            if pos + 4 > data.len() {
                bail!("Corrupted file: value length missing");
            }
            let val_len =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            pos += 4;

            if pos + val_len > data.len() {
                bail!("Corrupted file: value overflow");
            }
            let value = EncryptedValue::from_ciphertext(data[pos..pos + val_len].to_vec());
            pos += val_len;

            if pos + 4 > data.len() {
                bail!("Corrupted file: timestamp missing");
            }
            let timestamp = u64::from(u32::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]));
            pos += 4;

            container
                .data
                .entry(key)
                .or_default()
                .push(ValueEntry { value, timestamp });
        }

        // Sort each key's entries by timestamp so history()/get()/latest() can
        // rely on chronological order without re-sorting on every call.
        for entries in container.data.values_mut() {
            entries.sort_by_key(|e| e.timestamp);
        }

        Ok(container)
    }
}

impl Default for DataContainer {
    fn default() -> Self {
        Self::new()
    }
}
