use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use tempfile::NamedTempFile;

use crate::crypto::Cypher;
use crate::version::StoreVersion;

use super::store::StorageV4;
use super::v5::{self, StorageV5};
use super::value::{EncryptedValue, ValueEntry};

pub fn serialize_storage_v4(storage: &StorageV4) -> Vec<u8> {
    let mut result = Vec::new();

    // Version
    let version = StoreVersion::Version4 as u16;
    result.extend_from_slice(&version.to_be_bytes());

    // Count elements
    let count: u32 = u32::try_from(storage.data.values().map(Vec::len).sum::<usize>())
        .expect("Power user detected with > 4 billion keys");
    result.extend_from_slice(&count.to_be_bytes());

    // Serialize each entry
    for (key, entries) in &storage.data {
        for entry in entries {
            let key_bytes = key.as_bytes();
            let val_bytes = entry.value.as_bytes();

            result.extend_from_slice(
                &(u16::try_from(key_bytes.len()).expect("key is too long")).to_be_bytes(),
            );
            result.extend_from_slice(key_bytes);
            result.extend_from_slice(
                &(u32::try_from(val_bytes.len()).expect("value is too long")).to_be_bytes(),
            );
            result.extend_from_slice(val_bytes);
            // We store only seconds
            #[allow(clippy::cast_possible_truncation)]
            result.extend_from_slice(&(entry.timestamp as u32).to_be_bytes());
        }
    }

    result
}

pub fn deserialize_storage_v4(data: &[u8]) -> Result<StorageV4> {
    if data.len() < 6 {
        bail!("Data too short");
    }

    let count = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
    let mut storage = StorageV4::new();
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
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + val_len > data.len() {
            bail!("Corrupted file: value overflow");
        }
        let value = EncryptedValue::from_ciphertext(data[pos..pos + val_len].to_vec());
        pos += val_len;

        let timestamp = {
            if pos + 4 > data.len() {
                bail!("Corrupted file: timestamp missing");
            }
            let ts = u64::from(u32::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]));
            pos += 4;
            ts
        };

        storage
            .data
            .entry(key)
            .or_default()
            .push(ValueEntry { value, timestamp });
    }

    // IMPORTANT: Sort entries by timestamp after deserialization.
    // The Storage::history() method relies on this sorting to return entries
    // in chronological order without needing to sort on every call.
    // The Storage::get() method also depends on this to reliably return the
    // latest value using .last().
    for entries in storage.data.values_mut() {
        entries.sort_by_key(|e| e.timestamp);
    }

    Ok(storage)
}

pub fn load_storage_v4(cypher: &Cypher, path: &Path) -> Result<StorageV4> {
    if !path.exists() {
        return Ok(StorageV4::new());
    }
    let encrypted = fs::read(path)?;
    let decrypted = cypher.decrypt(&encrypted)?;

    deserialize_storage_v4(&decrypted)
}

pub fn save_storage_v4(cypher: &Cypher, storage: &StorageV4, path: &Path) -> Result<()> {
    let dir = path.parent().expect("Can't get parent dir of a file");
    let mut temp = NamedTempFile::new_in(dir)?;

    let serialized = serialize_storage_v4(storage);
    let encrypted = cypher.encrypt(&serialized)?;

    temp.write_all(&encrypted)?;
    temp.persist(path)?;

    Ok(())
}

// ============================================================================
// V5 Storage Functions
// ============================================================================

/// Load storage from file, automatically converting V4 to V5 if needed
/// This is the main entry point for loading storage - always returns V5
pub fn load_storage_v5(cypher: &Cypher, path: &Path) -> Result<StorageV5> {
    if !path.exists() {
        return Ok(StorageV5::new());
    }

    let encrypted = fs::read(path)?;
    let decrypted = cypher.decrypt(&encrypted)?;

    // Determine version and deserialize accordingly
    let version = StoreVersion::probe_data(&decrypted)?;
    match version {
        StoreVersion::Version4 => {
            // Load V4 and convert to V5
            let v4 = deserialize_storage_v4(&decrypted)?;
            Ok(v5::migrate_v4_to_v5(v4))
        }
        StoreVersion::Version5 => {
            // Load V5 directly
            v5::deserialize_storage_v5_from_slice(&decrypted)
        }
    }
}

/// Save V5 storage to file
pub fn save_storage_v5(cypher: &Cypher, storage: &StorageV5, path: &Path) -> Result<()> {
    let dir = path.parent().expect("Can't get parent dir of a file");
    let mut temp = NamedTempFile::new_in(dir)?;

    let serialized = v5::serialize_storage_v5_to_vec(storage)?;
    let encrypted = cypher.encrypt(&serialized)?;

    temp.write_all(&encrypted)?;
    temp.persist(path)?;

    Ok(())
}
