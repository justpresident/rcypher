use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use tempfile::NamedTempFile;

use crate::crypto::Cypher;
use crate::version::StoreVersion;

use super::store::Storage;
use super::value::{EncryptedValue, ValueEntry};

pub fn serialize_storage(storage: &Storage) -> Vec<u8> {
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

pub fn deserialize_storage(data: &[u8]) -> Result<Storage> {
    let version = StoreVersion::probe_data(data)?;
    match version {
        StoreVersion::Version4 => deserialize_storage_v4(data),
    }
}

pub fn deserialize_storage_v4(data: &[u8]) -> Result<Storage> {
    if data.len() < 6 {
        bail!("Data too short");
    }

    let count = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
    let mut storage = Storage::new();
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

    // Sort entries by timestamp
    for entries in storage.data.values_mut() {
        entries.sort_by_key(|e| e.timestamp);
    }

    Ok(storage)
}

pub fn load_storage(cypher: &Cypher, path: &Path) -> Result<Storage> {
    if !path.exists() {
        return Ok(Storage::new());
    }

    let encrypted = fs::read(path)?;
    let decrypted = cypher.decrypt(&encrypted)?;

    deserialize_storage(&decrypted)
}

pub fn save_storage(cypher: &Cypher, storage: &Storage, path: &Path) -> Result<()> {
    let dir = path.parent().expect("Can't get parent dir of a file");
    let mut temp = NamedTempFile::new_in(dir)?;

    let serialized = serialize_storage(storage);
    let encrypted = cypher.encrypt(&serialized)?;

    temp.write_all(&encrypted)?;
    temp.persist(path)?;

    Ok(())
}
