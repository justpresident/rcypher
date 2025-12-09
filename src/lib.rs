use aes::{Aes256, Block};
use anyhow::{Result, bail};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use chrono::{Local, TimeZone};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub const STORE_VERSION: u16 = 4;
pub const CYPHER_VERSION: u16 = 2;
pub const ENCRYPTED_FILE_VER: u16 = 5;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueEntry {
    pub value: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Storage {
    pub data: HashMap<String, Vec<ValueEntry>>,
}

impl Storage {
    pub fn new() -> Self {
        Storage {
            data: HashMap::new(),
        }
    }

    pub fn put(&mut self, key: String, value: String) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.data
            .entry(key)
            .or_default()
            .push(ValueEntry { value, timestamp });
    }

    pub fn get(&self, pattern: &str) -> Result<Vec<(String, String)>> {
        let re = Regex::new(&format!("^{}$", pattern))?;
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

pub struct Cypher {
    key: [u8; 32],
}

impl Cypher {
    pub fn new(password: &str) -> Self {
        let mut key = [b'~'; 32];
        let bytes = password.as_bytes();
        let len = bytes.len().min(32);
        key[..len].copy_from_slice(&bytes[..len]);
        Cypher { key }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();

        // Add version
        result.extend_from_slice(&CYPHER_VERSION.to_be_bytes());

        // Pad data to block size
        let pad_len = 16 - (data.len() % 16);
        let mut padded = data.to_vec();
        padded.extend(vec![b'~'; pad_len]);

        // Add padding length
        result.push(pad_len as u8);

        // Encrypt
        let iv = [0u8; 16];
        let cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());
        let len = padded.len();
        let encrypted = cipher
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut padded, len)
            .expect("encryption failed");
        result.extend_from_slice(encrypted);

        result
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            bail!("Data too short");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != CYPHER_VERSION {
            bail!("Unsupported cypher version: {}", version);
        }

        let pad_len = data[2] as usize;
        let mut encrypted = data[3..].to_vec();

        let iv = [0u8; 16];
        let cipher = Aes256CbcDec::new(&self.key.into(), &iv.into());
        let decrypted = cipher
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut encrypted)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

        let mut result = decrypted.to_vec();
        if pad_len > 0 && pad_len <= result.len() {
            result.truncate(result.len() - pad_len);
        }

        Ok(result)
    }

    pub fn encrypt_file(&self, path: &PathBuf) -> Result<Vec<u8>> {
        let mut file = fs::File::open(path)?;
        let mut out = Vec::new();

        // Write file version
        out.extend_from_slice(&ENCRYPTED_FILE_VER.to_be_bytes());

        // TODO: Generate random IV
        let iv = [0u8; 16];
        // rand::rngs::OsRng.fill_bytes(&mut iv);
        // out.extend_from_slice(&iv);

        let mut cipher = Aes256CbcEnc::new(&self.key.into(), &iv.into());

        const READ_BUF_SIZE: usize = 1024;
        const BLOCK_SIZE: usize = 16;
        let mut buffer = [0u8; READ_BUF_SIZE];

        // All read data goes into this vec
        let mut file_data = Vec::new();
        let mut pos: usize = 0;
        loop {
            while file_data.len() < READ_BUF_SIZE {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                file_data.extend_from_slice(&buffer[0..n]);
            }
            if file_data.len() < BLOCK_SIZE {
                break;
            }

            while file_data.len() >= pos + BLOCK_SIZE {
                let mut block = Block::clone_from_slice(&file_data[pos..pos + BLOCK_SIZE]);
                pos += BLOCK_SIZE;

                cipher.encrypt_block_mut(&mut block);
                out.extend_from_slice(&block);
            }
            file_data = file_data[pos..].to_vec();
            pos = 0;
        }

        let mut pad_len: u8 = 0;
        if !file_data.is_empty() {
            pad_len = (BLOCK_SIZE - (file_data.len() % BLOCK_SIZE)) as u8;
            while file_data.len() % BLOCK_SIZE != 0 {
                file_data.push(b'~');
            }

            // encrypt final padded block
            let mut block = Block::clone_from_slice(&file_data[pos..]);
            cipher.encrypt_block_mut(&mut block);
            out.extend_from_slice(&block);
        }
        out.push(pad_len);
        Ok(out)
    }

    pub fn decrypt_file(&self, input_path: &PathBuf) -> Result<Vec<u8>> {
        let data = fs::read(input_path)?;

        if data.len() < 3 {
            bail!("File too short");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != ENCRYPTED_FILE_VER {
            bail!("Unsupported file encryption format: {}", version);
        }

        let pad_len = *data.last().unwrap() as usize;
        let mut encrypted = data[2..data.len() - 1].to_vec();

        let iv = [0u8; 16];
        let cipher = Aes256CbcDec::new(&self.key.into(), &iv.into());

        let encrypted_len = encrypted.len();
        let decrypted = cipher
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut encrypted)
            .map_err(|e| anyhow::anyhow!("File decryption failed: {e}, size={}", encrypted_len))?;

        let mut result = decrypted.to_vec();
        if pad_len > 0 && pad_len <= result.len() {
            result.truncate(result.len() - pad_len);
        }

        Ok(result)
    }
}

pub fn serialize_storage(storage: &Storage) -> Vec<u8> {
    let mut result = Vec::new();

    // Version
    result.extend_from_slice(&STORE_VERSION.to_be_bytes());

    // Count elements
    let count: u32 = storage.data.values().map(|v| v.len()).sum::<usize>() as u32;
    result.extend_from_slice(&count.to_be_bytes());

    // Serialize each entry
    for (key, entries) in &storage.data {
        for entry in entries {
            let key_bytes = key.as_bytes();
            let val_bytes = entry.value.as_bytes();

            result.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
            result.extend_from_slice(key_bytes);
            result.extend_from_slice(&(val_bytes.len() as u32).to_be_bytes());
            result.extend_from_slice(val_bytes);
            result.extend_from_slice(&(entry.timestamp as u32).to_be_bytes());
        }
    }

    result
}

pub fn deserialize_storage(data: &[u8]) -> Result<Storage> {
    if data.len() < 6 {
        bail!("Data too short");
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != STORE_VERSION && version != 3 {
        bail!("Unsupported storage version: {}", version);
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
        let value = String::from_utf8(data[pos..pos + val_len].to_vec())?;
        pos += val_len;

        let timestamp = if version == 4 {
            if pos + 4 > data.len() {
                bail!("Corrupted file: timestamp missing");
            }
            let ts =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as u64;
            pos += 4;
            ts
        } else {
            0
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

pub fn load_storage(cypher: &Cypher, path: &PathBuf) -> Result<Storage> {
    if !path.exists() {
        return Ok(Storage::new());
    }

    let encrypted = fs::read(path)?;
    let decrypted = cypher.decrypt(&encrypted)?;
    deserialize_storage(&decrypted)
}

pub fn save_storage(cypher: &Cypher, storage: &Storage, path: &PathBuf) -> Result<()> {
    let serialized = serialize_storage(storage);
    let encrypted = cypher.encrypt(&serialized);
    fs::write(path, encrypted)?;
    Ok(())
}

pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }
    let dt = Local.timestamp_opt(ts as i64, 0).unwrap();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}
