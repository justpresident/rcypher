#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::unwrap_used,
    clippy::panic,
    clippy::dbg_macro,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::redundant_pub_crate
)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::multiple_crate_versions,
    clippy::missing_panics_doc
)]

use aes::{Aes256, Block};
use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use bincode::{Decode, Encode};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use chrono::{Local, TimeZone};
use hmac::{Hmac, Mac};
use num_enum::TryFromPrimitive;
use rand::TryRngCore;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const READ_BUF_SIZE: usize = 4096;
const BLOCK_SIZE: usize = 16;
const SALT_SIZE: usize = 32;
const HMAC_SIZE: usize = 32;
const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

type KeyBytes = [u8; KEY_LEN];
type SaltBytes = [u8; SALT_SIZE];
type BlockBytes = [u8; BLOCK_SIZE];
type HmacBytes = [u8; HMAC_SIZE];

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
enum StoreVersion {
    Version4 = 4u16,
}
#[derive(Clone, Debug, TryFromPrimitive, Default)]
#[repr(u16)]
pub enum CypherVersion {
    /// Legacy version with simple password padding (no KDF)
    LegacyWithoutKdf = 2u16,
    /// Modern version with Argon2id KDF and HMAC
    #[default]
    V7WithKdf = 7u16,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Default, Decode, Encode)]
struct Version7Header {
    version: [u8; 2],
    pad_len: u8,
    _reserved: u8,
    salt: SaltBytes,
    iv: BlockBytes,
}

impl Version7Header {
    fn validate(&self) -> Result<()> {
        if usize::from(self.pad_len) > BLOCK_SIZE {
            bail!("Incorrect pad length");
        }
        Ok(())
    }
}

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
        Self {
            data: HashMap::new(),
        }
    }

    pub fn put(&mut self, key: String, value: String) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should go forward")
            .as_secs();

        self.put_ts(key, value, timestamp);
    }

    pub fn put_ts(&mut self, key: String, value: String, timestamp: u64) {
        self.data
            .entry(key)
            .or_default()
            .push(ValueEntry { value, timestamp });
    }

    pub fn get(&self, pattern: &str) -> Result<Vec<(String, String)>> {
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

#[derive(Clone, Default)]
pub struct EncryptionKey {
    version: CypherVersion,
    key: Zeroizing<KeyBytes>,
    salt: SaltBytes,
    hmac_key: Zeroizing<KeyBytes>,
}

impl EncryptionKey {
    /// Creates a key from password without KDF (for backward compatibility)
    pub fn from_password(version: CypherVersion, password: &str) -> Result<Self> {
        match version {
            CypherVersion::LegacyWithoutKdf => {
                let mut key = [b'~'; KEY_LEN];
                let bytes = password.as_bytes();
                let len = bytes.len().min(KEY_LEN);

                key[..len].copy_from_slice(&bytes[..len]);

                Ok(Self {
                    version,
                    key: Zeroizing::new(key),
                    ..Default::default()
                })
            }
            CypherVersion::V7WithKdf => {
                let mut salt = SaltBytes::default();
                rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
                Self::from_password_with_salt(version, password, &salt)
            }
        }
    }

    /// Derives a key from password and salt using Argon2id
    fn from_password_with_salt(
        version: CypherVersion,
        password: &str,
        salt: &SaltBytes,
    ) -> Result<Self> {
        // Argon2id parameters: memory=64MB, iterations=3, parallelism=1
        let params = Params::new(65536, 3, 1, Some(2 * size_of::<KeyBytes>()))
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {e}"))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut all_key_bytes = Zeroizing::new([0u8; 2 * size_of::<KeyBytes>()]);
        argon2
            .hash_password_into(password.as_bytes(), salt, all_key_bytes.as_mut())
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {e}"))?;

        let mut key = KeyBytes::default();
        let mut hmac_key = KeyBytes::default();
        key.copy_from_slice(&all_key_bytes[0..KEY_LEN]);
        hmac_key.copy_from_slice(&all_key_bytes[KEY_LEN..]);

        Ok(Self {
            version,
            key: Zeroizing::new(key),
            hmac_key: Zeroizing::new(hmac_key),
            salt: *salt,
        })
    }

    pub fn as_bytes(&self) -> &KeyBytes {
        &self.key
    }
    pub fn hmac_key(&self) -> &KeyBytes {
        &self.hmac_key
    }
    pub const fn salt(&self) -> &SaltBytes {
        &self.salt
    }
    pub const fn version(&self) -> &CypherVersion {
        &self.version
    }
}

pub struct Cypher {
    key: EncryptionKey,
}

impl Cypher {
    pub const fn new(key: EncryptionKey) -> Self {
        Self { key }
    }

    pub fn encryption_key_for_file(password: &str, path: &Path) -> Result<EncryptionKey> {
        let version = Self::probe_version(path, CypherVersion::V7WithKdf)?;

        let key = match version {
            CypherVersion::LegacyWithoutKdf => EncryptionKey::from_password(version, password)?,
            CypherVersion::V7WithKdf => {
                if !fs::exists(path)? {
                    return EncryptionKey::from_password(version, password);
                }
                let mut file = fs::File::open(path)?;
                if file.metadata()?.len() < u64::try_from(size_of::<Version7Header>())? {
                    bail!("file size is too small");
                }
                let header: Version7Header =
                    bincode::decode_from_std_read(&mut file, bincode::config::standard())?;
                header.validate()?;
                EncryptionKey::from_password_with_salt(version, password, &header.salt)?
            }
        };

        Ok(key)
    }

    /// Probes a file to determine its encryption version
    fn probe_version(path: &Path, default: CypherVersion) -> Result<CypherVersion> {
        if !path.exists() {
            return Ok(default);
        }
        let mut file = fs::File::open(path)?;
        let mut version_bytes = [0u8; 2];
        file.read_exact(&mut version_bytes)?;

        Self::probe_data_version(&version_bytes)
    }

    /// Probes data to determine its encryption version
    fn probe_data_version(data: &[u8]) -> Result<CypherVersion> {
        if data.len() < 2 {
            bail!("Data too short to determine version");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        Ok(CypherVersion::try_from(version)?)
    }

    // TODO: initialize HMAC from a separate key derived from master key
    fn hmac_start(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(self.key.hmac_key()).expect("HMAC can take key of any size")
    }

    fn compute_hmac(&self, header: &[u8], encrypted_data: &[u8]) -> HmacBytes {
        let mut mac = self.hmac_start();
        Mac::update(&mut mac, header);
        Mac::update(&mut mac, encrypted_data);
        let result = mac.finalize();
        result.into_bytes().into()
    }

    fn compute_file_hmac(&self, file: &mut fs::File, from: u64, to: u64) -> Result<HmacSha256> {
        let mut mac = self.hmac_start();
        // Go to the starting position
        file.seek(std::io::SeekFrom::Start(from))?;

        let mut remaining = usize::try_from(to - from)?;
        let mut buf = [0u8; READ_BUF_SIZE];

        while remaining > 0 {
            let read_len = buf.len().min(remaining);
            let n = file.read(&mut buf[..read_len])?;

            if n == 0 {
                return Err(anyhow::anyhow!("unexpected EOF while computing HMAC"));
            }

            mac.update(&buf[..n]);
            remaining -= n;
        }

        Ok(mac)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.key.version() {
            CypherVersion::LegacyWithoutKdf => {
                bail!("Encryption with legacy version is not supported")
            }
            CypherVersion::V7WithKdf => self.encrypt_v7(data),
        }
    }

    fn encrypt_v7(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        // Pad data first
        #[allow(clippy::cast_possible_truncation)]
        let pad_len = (BLOCK_SIZE - (data.len() % BLOCK_SIZE)) as u8;

        // Generate random IV and salt
        let mut iv = BlockBytes::default();
        rand::rngs::OsRng.try_fill_bytes(&mut iv)?;

        let header = Version7Header {
            version: (CypherVersion::V7WithKdf as u16).to_be_bytes(),
            salt: *self.key.salt(),
            pad_len,
            _reserved: 0,
            iv,
        };
        let mut header_bytes = [0u8; size_of::<Version7Header>()];
        bincode::encode_into_slice(&header, &mut header_bytes, bincode::config::standard())?;
        result.extend_from_slice(&header_bytes);

        // Pad data to block size
        let mut padded = data.to_vec();
        padded.extend(vec![pad_len; pad_len as usize]);
        let len = padded.len();

        // Encrypt data
        let cipher = Aes256CbcEnc::new(self.key.as_bytes().into(), &header.iv.into());
        let encrypted = cipher
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut padded, len)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

        result.extend_from_slice(encrypted);

        let hmac = self.compute_hmac(&header_bytes, encrypted);

        result.extend_from_slice(&hmac);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            bail!("Data too short");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);

        match CypherVersion::try_from(version) {
            Ok(CypherVersion::LegacyWithoutKdf) => {
                let pad_len = data[2] as usize;
                assert!(pad_len <= BLOCK_SIZE);
                let mut encrypted = data[3..].to_vec();

                let iv = BlockBytes::default();
                let cipher = Aes256CbcDec::new(self.key.as_bytes().into(), &iv.into());
                let decrypted = cipher
                    .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut encrypted)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

                let mut result = decrypted.to_vec();
                if pad_len > 0 && pad_len <= result.len() {
                    result.truncate(result.len() - pad_len);
                }

                Ok(result)
            }
            Ok(CypherVersion::V7WithKdf) => {
                if data.len() < size_of::<Version7Header>() + BLOCK_SIZE + HMAC_SIZE {
                    bail!("File is too small");
                }

                // First thing we do is to verify HMAC to make sure the file is correct and hasn't
                // been tampered. If it doesn't match we immediately exit to minimize exposure of
                // the code to the potential attacker.
                let header_bytes = &data[0..size_of::<Version7Header>()];
                let pos = size_of::<Version7Header>();
                let encrypted_data = &data[pos..data.len() - HMAC_SIZE];
                let hmac = &data[data.len() - HMAC_SIZE..];

                let mut mac = self.hmac_start();
                Mac::update(&mut mac, header_bytes);
                Mac::update(&mut mac, encrypted_data);
                if mac.verify_slice(hmac).is_err() {
                    bail!("Decryption failed");
                }

                // Read header
                let (header, _): (Version7Header, _) =
                    bincode::decode_from_slice(header_bytes, bincode::config::standard())?;
                header.validate()?;

                // Decrypt
                let mut encrypted = encrypted_data.to_vec();
                let cipher = Aes256CbcDec::new(self.key.as_bytes().into(), &header.iv.into());
                let encrypted_len = encrypted.len();
                cipher
                    .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut encrypted)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {e}, size={encrypted_len}"))?;

                if header.pad_len > 0 && header.pad_len as usize <= encrypted_len {
                    encrypted.truncate(encrypted_len - header.pad_len as usize);
                }

                Ok(encrypted)
            }
            _ => bail!("Unsupported cypher version {version}"),
        }
    }

    pub fn encrypt_file<T: io::Write>(&self, path: &Path, out: &mut T) -> Result<()> {
        match self.key.version() {
            CypherVersion::LegacyWithoutKdf => {
                bail!("Encryption with legacy version is not supported")
            }
            CypherVersion::V7WithKdf => self.encrypt_file_v7(path, out),
        }
    }

    fn encrypt_file_v7<T: io::Write>(&self, path: &Path, out: &mut T) -> Result<()> {
        let mut file = fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        #[allow(clippy::cast_possible_truncation)]
        let pad_len = (BLOCK_SIZE - (file_len as usize % BLOCK_SIZE)) as u8;

        // Generate random IV
        let mut iv = BlockBytes::default();
        rand::rngs::OsRng.try_fill_bytes(&mut iv)?;

        // Prepare header without HMAC
        let header = Version7Header {
            version: (CypherVersion::V7WithKdf as u16).to_be_bytes(),
            salt: self.key.salt,
            pad_len,
            _reserved: 0,
            iv,
        };

        let mut mac = self.hmac_start();

        let mut header_bytes = [0u8; size_of::<Version7Header>()];
        bincode::encode_into_slice(&header, &mut header_bytes, bincode::config::standard())?;
        Mac::update(&mut mac, &header_bytes);
        out.write_all(&header_bytes[..])?;

        let mut cipher = Aes256CbcEnc::new(self.key.as_bytes().into(), &header.iv.into());

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
                Mac::update(&mut mac, &block);
                out.write_all(&block)?;
            }
            file_data = file_data[pos..].to_vec();
            pos = 0;
        }

        if !file_data.is_empty() {
            for _ in 0..header.pad_len {
                file_data.push(header.pad_len);
            }

            // encrypt final padded block
            let mut block = Block::clone_from_slice(&file_data[pos..]);
            cipher.encrypt_block_mut(&mut block);
            Mac::update(&mut mac, &block);
            out.write_all(&block)?;
        }
        let computed_hmac = mac.finalize();
        out.write_all(&computed_hmac.into_bytes())?;

        Ok(())
    }

    pub fn decrypt_file<T: io::Write>(&self, input_path: &Path, out: &mut T) -> Result<()> {
        let mut file = fs::File::open(input_path)?;
        let file_size = usize::try_from(file.metadata()?.len())
            .expect("Can't process files larger than 4Gb on a 32-bit platform");

        if file_size < 3 {
            bail!("File is too small");
        }
        let mut version_bytes = [0; 2];
        file.read_exact(&mut version_bytes)?;
        file.seek(std::io::SeekFrom::Start(0))?;

        let version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);

        match CypherVersion::try_from(version) {
            Ok(CypherVersion::V7WithKdf) => {
                if file_size < size_of::<Version7Header>() + HMAC_SIZE {
                    bail!("File is too small");
                }

                // First thing we do is to verify HMAC to make sure the file is correct and hasn't
                // been tampered. If it doesn't match we immediately exit to minimize exposure of
                // the code to the potential attacker.
                file.seek(std::io::SeekFrom::End(-i64::try_from(HMAC_SIZE)?))?;
                let mut hmac = HmacBytes::default();
                file.read_exact(&mut hmac)?;

                let computed_hmac =
                    self.compute_file_hmac(&mut file, 0, u64::try_from(file_size - HMAC_SIZE)?)?;

                computed_hmac.verify_slice(&hmac)?;

                // Read header
                file.seek(std::io::SeekFrom::Start(0))?;
                let header: Version7Header =
                    bincode::decode_from_std_read(&mut file, bincode::config::standard())?;
                header.validate()?;

                // Proceed with decryption
                let data_end = u64::try_from(file_size - HMAC_SIZE)?;
                let mut cipher = Aes256CbcDec::new(self.key.as_bytes().into(), &header.iv.into());
                let mut buffer = [0u8; READ_BUF_SIZE];

                // All read data goes into this vec
                let mut file_data = Vec::new();
                let mut pos: usize = 0;
                loop {
                    // Read only until data_end, not full file
                    while file_data.len() < READ_BUF_SIZE {
                        let current = file.stream_position()?;
                        if current >= data_end {
                            break;
                        }

                        let remaining = usize::try_from(data_end - current)?;
                        let to_read = remaining.min(READ_BUF_SIZE);

                        let n = file.read(&mut buffer[..to_read])?;
                        if n == 0 {
                            break;
                        }

                        file_data.extend_from_slice(&buffer[..n]);
                    }

                    if file_data.is_empty() {
                        break;
                    } else if file_data.len() < BLOCK_SIZE {
                        bail!("Incorrect file size");
                    }

                    let file_end = file.stream_position()? >= data_end;

                    while file_data.len() >= pos + BLOCK_SIZE {
                        let mut block = Block::clone_from_slice(&file_data[pos..pos + BLOCK_SIZE]);
                        pos += BLOCK_SIZE;

                        cipher.decrypt_block_mut(&mut block);

                        if file_end && file_data.len() == pos {
                            let last_block_len = BLOCK_SIZE - header.pad_len as usize;
                            out.write_all(&block[..last_block_len])?;
                        } else {
                            out.write_all(&block)?;
                        }
                    }

                    file_data = file_data[pos..].to_vec();
                    pos = 0;
                }
            }
            _ => bail!("Unsupported file encryption format: {version}"),
        }
        Ok(())
    }
}

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
    if data.len() < 6 {
        bail!("Data too short");
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != StoreVersion::Version4 as u16 {
        bail!("Unsupported storage version: {version}");
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

pub fn load_storage(password: &str, path: &Path) -> Result<Storage> {
    if !path.exists() {
        return Ok(Storage::new());
    }

    let key = Cypher::encryption_key_for_file(password, path)?;

    let cypher = Cypher::new(key);

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

pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }
    let dt = Local
        .timestamp_opt(ts.try_into().expect("invalid timestamp"), 0)
        .unwrap();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}
