use std::fs;
use std::io::{Cursor, Read, Seek};
use std::mem::size_of;
use std::path::Path;

use anyhow::{Result, bail};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Mac;
use rand::TryRngCore;
use zeroize::Zeroizing;

use super::LimitedReader;
use super::key::EncryptionKey;
use super::stream_ops::{decrypt_blocks_v7, encrypt_blocks_v7};
use crate::constants::{
    Aes256CbcDec, Aes256CbcEnc, BLOCK_SIZE, BlockBytes, HMAC_SIZE, HmacSha256, READ_BUF_SIZE,
};
use crate::security::is_debugger_attached;
use crate::version::{CypherVersion, Version7Header};

pub struct Cypher {
    pub(super) key: EncryptionKey,
}

/// Calculates the encrypted size for V7 format given plaintext size
const fn encrypted_size_v7(plaintext_len: usize) -> usize {
    let pad_len = BLOCK_SIZE - (plaintext_len % BLOCK_SIZE);
    size_of::<Version7Header>() + plaintext_len + pad_len + HMAC_SIZE
}

/// Calculates padding length for given data size
#[allow(clippy::cast_possible_truncation)]
pub const fn calculate_padding(data_len: usize) -> u8 {
    (BLOCK_SIZE - (data_len % BLOCK_SIZE)) as u8
}

impl Cypher {
    pub const fn new(key: EncryptionKey) -> Self {
        Self { key }
    }

    pub fn version(&self) -> CypherVersion {
        self.key.version.clone()
    }

    pub fn encryption_key_for_file(password: &str, path: &Path) -> Result<EncryptionKey> {
        let version = Self::probe_version(path)?;

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
    fn probe_version(path: &Path) -> Result<CypherVersion> {
        if !path.exists() {
            return Ok(CypherVersion::default());
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
    pub(crate) fn hmac_start(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(self.key.hmac_key()).expect("HMAC can take key of any size")
    }

    pub(crate) fn compute_file_hmac(
        &self,
        file: &mut fs::File,
        from: u64,
        to: u64,
    ) -> Result<HmacSha256> {
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
        if is_debugger_attached() {
            bail!("Debugger detected");
        }

        match self.key.version() {
            CypherVersion::LegacyWithoutKdf => self.encrypt_legacy(data),
            CypherVersion::V7WithKdf => self.encrypt_v7(data),
        }
    }

    fn encrypt_legacy(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        // Pad data to block size
        let pad_len = calculate_padding(data.len());

        // Write header: version (2 bytes) + pad_len (1 byte)
        result.extend_from_slice(&(CypherVersion::LegacyWithoutKdf as u16).to_be_bytes());
        result.push(pad_len);

        // Prepare data with padding (zeros for legacy)
        let mut padded_data = data.to_vec();
        padded_data.extend(std::iter::repeat_n(0, pad_len as usize));
        let len = padded_data.len();

        // Encrypt with zero IV (legacy behavior)
        let iv = BlockBytes::default();
        let cipher = Aes256CbcEnc::new(self.key.as_bytes().into(), &iv.into());
        let encrypted = cipher
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut padded_data, len)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

        result.extend_from_slice(encrypted);
        Ok(result)
    }

    fn encrypt_v7(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Pre-allocate output buffer with exact size needed
        let output_size = encrypted_size_v7(data.len());
        let mut result = Vec::with_capacity(output_size);

        let pad_len = calculate_padding(data.len());

        // Generate random IV
        let mut iv = BlockBytes::default();
        rand::rngs::OsRng.try_fill_bytes(&mut iv)?;

        // Prepare and write header
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

        // Create reader from input data
        let mut reader = Cursor::new(data);
        let mut cipher = Aes256CbcEnc::new(self.key.as_bytes().into(), &header.iv.into());
        let mut mac = self.hmac_start();
        Mac::update(&mut mac, &header_bytes);

        encrypt_blocks_v7(&mut reader, &mut result, &mut cipher, &mut mac, pad_len)?;

        // Write HMAC
        let computed_hmac = mac.finalize();
        result.extend_from_slice(&computed_hmac.into_bytes());

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if is_debugger_attached() {
            bail!("Debugger detected");
        }

        if data.len() < 3 {
            bail!("Data too short");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);

        match CypherVersion::try_from(version) {
            Ok(CypherVersion::LegacyWithoutKdf) => self.decrypt_legacy(data),
            Ok(CypherVersion::V7WithKdf) => self.decrypt_v7(data),
            _ => bail!("Unsupported cypher version {version}"),
        }
    }

    fn decrypt_legacy(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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

        Ok(Zeroizing::from(result))
    }

    fn decrypt_v7(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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

        // Decrypt using stream function
        let encrypted_len = encrypted_data.len();
        let decrypted_len = encrypted_len - header.pad_len as usize;
        let mut result = Vec::with_capacity(decrypted_len);

        // Create reader limited to encrypted data (excluding HMAC)
        let cursor = Cursor::new(encrypted_data);
        let mut limited_reader = LimitedReader::new(cursor, encrypted_len as u64);
        let mut cipher = Aes256CbcDec::new(self.key.as_bytes().into(), &header.iv.into());

        // Use generic stream decryption
        decrypt_blocks_v7(
            &mut limited_reader,
            &mut result,
            &mut cipher,
            header.pad_len,
            encrypted_len as u64,
        )?;

        Ok(Zeroizing::from(result))
    }
}
