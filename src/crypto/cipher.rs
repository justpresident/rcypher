use crate::constants::HmacBytes;
use std::fs;
use std::io::{self, Cursor, Read, Seek};
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

    // Initializes HMAC from a separate key derived from master key
    fn hmac_start(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(self.key.hmac_key()).expect("HMAC can take key of any size")
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

    /// Generic helper for V7 encryption that works with any Reader and Writer
    fn encrypt_helper_v7<R: Read, W: io::Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        pad_len: u8,
    ) -> Result<()> {
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
        writer.write_all(&header_bytes)?;

        // Create cipher and MAC
        let mut cipher = Aes256CbcEnc::new(self.key.as_bytes().into(), &header.iv.into());
        let mut mac = self.hmac_start();
        Mac::update(&mut mac, &header_bytes);

        // Encrypt blocks
        encrypt_blocks_v7(reader, writer, &mut cipher, &mut mac, pad_len)?;

        // Write HMAC
        let computed_hmac = mac.finalize();
        writer.write_all(&computed_hmac.into_bytes())?;

        Ok(())
    }

    fn encrypt_v7(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Pre-allocate output buffer with exact size needed
        let output_size = encrypted_size_v7(data.len());
        let mut result = Vec::with_capacity(output_size);

        let pad_len = calculate_padding(data.len());
        let mut reader = Cursor::new(data);

        self.encrypt_helper_v7(&mut reader, &mut result, pad_len)?;

        Ok(result)
    }
    pub fn encrypt_file<T: io::Write>(&self, path: &Path, out: &mut T) -> Result<()> {
        if is_debugger_attached() {
            bail!("Debugger detected");
        }

        match self.version() {
            CypherVersion::LegacyWithoutKdf => {
                bail!("Encryption with legacy version is not supported")
            }
            CypherVersion::V7WithKdf => self.encrypt_file_v7(path, out),
        }
    }

    fn encrypt_file_v7<T: io::Write>(&self, path: &Path, out: &mut T) -> Result<()> {
        let mut file = fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        let pad_len = calculate_padding(usize::try_from(file_len)?);

        self.encrypt_helper_v7(&mut file, out, pad_len)?;

        Ok(())
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
        if pad_len > BLOCK_SIZE {
            bail!("Invalid padding length: {pad_len}");
        }
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

    pub fn decrypt_file<T: io::Write>(&self, input_path: &Path, out: &mut T) -> Result<()> {
        if is_debugger_attached() {
            bail!("Debugger detected");
        }

        match self.version() {
            CypherVersion::LegacyWithoutKdf => {
                bail!("Legacy encryption is not supported for files")
            }
            CypherVersion::V7WithKdf => self.decrypt_file_v7(input_path, out)?,
        }
        Ok(())
    }

    fn decrypt_file_v7<T: io::Write>(&self, input_path: &Path, out: &mut T) -> Result<()> {
        let mut file = fs::File::open(input_path)?;
        let file_size = usize::try_from(file.metadata()?.len()).map_err(|_| {
            anyhow::anyhow!("Can't process files larger than 4Gb on a 32-bit platform")
        })?;
        if file_size < size_of::<Version7Header>() + BLOCK_SIZE + HMAC_SIZE {
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

        if computed_hmac.verify_slice(&hmac).is_err() {
            bail!("Decryption failed");
        }

        // Read header
        file.seek(std::io::SeekFrom::Start(0))?;
        let header: Version7Header =
            bincode::decode_from_std_read(&mut file, bincode::config::standard())?;
        header.validate()?;

        // Proceed with decryption
        let data_end = u64::try_from(file_size - HMAC_SIZE)?;
        let mut cipher = Aes256CbcDec::new(self.key.as_bytes().into(), &header.iv.into());

        // Create a limited reader that only reads encrypted data (excluding HMAC)
        let current_pos = file.stream_position()?;
        let remaining_bytes = data_end - current_pos;
        let mut limited_reader = LimitedReader::new(file, remaining_bytes);

        // Use generic decryption function
        decrypt_blocks_v7(
            &mut limited_reader,
            out,
            &mut cipher,
            header.pad_len,
            remaining_bytes,
        )?;

        Ok(())
    }
}
