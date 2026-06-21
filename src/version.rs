use std::{fs, io::Read as _, path::Path};

use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::constants::{BLOCK_SIZE, BlockBytes, SaltBytes};

/// Version tag for the bundled key-value storage payload (the `storage` feature).
/// Distinct from [`CypherVersion`], which versions the encryption envelope.
#[cfg(feature = "storage")]
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum StoreVersion {
    Version4 = 4u16,
}

#[cfg(feature = "storage")]
impl StoreVersion {
    /// Probes data to determine its storage-format version
    pub fn probe_data(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            bail!("Data too short to determine version");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self::try_from(version)?)
    }
}

/// On-disk container format — the top-level store-file version, read from the
/// leading two bytes.
///
/// The single source of truth for "what kind of store file is this". Distinct
/// from [`CypherVersion`] (the AEAD envelope used *inside* a container) and
/// [`StoreVersion`] (the serialized key-value payload).
#[derive(Clone, Copy, Debug, TryFromPrimitive, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum ContainerFormat {
    /// Legacy: the whole file is one AEAD envelope keyed directly by the password.
    V7 = 7u16,
    /// Current default: a multi-factor keyslot header followed by the
    /// DEK-encrypted payload.
    #[default]
    V8 = 8u16,
}

impl ContainerFormat {
    /// Probes the leading two bytes to determine the container format.
    pub fn probe(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            bail!("data too short to determine container format");
        }
        Ok(Self::try_from(u16::from_be_bytes([data[0], data[1]]))?)
    }

    /// Probes an existing file's leading two bytes.
    pub fn probe_file(path: &Path) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let mut bytes = [0u8; 2];
        file.read_exact(&mut bytes)?;
        Self::probe(&bytes)
    }

    /// The container format's two-byte on-disk tag.
    #[must_use]
    pub const fn tag(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl From<ContainerFormat> for CypherVersion {
    /// The AEAD envelope a container uses for its ciphertext. Both formats use
    /// the same envelope today, so this is the one mapping.
    fn from(_: ContainerFormat) -> Self {
        Self::V7WithKdf
    }
}

#[derive(Clone, Debug, TryFromPrimitive, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum CypherVersion {
    /// Modern version with Argon2id KDF and HMAC
    #[default]
    V7WithKdf = 7u16,
}

impl CypherVersion {
    /// Probes a file to determine its encryption version
    pub fn probe_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let mut file = fs::File::open(path)?;
        let mut version_bytes = [0u8; 2];
        file.read_exact(&mut version_bytes)?;

        Self::probe_data(&version_bytes)
    }

    /// Probes data to determine its encryption version
    pub fn probe_data(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            bail!("Data too short to determine version");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self::try_from(version)?)
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Default, Decode, Encode)]
pub struct Version7Header {
    pub version: [u8; 2],
    pub pad_len: u8,
    pub _reserved: u8,
    pub salt: SaltBytes,
    pub iv: BlockBytes,
}

impl Version7Header {
    pub fn validate(&self) -> Result<()> {
        if usize::from(self.pad_len) > BLOCK_SIZE {
            bail!("Incorrect pad length");
        }
        Ok(())
    }
}
