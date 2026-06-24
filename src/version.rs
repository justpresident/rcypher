use std::{fs, io::Read as _, path::Path};

use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::constants::{BLOCK_SIZE, BlockBytes, SaltBytes};

/// Version tag for the serialized [`DataContainer`](crate::DataContainer) payload
/// (the `storage` feature) — the leading two bytes of the decrypted bytes.
/// Distinct from [`CypherVersion`], which versions the encryption envelope.
#[cfg(feature = "storage")]
#[derive(Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum DataContainerVersion {
    Version4 = 4u16,
}

#[cfg(feature = "storage")]
impl DataContainerVersion {
    /// Probes the leading two bytes to determine the data-container version.
    pub fn probe_data(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            bail!("data too short to determine version");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self::try_from(version)?)
    }

    /// The version's two-byte on-disk tag (the leading bytes of the payload).
    #[must_use]
    pub const fn tag(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

/// The AEAD envelope version used *inside* a container.
///
/// The on-disk store-file format (the leading two bytes) lives separately in
/// [`FileContainerFormat`](crate::container::FileContainerFormat).
#[derive(Clone, Copy, Debug, TryFromPrimitive, Default, PartialEq, Eq, PartialOrd, Ord)]
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
            bail!("data too short to determine version");
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self::try_from(version)?)
    }

    /// The version's two-byte on-disk tag (written into the envelope header).
    #[must_use]
    pub const fn tag(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
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
