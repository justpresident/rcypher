use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::constants::{BLOCK_SIZE, BlockBytes, SaltBytes};

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum StoreVersion {
    Version4 = 4u16,
}

#[derive(Clone, Debug, TryFromPrimitive, Default, PartialEq, Eq, PartialOrd, Ord)]
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
