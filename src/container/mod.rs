//! On-disk store-file containers.
//!
//! The public surface is the version-agnostic facade in [`store`]
//! ([`LockedContainer`]/[`UnlockedContainer`]). Internally a store file is a
//! leading [`FileContainerFormat`] tag followed by a body: for the current format
//! that is a keyslot header ([`FileContainerV8`]) plus the DEK-encrypted,
//! header-authenticated payload; for the legacy format the whole file is one
//! password envelope (the facade reads it directly). Adding a format is a new
//! [`FileContainerFormat`] variant the facade dispatches on — no client changes.

mod store;
mod v8;

pub use store::{LockedContainer, UnlockedContainer, backup_path};
pub use v8::FileContainerV8;

use anyhow::Result;
use num_enum::TryFromPrimitive;

use crate::version::{CypherVersion, probe_u16_tag};

/// On-disk store-file format — the leading two bytes select one. The single
/// source of truth for "what kind of store file is this".
///
/// Distinct from [`CypherVersion`] (the AEAD envelope used *inside* a container)
/// and `SecretStoreVersion` (the serialized key-value payload).
#[derive(Clone, Copy, Debug, TryFromPrimitive, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum FileContainerFormat {
    /// Legacy: the whole file is one AEAD envelope keyed directly by the password.
    V7 = 7u16,
    /// Current default: a multi-factor keyslot header followed by the
    /// DEK-encrypted payload.
    #[default]
    V8 = 8u16,
}

impl FileContainerFormat {
    /// Probes the leading two bytes to determine the container format.
    pub fn probe(data: &[u8]) -> Result<Self> {
        probe_u16_tag(data)
    }

    /// The container format's two-byte on-disk tag.
    #[must_use]
    pub const fn tag(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl From<FileContainerFormat> for CypherVersion {
    /// The AEAD envelope a container uses for its ciphertext. Both formats use the
    /// same envelope today; spelling it as an explicit match means a future format
    /// that needs a different envelope won't compile until this mapping is updated.
    fn from(format: FileContainerFormat) -> Self {
        match format {
            FileContainerFormat::V7 | FileContainerFormat::V8 => Self::V7WithKdf,
        }
    }
}
