//! On-disk store-file containers.
//!
//! A *container* is the whole store file: a leading [`FileContainerFormat`] tag,
//! a cleartext header that describes how to unlock, and the encrypted payload.
//! The header is bound to the payload as associated data (the envelope in
//! [`crate::crypto`] folds it into the authentication tag), so the header cannot
//! be altered, downgraded, or spliced onto a different payload without the key.
//!
//! Each format implements [`ContainerCodec`] — its wire layout, how to unlock it,
//! and how to decrypt its payload. [`FileContainer`] is the registry: it probes
//! the leading tag and dispatches to the matching codec. Adding a format is a new
//! submodule + a [`FileContainerFormat`] variant + a [`FileContainer`] arm; the
//! AEAD envelope is shared, only the keyslot scheme is new.

mod v7;
mod v8;

pub use v7::FileContainerV7;
pub use v8::FileContainerV8;

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Result, bail};
use num_enum::TryFromPrimitive;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::auth::FactorSecret;
use crate::crypto::Argon2Params;
use crate::version::CypherVersion;

/// On-disk store-file format — the leading two bytes select one. The single
/// source of truth for "what kind of store file is this".
///
/// Distinct from [`CypherVersion`] (the AEAD envelope used *inside* a container)
/// and `DataContainerVersion` (the serialized key-value payload).
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
        if data.len() < 2 {
            bail!("data too short to determine container format");
        }
        Ok(Self::try_from(u16::from_be_bytes([data[0], data[1]]))?)
    }

    /// The container format's two-byte on-disk tag.
    #[must_use]
    pub const fn tag(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl From<FileContainerFormat> for CypherVersion {
    /// The AEAD envelope a container uses for its ciphertext. Both formats use the
    /// same envelope today, so this is the one mapping.
    fn from(_: FileContainerFormat) -> Self {
        Self::V7WithKdf
    }
}

/// The secrets a container needs to unlock.
///
/// A sum type so the [`FileContainer`] registry can offer one `unlock` surface
/// across formats whose credentials differ; each codec accepts only its own
/// variant and rejects the rest.
pub enum Secrets {
    /// A single password (legacy [`FileContainerV7`]).
    Password(Zeroizing<String>),
    /// A set of named factor secrets (the [`FileContainerV8`] policy vault).
    Factors(HashMap<String, FactorSecret>),
}

/// One on-disk store-file format: its wire layout, how to unlock it, and how to
/// decrypt its payload. Implemented once per [`FileContainerFormat`].
///
/// Writing is *not* part of this trait — only current formats are written, so a
/// codec exposes serialization as its own inherent method (e.g.
/// [`FileContainerV8::write`]) rather than every format pretending it can.
pub trait ContainerCodec<'a>: Sized {
    /// The unlocked key context this format yields — e.g. a password-derived
    /// [`EncryptionKey`](crate::crypto::EncryptionKey) (V7) or an unlocked
    /// [`PolicyVault`](crate::auth::PolicyVault) (V8).
    type Key;

    /// The format tag this codec handles.
    const FORMAT: FileContainerFormat;

    /// Parses a file already known to be of this format.
    fn parse(data: &'a [u8]) -> Result<Self>;

    /// A human-readable description of what unlocking requires, for display
    /// before any secret is supplied (e.g. the access-policy expression).
    #[must_use]
    fn describe(&self) -> String;

    /// Unlocks to a key context using `secrets`. `params` are the Argon2 cost
    /// parameters for password derivation where the format needs them (V7); a
    /// format that stores its own per-factor parameters (V8) ignores them.
    fn unlock(&self, secrets: &Secrets, params: &Argon2Params) -> Result<Self::Key>;

    /// Decrypts the payload with an unlocked `key`, verifying the header binding.
    fn decrypt_payload(&self, key: &Self::Key) -> Result<Zeroizing<Vec<u8>>>;
}

/// A parsed store file, dispatched by format.
///
/// The registry over [`ContainerCodec`] implementations: probe-and-parse with
/// [`FileContainer::parse`], then match on the variant to drive the
/// format-specific unlock.
pub enum FileContainer<'a> {
    /// A legacy version-7 password envelope.
    V7(FileContainerV7<'a>),
    /// A version-8 policy vault.
    V8(FileContainerV8<'a>),
}

impl<'a> FileContainer<'a> {
    /// Probes the leading tag and parses the matching format.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        match FileContainerFormat::probe(data)? {
            FileContainerFormat::V7 => Ok(Self::V7(FileContainerV7::parse(data)?)),
            FileContainerFormat::V8 => Ok(Self::V8(FileContainerV8::parse(data)?)),
        }
    }

    /// The format of the parsed file.
    #[must_use]
    pub const fn format(&self) -> FileContainerFormat {
        match self {
            Self::V7(_) => FileContainerFormat::V7,
            Self::V8(_) => FileContainerFormat::V8,
        }
    }

    /// A human-readable description of what unlocking this file requires.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::V7(c) => c.describe(),
            Self::V8(c) => c.describe(),
        }
    }
}

/// Atomically writes `bytes` to `path` (a temp file in the same directory, then a
/// rename), so a crash mid-write never leaves a truncated store.
///
/// Private to the `container` module; its codecs (e.g. [`FileContainerV8::write`])
/// call it via `super::write_atomic`.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut temp = NamedTempFile::new_in(dir)?;
    temp.write_all(bytes)?;
    temp.persist(path)?;
    Ok(())
}
