//! The version-8 store file: a multi-factor keyslot header followed by the
//! DEK-encrypted payload.
//!
//! Layout: `tag(8) ‖ bincode(VaultHeader) ‖ wrap(DEK, payload, aad = header)`,
//! where `header = tag(8) ‖ bincode(VaultHeader)`. The whole header is the
//! payload's associated data, so the policy and factor table are bound to the
//! ciphertext: they cannot be altered, downgraded, or spliced onto a different
//! payload without the DEK — which only a party that satisfies the policy can
//! recover. The keyslot/unlock logic itself lives in [`crate::auth`].

use anyhow::{Result, bail};

use super::FileContainerFormat;
use crate::auth::{PolicyVault, VaultHeader};
use crate::version::CypherVersion;

/// A parsed version-8 store file: its keyslot header and a borrow of the trailing
/// DEK-encrypted payload. A wire-format helper for the facade — parsing the
/// header for an unlock session, and serializing a fresh file from an unlocked
/// vault. The unlock/decrypt logic lives in [`crate::container::store`].
pub struct FileContainerV8<'a> {
    header: VaultHeader,
    payload: &'a [u8],
}

impl<'a> FileContainerV8<'a> {
    /// Parses a version-8 file into its keyslot header and payload slice.
    pub(super) fn parse(data: &'a [u8]) -> Result<Self> {
        if FileContainerFormat::probe(data)? != FileContainerFormat::V8 {
            bail!("not a version-8 store file");
        }
        let (header, consumed): (VaultHeader, usize) =
            bincode::decode_from_slice(&data[2..], bincode::config::standard())?;
        Ok(Self {
            header,
            payload: &data[2 + consumed..],
        })
    }

    /// The keyslot header (enrolled factors + access policy). The caller drives
    /// the unlock from this — e.g. displaying the policy and prompting for
    /// factors — before any secret is supplied.
    #[must_use]
    pub(super) const fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// The DEK-encrypted payload slice (the envelope after the keyslot header).
    #[must_use]
    pub(super) const fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Serializes a fresh version-8 file from an unlocked `vault` and `payload`,
    /// binding the keyslot header (`tag(8) ‖ bincode(header)`) to the payload as
    /// associated data, so the policy/factor table cannot be altered, downgraded,
    /// or spliced without the DEK.
    pub(super) fn serialize(vault: &PolicyVault, payload: &[u8]) -> Result<Vec<u8>> {
        let header = serialize_header(&vault.header())?;
        let version = CypherVersion::from(FileContainerFormat::V8);
        let ciphertext = vault.encrypt_payload(payload, &header, version)?;
        let mut bytes = header;
        bytes.extend_from_slice(&ciphertext);
        Ok(bytes)
    }
}

/// Serializes a version-8 keyslot header: the container tag followed by the
/// bincoded metadata. This is exactly the byte string the payload binds as its
/// associated data, so the write and read paths must produce it identically.
fn serialize_header(header: &VaultHeader) -> Result<Vec<u8>> {
    let mut out = FileContainerFormat::V8.tag().to_vec();
    let encoded = bincode::encode_to_vec(header, bincode::config::standard())?;
    out.extend_from_slice(&encoded);
    Ok(out)
}
