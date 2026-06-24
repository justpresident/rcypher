//! The version-8 store file: a multi-factor keyslot header followed by the
//! DEK-encrypted payload.
//!
//! Layout: `tag(8) ‖ bincode(VaultHeader) ‖ wrap(DEK, payload, aad = header)`,
//! where `header = tag(8) ‖ bincode(VaultHeader)`. The whole header is the
//! payload's associated data, so the policy and factor table are bound to the
//! ciphertext: they cannot be altered, downgraded, or spliced onto a different
//! payload without the DEK — which only a party that satisfies the policy can
//! recover. The keyslot/unlock logic itself lives in [`crate::auth`].

use std::path::Path;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use super::{ContainerCodec, FileContainerFormat, Secrets};
use crate::auth::{PolicyVault, VaultHeader};
use crate::crypto::Argon2Params;
use crate::version::CypherVersion;

/// A parsed version-8 store file: its keyslot header and a borrow of the trailing
/// DEK-encrypted payload.
pub struct FileContainerV8<'a> {
    header: VaultHeader,
    payload: &'a [u8],
}

impl FileContainerV8<'_> {
    /// The keyslot header (enrolled factors + access policy). The caller drives
    /// the unlock from this — e.g. displaying the policy and prompting for
    /// factors — before any secret is supplied.
    #[must_use]
    pub const fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// The exact header bytes the payload binds as associated data.
    fn header_bytes(&self) -> Result<Vec<u8>> {
        serialize_header(&self.header)
    }

    /// Serializes a fresh version-8 file from an unlocked `vault` and `payload`,
    /// binding the keyslot header to the payload as associated data. The public
    /// write surface is [`FileContainerV8::write`]; this is its in-memory core.
    fn serialize(vault: &PolicyVault, payload: &[u8]) -> Result<Vec<u8>> {
        let header = serialize_header(&vault.header())?;
        let version = CypherVersion::from(FileContainerFormat::V8);
        let ciphertext = vault.encrypt_payload(payload, &header, version)?;
        let mut bytes = header;
        bytes.extend_from_slice(&ciphertext);
        Ok(bytes)
    }

    /// Serializes and atomically writes a version-8 file to `path`.
    pub fn write(path: &Path, vault: &PolicyVault, payload: &[u8]) -> Result<()> {
        super::write_atomic(path, &Self::serialize(vault, payload)?)
    }
}

impl<'a> ContainerCodec<'a> for FileContainerV8<'a> {
    type Key = PolicyVault;
    const FORMAT: FileContainerFormat = FileContainerFormat::V8;

    fn parse(data: &'a [u8]) -> Result<Self> {
        if FileContainerFormat::probe(data)? != Self::FORMAT {
            bail!("not a version-8 store file");
        }
        let (header, consumed): (VaultHeader, usize) =
            bincode::decode_from_slice(&data[2..], bincode::config::standard())?;
        Ok(Self {
            header,
            payload: &data[2 + consumed..],
        })
    }

    fn describe(&self) -> String {
        self.header.policy_expr()
    }

    fn unlock(&self, secrets: &Secrets, _params: &Argon2Params) -> Result<PolicyVault> {
        // V8 stores each factor's KDF parameters in its header, so the caller's
        // `params` are not used here.
        match secrets {
            Secrets::Factors(map) => PolicyVault::unlock(self.header.clone(), map),
            Secrets::Password(_) => {
                bail!("a version-8 store needs factor secrets, not a single password")
            }
        }
    }

    fn decrypt_payload(&self, vault: &PolicyVault) -> Result<Zeroizing<Vec<u8>>> {
        // Bind the on-disk header as associated data: a tampered or downgraded
        // header makes this fail, even if the DEK still reconstructed.
        let version = CypherVersion::from(Self::FORMAT);
        vault.decrypt_payload(self.payload, &self.header_bytes()?, version)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use zeroize::Zeroizing;

    use crate::auth::{FactorSecret, Leaf, PolicyNode};

    fn params() -> Argon2Params {
        Argon2Params::insecure()
    }

    fn secrets(pairs: &[(&str, &str)]) -> Secrets {
        Secrets::Factors(
            pairs
                .iter()
                .map(|(id, p)| {
                    (
                        (*id).to_string(),
                        FactorSecret::Password(Zeroizing::new((*p).to_string())),
                    )
                })
                .collect(),
        )
    }

    /// Opens a v8 file the library way: parse, unlock, decrypt — returning the
    /// payload (or an error if unlock or the header binding fails).
    fn open(path: &Path, creds: Secrets) -> Result<Zeroizing<Vec<u8>>> {
        let data = std::fs::read(path)?;
        let container = FileContainerV8::parse(&data)?;
        let vault = container.unlock(&creds, &params())?;
        container.decrypt_payload(&vault)
    }

    /// The first leaf in `node` referencing factor `id`.
    fn first_leaf(node: &PolicyNode, id: &str) -> Leaf {
        match node {
            PolicyNode::Leaf(leaf) if leaf.factor == id => leaf.clone(),
            PolicyNode::Leaf(_) => panic!("leaf for '{id}' not found"),
            PolicyNode::And(children) | PolicyNode::Or(children) => children
                .iter()
                .find(|c| matches!(c, PolicyNode::Leaf(l) if l.factor == id))
                .map_or_else(
                    || panic!("leaf for '{id}' not found"),
                    |c| first_leaf(c, id),
                ),
        }
    }

    #[test]
    fn parse_splits_header_and_payload() {
        let vault = PolicyVault::create("p1", "hunter2", &params()).unwrap();
        let blob = FileContainerV8::serialize(&vault, b"the payload").unwrap();

        let parsed = FileContainerV8::parse(&blob).unwrap();
        assert_eq!(parsed.header().policy_expr(), "p1");
        // describe surfaces the policy expression for display before unlock.
        assert_eq!(parsed.describe(), "p1");
        // The header bytes reserialize to the leading slice of the file.
        let header = serialize_header(parsed.header()).unwrap();
        assert_eq!(&blob[..header.len()], header.as_slice());
    }

    #[test]
    fn file_roundtrip_single_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");

        let vault = PolicyVault::create("p1", "pw", &params()).unwrap();
        FileContainerV8::write(&path, &vault, b"payload-bytes").unwrap();

        assert_eq!(
            open(&path, secrets(&[("p1", "pw")])).unwrap().as_slice(),
            b"payload-bytes"
        );
        assert!(open(&path, secrets(&[("p1", "wrong")])).is_err());
    }

    #[test]
    fn file_multifactor_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");

        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.enroll_password("p3", "three", &params()).unwrap();
        vault.set_policy("p1 or (p2 and p3)").unwrap();

        // A stored value is encrypted under the DEK-cypher and saved as the payload.
        let value_ct = vault.cypher().encrypt(b"a stored secret").unwrap();
        FileContainerV8::write(&path, &vault, &value_ct).unwrap();

        // Reopen via the AND branch; the DEK-cypher decrypts the stored value.
        let payload = open(&path, secrets(&[("p2", "two"), ("p3", "three")])).unwrap();
        let reopened = FileContainerV8::parse(&std::fs::read(&path).unwrap())
            .unwrap()
            .unlock(&secrets(&[("p2", "two"), ("p3", "three")]), &params())
            .unwrap();
        let plain = reopened.cypher().decrypt(&payload).unwrap();
        assert_eq!(plain.as_slice(), b"a stored secret");

        assert!(open(&path, secrets(&[("p2", "two")])).is_err()); // p2 alone
    }

    #[test]
    fn rejects_tampered_keyslot_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");

        let vault = PolicyVault::create("p1", "one-secret", &params()).unwrap();
        FileContainerV8::write(&path, &vault, b"top secret payload").unwrap();
        assert!(open(&path, secrets(&[("p1", "one-secret")])).is_ok());

        // Flip a byte inside the keyslot header (between the 2-byte tag and the
        // encrypted payload). The payload binds this region as associated data,
        // so the open must now fail.
        let mut data = std::fs::read(&path).unwrap();
        let header_len = serialize_header(FileContainerV8::parse(&data).unwrap().header())
            .unwrap()
            .len();
        data[header_len - 1] ^= 0x01;
        std::fs::write(&path, &data).unwrap();

        assert!(open(&path, secrets(&[("p1", "one-secret")])).is_err());
    }

    #[test]
    fn rejects_policy_downgrade_via_or_branch_stripping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");

        // p1 OR p2: OR replicates the full DEK to each branch, so p1 alone unlocks.
        let mut vault = PolicyVault::create("p1", "one-secret", &params()).unwrap();
        vault
            .enroll_password("p2", "two-secret", &params())
            .unwrap();
        vault.set_policy("p1 or p2").unwrap();
        FileContainerV8::write(&path, &vault, b"top secret payload").unwrap();

        // An attacker with no password rewrites the keyslot down to a single p1
        // leaf — reusing p1's original factor and wrapped share — and keeps the
        // original payload. The DEK still reconstructs from p1 alone...
        let data = std::fs::read(&path).unwrap();
        let parsed = FileContainerV8::parse(&data).unwrap();
        let header_len = serialize_header(parsed.header()).unwrap().len();
        let payload = &data[header_len..];
        let p1_factor = parsed
            .header()
            .factors
            .iter()
            .find(|f| f.id == "p1")
            .unwrap()
            .clone();
        let stripped = VaultHeader {
            factors: vec![p1_factor],
            policy: PolicyNode::Leaf(first_leaf(&parsed.header().policy, "p1")),
        };
        let mut tampered = serialize_header(&stripped).unwrap();
        tampered.extend_from_slice(payload);
        std::fs::write(&path, &tampered).unwrap();

        // ...but the payload was bound to the original `p1 OR p2` header as
        // associated data, so opening the downgraded file fails instead of
        // silently dropping the second factor.
        assert!(open(&path, secrets(&[("p1", "one-secret")])).is_err());
    }
}
