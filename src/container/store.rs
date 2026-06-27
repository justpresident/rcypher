//! The version-agnostic container facade: [`LockedContainer`] and
//! [`UnlockedContainer`].
//!
//! These are the only types a client needs. Loading a file gives a
//! [`LockedContainer`] regardless of its on-disk format; you satisfy its lock
//! with passwords and [`unlock`](LockedContainer::unlock) it into an
//! [`UnlockedContainer<T>`], which exposes your data, the data-key [`Cypher`],
//! and lock management. A legacy file is transparently upgraded to the current
//! format on unlock; clients never name a format version.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use super::{FileContainerFormat, FileContainerV8};
use crate::DataContainer;
use crate::auth::{FactorKind, PolicyVault, UnlockSession};
use crate::constants::{HmacSecretBytes, SaltBytes};
use crate::crypto::{Argon2Params, Cypher, EncryptionKey};
use crate::version::CypherVersion;

/// Factor id given to the password enrolled when a legacy store is upgraded.
const PRIMARY_FACTOR: &str = "primary";

/// A loaded but locked store file. Version-agnostic: you cannot tell whether the
/// file on disk is the current format or a legacy one.
pub struct LockedContainer {
    bytes: Vec<u8>,
    argon2: Argon2Params,
    lock: Lock,
}

/// The per-format unlock state. The only place the on-disk format leaks — and it
/// is private.
enum Lock {
    /// Legacy single-password file: the whole file is a password envelope. Once a
    /// correct password is supplied we cache it and the decrypted payload.
    Legacy(Option<Legacy>),
    /// Current policy vault: an incremental [`UnlockSession`] over the keyslot
    /// header. `payload_offset` is where the encrypted body begins (the header is
    /// the body's associated data).
    Policy {
        payload_offset: usize,
        session: UnlockSession,
    },
}

/// A verified legacy password and its derived key. The decrypted payload is *not*
/// cached here — it is re-derived in [`LockedContainer::unlock`], so the cleartext
/// never outlives the unlock call.
struct Legacy {
    password: Zeroizing<String>,
    key: EncryptionKey,
}

impl LockedContainer {
    /// Loads a store file, using secure default Argon2 parameters for any password
    /// derivation (legacy unlock, the upgraded factor, and later enrollments).
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_params(path, &Argon2Params::default())
    }

    /// Like [`load`](LockedContainer::load) with explicit Argon2 cost parameters.
    pub fn load_with_params(path: &Path, argon2: &Argon2Params) -> Result<Self> {
        Self::from_slice_with_params(&std::fs::read(path)?, argon2)
    }

    /// Loads a store from an in-memory slice, with secure default Argon2 params.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Self::from_slice_with_params(bytes, &Argon2Params::default())
    }

    /// Like [`from_slice`](LockedContainer::from_slice) with explicit Argon2 params.
    pub fn from_slice_with_params(bytes: &[u8], argon2: &Argon2Params) -> Result<Self> {
        let bytes = bytes.to_vec();
        let lock = match FileContainerFormat::probe(&bytes)? {
            // Legacy: the whole file is one password envelope; nothing to parse
            // until a password is supplied (the salt is in the envelope header).
            FileContainerFormat::V7 => Lock::Legacy(None),
            FileContainerFormat::V8 => {
                let container = FileContainerV8::parse(&bytes)?;
                Lock::Policy {
                    payload_offset: bytes.len() - container.payload().len(),
                    session: UnlockSession::new(container.header().clone()),
                }
            }
        };
        Ok(Self {
            bytes,
            argon2: *argon2,
            lock,
        })
    }

    /// A human-readable description of what unlocking requires — e.g. `a password`
    /// or `pass1 or (pass2 and fido2)`.
    #[must_use]
    pub fn requirement(&self) -> String {
        match &self.lock {
            Lock::Legacy(_) => "a password".to_string(),
            Lock::Policy { session, .. } => session.policy_expr(),
        }
    }

    /// Whether the lock can be satisfied with passwords alone — i.e. without
    /// presenting a FIDO2 security key. A caller without FIDO2 support can use this
    /// to decide whether it can unlock at all.
    #[must_use]
    pub fn satisfiable_by_password(&self) -> bool {
        match &self.lock {
            Lock::Legacy(_) => true,
            Lock::Policy { session, .. } => session.satisfiable_by_passwords(),
        }
    }

    /// The still-unsatisfied factors, each id paired with its kind — so a caller can
    /// see which factor *types* remain (and read a pending FIDO2 factor's device
    /// parameters: `credential_id`, `rp_id`, `salt`, `require_pin`) and prompt only
    /// for those. Empty for a legacy single-password store (use
    /// [`needs_password`](Self::needs_password) there).
    #[must_use]
    pub fn pending_factor_kinds(&self) -> Vec<(String, FactorKind)> {
        match &self.lock {
            Lock::Legacy(_) => Vec::new(),
            Lock::Policy { session, .. } => session.pending_factor_kinds(),
        }
    }

    /// Whether a password could still make progress toward unlocking — i.e. a legacy
    /// store not yet unlocked, or a policy with an unsatisfied password factor. Lets
    /// a prompt loop skip asking for a password when none is needed.
    #[must_use]
    pub fn needs_password(&self) -> bool {
        match &self.lock {
            Lock::Legacy(slot) => slot.is_none(),
            Lock::Policy { session, .. } => session
                .pending_factor_kinds()
                .iter()
                .any(|(_, kind)| matches!(kind, FactorKind::Password { .. })),
        }
    }

    /// Whether this is a legacy single-password store (which [`unlock`](Self::unlock)
    /// transparently converts to the current format).
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        matches!(self.lock, Lock::Legacy(_))
    }

    /// Tries `password` against the still-unsatisfied factors. Returns the id of
    /// the factor it satisfied (or `None` if it matched nothing).
    pub fn try_password(&mut self, password: &str) -> Result<Option<String>> {
        match &mut self.lock {
            Lock::Policy { session, .. } => session.try_password(password),
            Lock::Legacy(slot) => {
                if slot.is_some() {
                    return Ok(Some(PRIMARY_FACTOR.to_string()));
                }
                // The legacy file is one password envelope; a correct password is
                // exactly one whose derived key authenticates the whole file. Verify
                // by decrypting, then discard the plaintext — `unlock` re-derives it,
                // so the cleartext payload never lives in the locked handle.
                let key = EncryptionKey::for_data_with_params(password, &self.bytes, &self.argon2)?;
                if Cypher::new(key.clone()).decrypt(&self.bytes).is_err() {
                    return Ok(None);
                }
                *slot = Some(Legacy {
                    password: Zeroizing::new(password.to_string()),
                    key,
                });
                Ok(Some(PRIMARY_FACTOR.to_string()))
            }
        }
    }

    /// Tries a FIDO2 `hmac-secret` output (obtained from the authenticator for one
    /// of the factors reported by [`factor_kinds`](Self::factor_kinds)) against the
    /// still-unsatisfied factors. Returns the id of the FIDO2 factor it satisfied,
    /// or `None`. A legacy single-password store has no FIDO2 factors, so this
    /// returns `None` for one.
    pub fn try_fido2_secret(
        &mut self,
        raw_hmac_secret: &HmacSecretBytes,
    ) -> Result<Option<String>> {
        match &mut self.lock {
            Lock::Policy { session, .. } => session.try_fido2_secret(raw_hmac_secret),
            Lock::Legacy(_) => Ok(None),
        }
    }

    /// Whether enough factors have been supplied to unlock.
    #[must_use]
    pub fn can_unlock(&self) -> bool {
        match &self.lock {
            Lock::Legacy(slot) => slot.is_some(),
            Lock::Policy { session, .. } => session.is_complete(),
        }
    }

    /// Unlocks the store and decrypts its payload into `T`.
    ///
    /// A legacy file is transparently upgraded here: a fresh data key is
    /// generated, [`DataContainer::rekey`] re-keys the data, and [`DataContainer::verify`]
    /// confirms it — so an inner-key mistake fails now rather than on the next
    /// save. [`was_upgraded`](UnlockedContainer::was_upgraded) reports it.
    pub fn unlock<T: DataContainer>(self) -> Result<UnlockedContainer<T>> {
        match self.lock {
            Lock::Policy {
                payload_offset,
                session,
            } => {
                let vault = session.finish()?;
                let aad = &self.bytes[..payload_offset];
                let ciphertext = &self.bytes[payload_offset..];
                let version = CypherVersion::from(FileContainerFormat::V8);
                let plaintext = vault.decrypt_payload(ciphertext, aad, version)?;
                let data = T::decode(&plaintext)?;
                data.verify(&vault.cypher())?;
                Ok(UnlockedContainer {
                    vault,
                    data,
                    argon2: self.argon2,
                    provenance: Provenance::Fresh,
                })
            }
            Lock::Legacy(Some(Legacy { password, key })) => {
                // Re-derive the plaintext here (it was not cached at try_password
                // time), then upgrade: a fresh DEK with the password enrolled as the
                // primary factor, re-keying the inner data.
                let old_cypher = Cypher::new(key);
                let payload = old_cypher.decrypt(&self.bytes)?;
                let mut data = T::decode(&payload)?;
                let vault = PolicyVault::create(PRIMARY_FACTOR, &password, &self.argon2)?;
                data.rekey(&old_cypher, &vault.cypher())?;
                data.verify(&vault.cypher())?;
                Ok(UnlockedContainer {
                    vault,
                    data,
                    argon2: self.argon2,
                    // Keep the exact pre-upgrade bytes so the first save backs them
                    // up regardless of the save path.
                    provenance: Provenance::UpgradedPendingBackup(self.bytes),
                })
            }
            Lock::Legacy(None) => {
                bail!("the store is still locked; supply a correct password first")
            }
        }
    }
}

/// An unlocked store: mutable access to the data, the data-key [`Cypher`], lock
/// management, and saving. Always written in the current format.
pub struct UnlockedContainer<T> {
    vault: PolicyVault,
    data: T,
    argon2: Argon2Params,
    provenance: Provenance,
}

/// Where an [`UnlockedContainer`] came from, and whether its pre-upgrade file still
/// needs backing up. A single enum so "was upgraded" and "backup still owed" can't
/// drift out of sync (the trap of two separate bools).
enum Provenance {
    /// A fresh store, or one opened from a current-format file. No backup owed.
    Fresh,
    /// Upgraded from a legacy file on unlock; the first [`save`](UnlockedContainer::save)
    /// must still write these exact pre-upgrade bytes to `<path>.bak`.
    UpgradedPendingBackup(Vec<u8>),
    /// Upgraded from a legacy file and already saved once (backup written).
    Upgraded,
}

impl<T: DataContainer> UnlockedContainer<T> {
    /// Creates a brand-new store protected by a single password factor, holding
    /// `data`. Uses secure default Argon2 parameters; [`save`](Self::save) writes
    /// it in the current format.
    pub fn create(factor_id: &str, password: &str, data: T) -> Result<Self> {
        Self::create_with_params(factor_id, password, data, &Argon2Params::default())
    }

    /// Like [`create`](Self::create) with explicit Argon2 cost parameters.
    pub fn create_with_params(
        factor_id: &str,
        password: &str,
        data: T,
        argon2: &Argon2Params,
    ) -> Result<Self> {
        Ok(Self {
            vault: PolicyVault::create(factor_id, password, argon2)?,
            data,
            argon2: *argon2,
            provenance: Provenance::Fresh,
        })
    }

    /// The decrypted data.
    #[must_use]
    pub const fn data(&self) -> &T {
        &self.data
    }

    /// Mutable access to the decrypted data.
    pub const fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// A [`Cypher`] keyed by the store's data key — for the data type's own inner
    /// encryption (and the same key its [`DataContainer::rekey`]/`verify` receive).
    #[must_use]
    pub fn cypher(&self) -> Cypher {
        self.vault.cypher()
    }

    /// Whether this store was upgraded from a legacy format on unlock (so its data
    /// was re-keyed, and the first [`save`](Self::save) backs up the old file). For
    /// a slice loaded with [`from_slice`](LockedContainer::from_slice), this is the
    /// cue to keep your input bytes until you've persisted the result.
    #[must_use]
    pub const fn was_upgraded(&self) -> bool {
        !matches!(self.provenance, Provenance::Fresh)
    }

    /// The access policy as a canonical expression.
    #[must_use]
    pub fn policy_expr(&self) -> String {
        self.vault.policy_expr()
    }

    /// The ids of all enrolled factors.
    #[must_use]
    pub fn factor_ids(&self) -> Vec<String> {
        self.vault.factor_ids()
    }

    /// Each enrolled factor's id paired with its kind (for display).
    #[must_use]
    pub fn factor_kinds(&self) -> Vec<(String, FactorKind)> {
        self.vault.factor_kinds()
    }

    /// Enrolls an additional password factor (using the load-time Argon2 params).
    pub fn enroll_password(&mut self, id: &str, password: &str) -> Result<()> {
        self.vault.enroll_password(id, password, &self.argon2)
    }

    /// Enrolls a FIDO2 security-key factor from a just-enrolled credential and its
    /// current `hmac-secret` output (obtain both via `rcypher::fido2`). The factor
    /// is unused until [`set_policy`](Self::set_policy) references it.
    pub fn enroll_fido2(
        &mut self,
        id: &str,
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
        raw_hmac_secret: &HmacSecretBytes,
    ) -> Result<()> {
        self.vault
            .enroll_fido2(id, credential_id, rp_id, salt, require_pin, raw_hmac_secret)
    }

    /// Sets the access policy from an expression (e.g. `pass1 or (pass2 and fido2)`).
    pub fn set_policy(&mut self, expr: &str) -> Result<()> {
        self.vault.set_policy(expr)
    }

    /// Removes a factor. Fails if the current policy still references it.
    pub fn remove_factor(&mut self, id: &str) -> Result<()> {
        self.vault.remove_factor(id)
    }

    /// Serializes the store to a self-contained byte vector, in the current
    /// format. No file is touched — the caller keeps any previous copy.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let payload = self.data.encode()?;
        FileContainerV8::serialize(&self.vault, &payload)
    }

    /// Writes the store to `path` atomically, in the current format.
    ///
    /// On the first save of a store that was upgraded from a legacy file, the exact
    /// pre-upgrade bytes are first written to `<path>.bak`, so a bad
    /// [`DataContainer::rekey`] can't destroy the only copy. Those captured bytes — not
    /// whatever currently sits at `path` — are the backup, so it is correct even
    /// when `path` differs from the file the store was loaded from. The backup is
    /// taken only once; a later save won't overwrite it with already-upgraded data.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        if let Provenance::UpgradedPendingBackup(original) = &self.provenance {
            crate::file_io::write_atomic(&backup_path(path), original)?;
        }
        crate::file_io::write_atomic(path, &self.to_vec()?)?;
        if matches!(self.provenance, Provenance::UpgradedPendingBackup(_)) {
            self.provenance = Provenance::Upgraded;
        }
        Ok(())
    }
}

/// The backup path written before a legacy store is upgraded in place: `<path>.bak`.
#[must_use]
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Argon2Params {
        Argon2Params::insecure()
    }

    /// A trivial payload to exercise the facade without the storage feature.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Text(String);
    impl DataContainer for Text {
        fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(self.0.clone().into_bytes()))
        }
        fn decode(bytes: &[u8]) -> Result<Self> {
            Ok(Self(String::from_utf8(bytes.to_vec())?))
        }
        // No inner encryption, so nothing to re-key or verify on upgrade.
        fn rekey(&mut self, _from: &Cypher, _to: &Cypher) -> Result<()> {
            Ok(())
        }
        fn verify(&self, _cypher: &Cypher) -> Result<()> {
            Ok(())
        }
    }

    fn new_store(password: &str, text: &str) -> UnlockedContainer<Text> {
        UnlockedContainer::create_with_params("primary", password, Text(text.into()), &params())
            .unwrap()
    }

    fn open(bytes: &[u8]) -> LockedContainer {
        LockedContainer::from_slice_with_params(bytes, &params()).unwrap()
    }

    #[test]
    fn create_save_load_unlock_roundtrip() {
        let bytes = new_store("hunter2", "secret data").to_vec().unwrap();

        let mut locked = open(&bytes);
        assert_eq!(locked.requirement(), "primary");
        assert!(!locked.can_unlock());
        assert_eq!(locked.try_password("wrong").unwrap(), None);
        assert_eq!(
            locked.try_password("hunter2").unwrap().as_deref(),
            Some("primary")
        );
        assert!(locked.can_unlock());

        let unlocked = locked.unlock::<Text>().unwrap();
        assert_eq!(unlocked.data().0, "secret data");
        assert!(!unlocked.was_upgraded());
    }

    #[test]
    fn wrong_password_never_unlocks() {
        let bytes = new_store("right", "data").to_vec().unwrap();
        let mut locked = open(&bytes);
        assert_eq!(locked.try_password("nope").unwrap(), None);
        assert!(!locked.can_unlock());
        assert!(locked.unlock::<Text>().is_err());
    }

    #[test]
    fn enroll_and_multifactor_policy() {
        let mut store = new_store("p1pass", "d");
        store.enroll_password("p2", "p2pass").unwrap();
        store.set_policy("primary or p2").unwrap();
        let bytes = store.to_vec().unwrap();

        // Unlock via the second factor.
        let mut locked = open(&bytes);
        assert_eq!(locked.requirement(), "primary or p2");
        assert_eq!(
            locked.try_password("p2pass").unwrap().as_deref(),
            Some("p2")
        );
        assert_eq!(locked.unlock::<Text>().unwrap().data().0, "d");
    }

    #[test]
    fn enroll_fido2_and_unlock_via_secret() {
        // A fixed `hmac-secret` standing in for an authenticator, so the facade's
        // FIDO2 enroll/unlock path runs without hardware.
        let secret = [5u8; crate::constants::HMAC_SECRET_LEN];
        let mut store = new_store("p1pass", "d");
        store
            .enroll_fido2(
                "key",
                vec![1, 2],
                "rcypher".into(),
                crate::constants::SaltBytes::default(),
                false,
                &secret,
            )
            .unwrap();
        store.set_policy("primary or key").unwrap();
        let bytes = store.to_vec().unwrap();

        // The locked container reports the FIDO2 factor's params for the caller to
        // drive a `get_assertion`...
        let mut locked = open(&bytes);
        assert!(
            locked
                .pending_factor_kinds()
                .iter()
                .any(|(id, k)| id == "key" && matches!(k, FactorKind::Fido2 { .. }))
        );

        // ...and the resulting secret alone unlocks (OR replicates the DEK).
        assert_eq!(
            locked.try_fido2_secret(&secret).unwrap().as_deref(),
            Some("key")
        );
        assert!(locked.can_unlock());
        assert_eq!(locked.unlock::<Text>().unwrap().data().0, "d");

        // A legacy-style lock (no FIDO2 factors) yields no match and empty kinds.
        let mut pw_only = open(&new_store("only", "x").to_vec().unwrap());
        assert_eq!(pw_only.try_fido2_secret(&secret).unwrap(), None);
    }

    #[test]
    fn data_mut_then_save_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store");
        let mut store = new_store("pw", "v1");
        store.save(&path).unwrap();

        let mut store = open(&std::fs::read(&path).unwrap());
        store.try_password("pw").unwrap();
        let mut store = store.unlock::<Text>().unwrap();
        store.data_mut().0 = "v2".into();
        store.save(&path).unwrap();

        let mut reopened = open(&std::fs::read(&path).unwrap());
        reopened.try_password("pw").unwrap();
        assert_eq!(reopened.unlock::<Text>().unwrap().data().0, "v2");
    }

    /// Full open via the facade, returning the decrypted data or an error.
    fn try_open(bytes: &[u8], password: &str) -> Result<Text> {
        let mut locked = LockedContainer::from_slice_with_params(bytes, &params())?;
        locked.try_password(password)?;
        if !locked.can_unlock() {
            bail!("not unlockable with that password");
        }
        Ok(locked.unlock::<Text>()?.data().clone())
    }

    fn first_leaf(node: &crate::auth::PolicyNode, id: &str) -> Option<crate::auth::Leaf> {
        node.leaves().find(|l| l.factor == id).cloned()
    }

    #[test]
    fn rejects_tampered_keyslot_header() {
        let bytes = new_store("pw", "secret").to_vec().unwrap();
        assert!(try_open(&bytes, "pw").is_ok());

        // Flip a byte inside the keyslot header (before the encrypted payload).
        // The payload binds the header as associated data, so the open must fail.
        let header_len = bytes.len() - FileContainerV8::parse(&bytes).unwrap().payload().len();
        let mut tampered = bytes;
        tampered[header_len - 1] ^= 0x01;
        assert!(try_open(&tampered, "pw").is_err());
    }

    #[test]
    fn rejects_policy_downgrade_via_branch_stripping() {
        use crate::auth::{PolicyNode, VaultHeader};

        // primary OR p2: either password unlocks (OR replicates the DEK).
        let mut store = new_store("p1pass", "secret");
        store.enroll_password("p2", "p2pass").unwrap();
        store.set_policy("primary or p2").unwrap();
        let bytes = store.to_vec().unwrap();
        assert!(try_open(&bytes, "p1pass").is_ok());

        // An attacker rewrites the keyslot down to a single `primary` leaf, reusing
        // its original factor and wrapped share, keeping the original payload.
        let parsed = FileContainerV8::parse(&bytes).unwrap();
        let header = parsed.header();
        let primary = header
            .factors
            .iter()
            .find(|f| f.id == "primary")
            .unwrap()
            .clone();
        let leaf = first_leaf(&header.policy, "primary").unwrap();
        let payload = parsed.payload().to_vec();
        let stripped = VaultHeader {
            factors: vec![primary],
            policy: PolicyNode::Leaf(leaf),
        };
        let mut tampered = FileContainerFormat::V8.tag().to_vec();
        tampered.extend_from_slice(
            &bincode::encode_to_vec(&stripped, bincode::config::standard()).unwrap(),
        );
        tampered.extend_from_slice(&payload);

        // The DEK still reconstructs from `primary` alone, but the payload was
        // bound to the original `primary OR p2` header — so the open fails.
        assert!(try_open(&tampered, "p1pass").is_err());
    }
}
