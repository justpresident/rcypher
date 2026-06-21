//! The policy vault: assembling factors and an access policy into an encrypted
//! vault, and the unlock / management operations over it.
//!
//! A random data-encryption key (DEK) encrypts the payload and is secret-shared
//! down the policy tree; each leaf's share is wrapped under its factor's auth-key.
//! Each factor also stores its auth-key wrapped under the DEK, so a holder of the
//! unlocked DEK can re-distribute the policy without re-presenting every factor.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use super::factor::{new_password_kind, password_kek};
use super::format::{
    Factor, FactorKind, PolicyMetadata, parse_policy_vault, serialize_policy_header,
};
use super::keyslot::{self, KeyMaterial};
use super::parser::{parse_policy, render_policy, validate_factors};
use super::policy::{Leaf, PolicyNode, Share, distribute, reconstruct};
use crate::constants::{KEY_MATERIAL_LEN, KeyMaterialBytes};
use crate::crypto::{Argon2Params, Cypher, EncryptionKey};

/// A user-supplied secret for one factor, presented at unlock or enroll time.
/// The password is held in a zeroizing buffer so it is wiped when the secret is
/// dropped.
pub enum FactorSecret {
    Password(Zeroizing<String>),
    // A YubiKey secret is obtained by interacting with the device; added by the
    // FIDO2 task.
}

/// An unlocked policy vault: the enrolled factors, the access policy (leaves
/// carrying wrapped shares), and the recovered data-encryption key.
pub struct PolicyVault {
    factors: Vec<Factor>,
    policy: PolicyNode,
    dek: KeyMaterial,
}

impl PolicyVault {
    /// Creates a new vault protected by a single password factor; the initial
    /// policy is just that factor. Enroll more factors and refine the policy with
    /// [`PolicyVault::enroll_password`] and [`PolicyVault::set_policy`].
    pub fn create(id: &str, password: &str, params: &Argon2Params) -> Result<Self> {
        check_factor_password(id, password)?;
        let dek = keyslot::generate_dek()?;

        let kind = new_password_kind(params)?;
        let authkek = password_kek(password, &kind)?;
        let factor = Factor {
            id: id.to_string(),
            kind,
            authkek_under_dek: keyslot::wrap_share(&dek, authkek.as_slice())?,
        };

        let template = PolicyNode::Leaf(Leaf {
            factor: id.to_string(),
            wrapped_share: Vec::new(),
        });
        let authkeks = HashMap::from([(id.to_string(), authkek)]);
        let policy = distribute_and_wrap(&template, &dek, &authkeks)?;

        Ok(Self {
            factors: vec![factor],
            policy,
            dek,
        })
    }

    /// Opens a vault by satisfying its policy with the provided factor secrets.
    /// Returns an error if the provided factors do not satisfy the unlock policy.
    pub fn unlock(meta: PolicyMetadata, secrets: &HashMap<String, FactorSecret>) -> Result<Self> {
        let mut authkeks = HashMap::new();
        for factor in &meta.factors {
            if let Some(secret) = secrets.get(&factor.id) {
                authkeks.insert(factor.id.clone(), derive_authkek(&factor.kind, secret)?);
            }
        }

        let mut provided = Vec::new();
        unwrap_leaves(&meta.policy, &authkeks, &mut provided);

        let dek_bytes = reconstruct(&meta.policy, &provided)
            .ok_or_else(|| anyhow!("the provided factors do not satisfy the unlock policy"))?;
        let dek = to_key_material(&dek_bytes)?;

        Ok(Self {
            factors: meta.factors,
            policy: meta.policy,
            dek,
        })
    }

    /// Enrolls an additional password factor. The policy is unchanged — call
    /// [`PolicyVault::set_policy`] to start requiring or accepting the new factor.
    pub fn enroll_password(
        &mut self,
        id: &str,
        password: &str,
        params: &Argon2Params,
    ) -> Result<()> {
        check_factor_password(id, password)?;
        if self.factors.iter().any(|f| f.id == id) {
            bail!("a factor named '{id}' already exists");
        }
        let kind = new_password_kind(params)?;
        let authkek = password_kek(password, &kind)?;
        self.factors.push(Factor {
            id: id.to_string(),
            kind,
            authkek_under_dek: keyslot::wrap_share(&self.dek, authkek.as_slice())?,
        });
        Ok(())
    }

    /// Removes a factor. Fails if the current policy still references it.
    pub fn remove_factor(&mut self, id: &str) -> Result<()> {
        if !self.factors.iter().any(|f| f.id == id) {
            bail!("no factor named '{id}'");
        }
        let remaining: HashSet<String> = self
            .factors
            .iter()
            .filter(|f| f.id != id)
            .map(|f| f.id.clone())
            .collect();
        if validate_factors(&self.policy, &remaining).is_err() {
            bail!("factor '{id}' is still used by the policy; change the policy first");
        }
        self.factors.retain(|f| f.id != id);
        Ok(())
    }

    /// Sets the access policy from an expression (e.g. `pass1 or (pass2 and yk)`),
    /// re-distributing the DEK across the new tree. Recovers every factor's
    /// wrapping key from the DEK, so only an unlocked vault is required.
    pub fn set_policy(&mut self, expr: &str) -> Result<()> {
        let template = parse_policy(expr)?;
        let known: HashSet<String> = self.factors.iter().map(|f| f.id.clone()).collect();
        validate_factors(&template, &known)?;
        let authkeks = self.recover_all_authkeks()?;
        self.policy = distribute_and_wrap(&template, &self.dek, &authkeks)?;
        Ok(())
    }

    /// The current policy as a canonical expression.
    #[must_use]
    pub fn policy_expr(&self) -> String {
        render_policy(&self.policy)
    }

    /// The ids of all enrolled factors.
    #[must_use]
    pub fn factor_ids(&self) -> Vec<String> {
        self.factors.iter().map(|f| f.id.clone()).collect()
    }

    /// The keyslot metadata to write ahead of the encrypted payload.
    #[must_use]
    pub fn metadata(&self) -> PolicyMetadata {
        PolicyMetadata {
            factors: self.factors.clone(),
            policy: self.policy.clone(),
        }
    }

    /// Encrypts the vault payload under the DEK.
    pub fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        keyslot::encrypt_payload(&self.dek, plaintext)
    }

    /// Decrypts the vault payload under the DEK.
    pub fn decrypt_payload(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        keyslot::decrypt_payload(&self.dek, ciphertext)
    }

    /// A `Cypher` keyed by the DEK, for encrypting/decrypting individual stored
    /// values — the role the password-derived key played in a plain vault.
    #[must_use]
    pub fn cypher(&self) -> Cypher {
        Cypher::new(EncryptionKey::from_key_material(&self.dek))
    }

    /// Reads a policy-vault file, satisfies its policy with `secrets`, and returns
    /// the unlocked vault together with the decrypted payload.
    pub fn open(
        path: &Path,
        secrets: &HashMap<String, FactorSecret>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let data = fs::read(path)?;
        let (meta, payload) = parse_policy_vault(&data)?;
        let payload = payload.to_vec();
        let vault = Self::unlock(meta, secrets)?;
        let plaintext = vault.decrypt_payload(&payload)?;
        Ok((vault, plaintext))
    }

    /// Reads `path` and decrypts its payload with this (already unlocked) vault's
    /// DEK — no secrets needed. The on-disk keyslot metadata is ignored; the held
    /// DEK is the source of truth (the DEK never changes across saves).
    pub fn load_payload(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let data = fs::read(path)?;
        let (_meta, payload) = parse_policy_vault(&data)?;
        self.decrypt_payload(payload)
    }

    /// Writes the vault — keyslot metadata followed by `payload` encrypted under
    /// the DEK — to `path`, atomically (temp file then rename).
    pub fn save(&self, payload: &[u8], path: &Path) -> Result<()> {
        let mut bytes = serialize_policy_header(&self.metadata())?;
        bytes.extend_from_slice(&self.encrypt_payload(payload)?);

        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let mut temp = NamedTempFile::new_in(dir)?;
        temp.write_all(&bytes)?;
        temp.persist(path)?;
        Ok(())
    }

    /// Recovers every factor's auth-key from the DEK (for re-distribution).
    fn recover_all_authkeks(&self) -> Result<HashMap<String, KeyMaterial>> {
        let mut authkeks = HashMap::new();
        for factor in &self.factors {
            let bytes = keyslot::unwrap_share(&self.dek, &factor.authkek_under_dek)
                .ok_or_else(|| anyhow!("corrupt keyslot for factor '{}'", factor.id))?;
            authkeks.insert(factor.id.clone(), to_key_material(&bytes)?);
        }
        Ok(authkeks)
    }
}

fn derive_authkek(kind: &FactorKind, secret: &FactorSecret) -> Result<KeyMaterial> {
    match (kind, secret) {
        (FactorKind::Password { .. }, FactorSecret::Password(pw)) => password_kek(pw, kind),
        (FactorKind::Yubikey { .. }, FactorSecret::Password(_)) => {
            bail!("YubiKey factors are not yet supported")
        }
    }
}

/// Distributes `dek` across `template` and wraps each leaf's share under its
/// factor's auth-key, returning the policy tree with shares filled in.
fn distribute_and_wrap(
    template: &PolicyNode,
    dek: &KeyMaterialBytes,
    authkeks: &HashMap<String, KeyMaterial>,
) -> Result<PolicyNode> {
    let shares = distribute(dek, template)?;
    let mut idx = 0;
    wrap_leaves(template, &shares, &mut idx, authkeks)
}

fn wrap_leaves(
    node: &PolicyNode,
    shares: &[Share],
    idx: &mut usize,
    authkeks: &HashMap<String, KeyMaterial>,
) -> Result<PolicyNode> {
    match node {
        PolicyNode::Leaf(leaf) => {
            let share = shares
                .get(*idx)
                .ok_or_else(|| anyhow!("internal error: share/leaf count mismatch"))?;
            *idx += 1;
            let kek = authkeks
                .get(&leaf.factor)
                .ok_or_else(|| anyhow!("no key material for factor '{}'", leaf.factor))?;
            Ok(PolicyNode::Leaf(Leaf {
                factor: leaf.factor.clone(),
                wrapped_share: keyslot::wrap_share(kek, share)?,
            }))
        }
        PolicyNode::And(children) => Ok(PolicyNode::And(wrap_children(
            children, shares, idx, authkeks,
        )?)),
        PolicyNode::Or(children) => Ok(PolicyNode::Or(wrap_children(
            children, shares, idx, authkeks,
        )?)),
    }
}

fn wrap_children(
    children: &[PolicyNode],
    shares: &[Share],
    idx: &mut usize,
    authkeks: &HashMap<String, KeyMaterial>,
) -> Result<Vec<PolicyNode>> {
    children
        .iter()
        .map(|child| wrap_leaves(child, shares, idx, authkeks))
        .collect()
}

/// Builds the per-leaf `provided` shares: for each leaf in DFS order, unwrap its
/// share if we hold its factor's auth-key (and it authenticates), else `None`.
fn unwrap_leaves(
    node: &PolicyNode,
    authkeks: &HashMap<String, KeyMaterial>,
    out: &mut Vec<Option<Share>>,
) {
    match node {
        PolicyNode::Leaf(leaf) => {
            let share = authkeks
                .get(&leaf.factor)
                .and_then(|kek| keyslot::unwrap_share(kek, &leaf.wrapped_share));
            out.push(share);
        }
        PolicyNode::And(children) | PolicyNode::Or(children) => {
            for child in children {
                unwrap_leaves(child, authkeks, out);
            }
        }
    }
}

fn to_key_material(bytes: &[u8]) -> Result<KeyMaterial> {
    if bytes.len() != KEY_MATERIAL_LEN {
        bail!(
            "expected {KEY_MATERIAL_LEN}-byte key material, got {} bytes",
            bytes.len()
        );
    }
    // Copy straight into a zeroizing buffer, so the key material never lives in an
    // un-zeroized intermediate array.
    let mut material: KeyMaterial = Zeroizing::new([0u8; KEY_MATERIAL_LEN]);
    material.copy_from_slice(bytes);
    Ok(material)
}

fn validate_factor_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("a factor id cannot be empty");
    }
    if id.eq_ignore_ascii_case("and") || id.eq_ignore_ascii_case("or") {
        bail!("'{id}' is a reserved keyword and cannot be a factor id");
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        bail!("factor id '{id}' may contain only letters, digits, '-' and '_'");
    }
    Ok(())
}

/// Guards against a password that is too similar to the factor *name*.
///
/// The name is stored unencrypted as a label, so a password that shares a long
/// prefix with it (e.g. name `foobar`, password `foobar1`) leaks most of the
/// password to anyone reading the file. Require the password to be at least twice
/// as long as the prefix it shares with the name — which also rejects a password
/// equal to the name, catching the mix-up of typing a password into the name
/// slot. Comparison is case-insensitive, since an attacker would try case
/// variants of a known label cheaply.
/// Validates that `password` is acceptable for a factor named `id`, independent
/// of any vault — so a caller can check it before doing more work (e.g. a
/// strength prompt). The name must be well-formed and the password must not be
/// too similar to it. [`PolicyVault::create`] and [`PolicyVault::enroll_password`]
/// apply the same check.
pub fn check_factor_password(id: &str, password: &str) -> Result<()> {
    validate_factor_id(id)?;
    reject_password_resembling_id(id, password)
}

fn reject_password_resembling_id(id: &str, password: &str) -> Result<()> {
    let shared_prefix = id
        .chars()
        .flat_map(char::to_lowercase)
        .zip(password.chars().flat_map(char::to_lowercase))
        .take_while(|(a, b)| a == b)
        .count();
    if password.chars().count() < 2 * shared_prefix {
        bail!(
            "the password is too similar to the factor name '{id}': they share a \
             {shared_prefix}-character prefix, and the name is stored unencrypted. Use a \
             password at least twice as long as any prefix it shares with the name (or pick a \
             different name). Did you type your password where the factor name belongs? The \
             name is just a label; the password is prompted separately."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Argon2Params {
        Argon2Params::insecure()
    }

    fn pw(s: &str) -> FactorSecret {
        FactorSecret::Password(Zeroizing::new(s.to_string()))
    }

    fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, FactorSecret> {
        pairs
            .iter()
            .map(|(id, p)| ((*id).to_string(), pw(p)))
            .collect()
    }

    /// Round-trips a vault through its serialized metadata, then unlocks.
    fn reopen(vault: &PolicyVault, provided: &[(&str, &str)]) -> Result<PolicyVault> {
        PolicyVault::unlock(vault.metadata(), &secrets(provided))
    }

    #[test]
    fn single_password_unlock_and_payload() {
        let vault = PolicyVault::create("p1", "hunter2", &params()).unwrap();
        let blob = vault.encrypt_payload(b"top secret").unwrap();

        let reopened = reopen(&vault, &[("p1", "hunter2")]).unwrap();
        assert_eq!(
            reopened.decrypt_payload(&blob).unwrap().as_slice(),
            b"top secret"
        );

        assert!(reopen(&vault, &[("p1", "wrong")]).is_err());
    }

    #[test]
    fn or_and_policy() {
        // p1 OR (p2 AND p3)
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.enroll_password("p3", "three", &params()).unwrap();
        vault.set_policy("p1 or (p2 and p3)").unwrap();
        assert_eq!(vault.policy_expr(), "p1 or (p2 and p3)");

        assert!(reopen(&vault, &[("p1", "one")]).is_ok()); // p1 alone
        assert!(reopen(&vault, &[("p2", "two"), ("p3", "three")]).is_ok()); // p2 + p3
        assert!(reopen(&vault, &[("p2", "two")]).is_err()); // p2 alone -> no
        assert!(reopen(&vault, &[("p3", "three")]).is_err()); // p3 alone -> no
        assert!(reopen(&vault, &[("p2", "two"), ("p3", "WRONG")]).is_err());
    }

    #[test]
    fn payload_decrypts_via_either_branch() {
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        vault.enroll_password("yk", "two", &params()).unwrap();
        vault.set_policy("p1 or yk").unwrap();
        let blob = vault.encrypt_payload(b"data").unwrap();

        let via_p1 = reopen(&vault, &[("p1", "one")]).unwrap();
        let via_yk = reopen(&vault, &[("yk", "two")]).unwrap();
        assert_eq!(via_p1.decrypt_payload(&blob).unwrap().as_slice(), b"data");
        assert_eq!(via_yk.decrypt_payload(&blob).unwrap().as_slice(), b"data");
    }

    #[test]
    fn tightening_policy_to_and_takes_effect() {
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.set_policy("p1 and p2").unwrap();

        assert!(reopen(&vault, &[("p1", "one")]).is_err()); // one alone no longer enough
        assert!(reopen(&vault, &[("p1", "one"), ("p2", "two")]).is_ok());
    }

    #[test]
    fn remove_factor_rules() {
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.set_policy("p1 or p2").unwrap();

        assert!(vault.remove_factor("p2").is_err()); // still referenced
        vault.set_policy("p1").unwrap();
        assert!(vault.remove_factor("p2").is_ok());
        assert!(vault.remove_factor("nope").is_err());
    }

    #[test]
    fn rejects_bad_factor_ids_and_dupes() {
        assert!(PolicyVault::create("and", "x", &params()).is_err());
        assert!(PolicyVault::create("a b", "x", &params()).is_err());
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        assert!(vault.enroll_password("p1", "x", &params()).is_err());
        assert!(vault.set_policy("p1 or missing").is_err()); // unknown factor
    }

    #[test]
    fn rejects_password_resembling_factor_name() {
        // Equal name and password (a full shared prefix) is rejected — the footgun
        // of typing a password into the name slot and repeating it.
        assert!(PolicyVault::create("hunter2", "hunter2", &params()).is_err());

        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        // A shared prefix longer than half the password length is rejected.
        assert!(
            vault
                .enroll_password("foobar", "foobar1", &params())
                .is_err()
        ); // prefix 6, len 7
        // Case-insensitively, too.
        assert!(
            vault
                .enroll_password("foobar", "FOOBAR12", &params())
                .is_err()
        ); // prefix 6, len 8
        // A password at least twice the shared prefix is fine.
        assert!(
            vault
                .enroll_password("foobar", "foobarsecret", &params())
                .is_ok()
        ); // prefix 6, len 12
        // An unrelated password is fine.
        assert!(
            vault
                .enroll_password("backup", "s3cret-xyz", &params())
                .is_ok()
        );
    }

    #[test]
    fn file_roundtrip_single_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");

        let vault = PolicyVault::create("p1", "pw", &params()).unwrap();
        vault.save(b"payload-bytes", &path).unwrap();

        let (reopened, payload) = PolicyVault::open(&path, &secrets(&[("p1", "pw")])).unwrap();
        assert_eq!(payload.as_slice(), b"payload-bytes");
        assert_eq!(reopened.policy_expr(), "p1");

        assert!(PolicyVault::open(&path, &secrets(&[("p1", "wrong")])).is_err());
    }

    #[test]
    fn file_multifactor_and_value_cypher_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");

        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.enroll_password("p3", "three", &params()).unwrap();
        vault.set_policy("p1 or (p2 and p3)").unwrap();

        // A stored value is encrypted under the DEK-cypher and saved as the payload.
        let value_ct = vault.cypher().encrypt(b"a stored secret").unwrap();
        vault.save(&value_ct, &path).unwrap();

        // Reopen via the AND branch; the reopened DEK-cypher decrypts the value.
        let (reopened, payload) =
            PolicyVault::open(&path, &secrets(&[("p2", "two"), ("p3", "three")])).unwrap();
        let plain = reopened.cypher().decrypt(&payload).unwrap();
        assert_eq!(plain.as_slice(), b"a stored secret");

        assert!(PolicyVault::open(&path, &secrets(&[("p2", "two")])).is_err()); // p2 alone
    }
}
