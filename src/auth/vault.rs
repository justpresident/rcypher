//! The policy vault: assembling factors and an access policy into an encrypted
//! vault, and the unlock / management operations over it.
//!
//! A random data-encryption key (DEK) encrypts the payload and is secret-shared
//! down the policy tree; each leaf's share is wrapped under its factor's auth-KEK.
//! Each factor also stores its auth-KEK wrapped under the DEK, so a holder of the
//! unlocked DEK can re-distribute the policy without re-presenting every factor.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow, bail};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::factor::{Factor, FactorKind, fido2_kek, new_password_kind, password_kek};
use super::header::VaultHeader;
use super::policy::{
    Leaf, PolicyNode, Share, distribute, is_factor_id_char, parse_policy, reconstruct,
    render_policy, validate_factors,
};
use crate::constants::{HmacSecretBytes, KEY_MATERIAL_LEN, KeyMaterialBytes, SaltBytes};
use crate::crypto::{
    Argon2Params, Cypher, EncryptionKey, KeyMaterial, cypher_from_material, generate_key_material,
};
use crate::version::CypherVersion;

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
        let dek = generate_key_material()?;

        let kind = new_password_kind(params)?;
        let authkek = password_kek(password, &kind)?;
        let factor = Factor {
            id: id.to_string(),
            kind,
            authkek_under_dek: cypher_from_material(&dek, CypherVersion::default())
                .encrypt_with_aad(authkek.as_slice(), &[])?,
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
        if let Some(existing) = self.factor_matching_password(password)? {
            bail!(
                "that password is already in use by factor '{existing}'; each factor needs a \
                 distinct password"
            );
        }
        let kind = new_password_kind(params)?;
        let authkek = password_kek(password, &kind)?;
        self.factors.push(Factor {
            id: id.to_string(),
            kind,
            authkek_under_dek: self
                .dek_cypher()
                .encrypt_with_aad(authkek.as_slice(), &[])?,
        });
        Ok(())
    }

    /// Enrolls a FIDO2 security-key factor from a just-enrolled credential and its
    /// current `hmac-secret` output. Like [`enroll_password`](Self::enroll_password)
    /// the policy is unchanged until [`set_policy`](Self::set_policy) references it.
    pub fn enroll_fido2(
        &mut self,
        id: &str,
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
        raw_hmac_secret: &HmacSecretBytes,
    ) -> Result<()> {
        validate_factor_id(id)?;
        if self.factors.iter().any(|f| f.id == id) {
            bail!("a factor named '{id}' already exists");
        }
        let authkek = fido2_kek(raw_hmac_secret)?;
        self.factors.push(Factor {
            id: id.to_string(),
            kind: FactorKind::Fido2 {
                credential_id,
                rp_id,
                salt,
                require_pin,
            },
            authkek_under_dek: self
                .dek_cypher()
                .encrypt_with_aad(authkek.as_slice(), &[])?,
        });
        Ok(())
    }

    /// The id of an enrolled password factor whose password equals `password`, if
    /// any — re-derives each factor's auth-KEK from `password` (with that factor's
    /// salt) and compares it to the factor's actual auth-KEK recovered from the
    /// DEK. Lets enrollment refuse a password already used by another factor.
    fn factor_matching_password(&self, password: &str) -> Result<Option<String>> {
        for factor in &self.factors {
            if !matches!(factor.kind, FactorKind::Password { .. }) {
                continue;
            }
            let candidate = password_kek(password, &factor.kind)?;
            let Ok(actual) = self
                .dek_cypher()
                .decrypt_with_aad(&factor.authkek_under_dek, &[])
            else {
                continue;
            };
            // Both sides are secret 64-byte auth-KEKs; compare in constant time.
            if bool::from(candidate.as_slice().ct_eq(actual.as_slice())) {
                return Ok(Some(factor.id.clone()));
            }
        }
        Ok(None)
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

    /// Sets the access policy from an expression (e.g. `pass1 or (pass2 and fido2)`),
    /// re-distributing the DEK across the new tree. Recovers every factor's
    /// auth-KEK from the DEK, so only an unlocked vault is required.
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

    /// Each enrolled factor's id paired with its kind (for display).
    #[must_use]
    pub fn factor_kinds(&self) -> Vec<(String, FactorKind)> {
        self.factors
            .iter()
            .map(|f| (f.id.clone(), f.kind.clone()))
            .collect()
    }

    /// The vault header (factors + policy) — the locked, serializable projection
    /// of this vault, written ahead of the encrypted payload.
    #[must_use]
    pub fn header(&self) -> VaultHeader {
        VaultHeader {
            factors: self.factors.clone(),
            policy: self.policy.clone(),
        }
    }

    /// Encrypts the vault payload under the DEK with the envelope `version`,
    /// binding `aad` (the serialized keyslot header, or `&[]`) into the
    /// authentication tag. The container layer resolves `version` from the file
    /// format and passes the header here so the policy/factor table is bound to
    /// the ciphertext — see [`FileContainerV8`](crate::container::FileContainerV8).
    pub fn encrypt_payload(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        version: CypherVersion,
    ) -> Result<Vec<u8>> {
        cypher_from_material(&self.dek, version).encrypt_with_aad(plaintext, aad)
    }

    /// Decrypts the vault payload under the DEK with the envelope `version`,
    /// requiring `aad` to match the associated data bound at encryption — so a
    /// tampered or downgraded keyslot header fails here rather than yielding the
    /// payload.
    pub fn decrypt_payload(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        version: CypherVersion,
    ) -> Result<Zeroizing<Vec<u8>>> {
        cypher_from_material(&self.dek, version).decrypt_with_aad(ciphertext, aad)
    }

    /// A `Cypher` keyed by the DEK, for encrypting/decrypting individual stored
    /// values — the role the password-derived key played in a plain vault.
    #[must_use]
    pub fn cypher(&self) -> Cypher {
        Cypher::new(EncryptionKey::from_key_material(
            &self.dek,
            CypherVersion::default(),
        ))
    }

    /// Recovers every factor's auth-KEK from the DEK (for re-distribution).
    fn recover_all_authkeks(&self) -> Result<HashMap<String, KeyMaterial>> {
        let mut authkeks = HashMap::new();
        for factor in &self.factors {
            let bytes = self
                .dek_cypher()
                .decrypt_with_aad(&factor.authkek_under_dek, &[])
                .map_err(|_| anyhow!("corrupt keyslot for factor '{}'", factor.id))?;
            authkeks.insert(factor.id.clone(), to_key_material(&bytes)?);
        }
        Ok(authkeks)
    }

    /// A `Cypher` keyed by the DEK for the vault's *internal* key-wrapping — auth-KEKs
    /// stored under the DEK. Trace detection is deliberately off here (it is enforced
    /// once at the unlock entry point, not on every internal wrap), which is why this
    /// differs from [`cypher`](Self::cypher), the trace-checked key for stored data.
    fn dek_cypher(&self) -> Cypher {
        cypher_from_material(&self.dek, CypherVersion::default())
    }
}

/// An incremental unlock of a policy vault.
///
/// Present factor secrets one at a time — without saying which factor each
/// belongs to — until the policy is satisfied, then reconstruct the vault. Built
/// from on-disk [`VaultHeader`]; a caller drives it from a prompt loop.
pub struct UnlockSession {
    factors: Vec<Factor>,
    policy: PolicyNode,
    authkeks: HashMap<String, KeyMaterial>,
}

impl UnlockSession {
    #[must_use]
    pub fn new(header: VaultHeader) -> Self {
        Self {
            factors: header.factors,
            policy: header.policy,
            authkeks: HashMap::new(),
        }
    }

    fn satisfied_ids(&self) -> HashSet<String> {
        self.authkeks.keys().cloned().collect()
    }

    /// Whether the factors gathered so far satisfy the unlock policy.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.policy.is_satisfied_by(&self.satisfied_ids())
    }

    /// Whether the policy is satisfiable by password factors alone — i.e. it can be
    /// unlocked without presenting any FIDO2 security key.
    #[must_use]
    pub fn satisfiable_by_passwords(&self) -> bool {
        let passwords: HashSet<String> = self
            .factors
            .iter()
            .filter(|f| matches!(f.kind, FactorKind::Password { .. }))
            .map(|f| f.id.clone())
            .collect();
        self.policy.is_satisfied_by(&passwords)
    }

    /// The still-unsatisfied factors, each id paired with its kind — so a caller can
    /// see which factor *types* remain (and read a pending FIDO2 factor's device
    /// parameters) and prompt only for those.
    #[must_use]
    pub fn pending_factor_kinds(&self) -> Vec<(String, FactorKind)> {
        self.factors
            .iter()
            .filter(|f| !self.authkeks.contains_key(&f.id))
            .map(|f| (f.id.clone(), f.kind.clone()))
            .collect()
    }

    /// Tries `password` against the not-yet-satisfied password factors and, on the
    /// first match, records its auth-KEK and returns the factor id. Each factor
    /// has a distinct password (enforced at enroll), so one match is conclusive —
    /// no need to try the rest.
    pub fn try_password(&mut self, password: &str) -> Result<Option<String>> {
        let candidates: Vec<(String, FactorKind)> = self
            .factors
            .iter()
            .filter(|f| {
                matches!(f.kind, FactorKind::Password { .. }) && !self.authkeks.contains_key(&f.id)
            })
            .map(|f| (f.id.clone(), f.kind.clone()))
            .collect();

        for (id, kind) in candidates {
            let authkek = password_kek(password, &kind)?;
            let verified = self
                .policy
                .leaves()
                .find(|leaf| leaf.factor == id)
                .is_some_and(|leaf| {
                    cypher_from_material(&authkek, CypherVersion::default())
                        .decrypt_with_aad(&leaf.wrapped_share, &[])
                        .is_ok()
                });
            if verified {
                self.authkeks.insert(id.clone(), authkek);
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Tries a FIDO2 `hmac-secret` output against the not-yet-satisfied FIDO2
    /// factors. The auth-KEK depends only on the secret, so it is derived once and
    /// matched against each FIDO2 leaf; on the first whose wrapped share
    /// authenticates, records it and returns the factor id. Mirrors
    /// [`try_password`](Self::try_password); the caller obtains the secret from the
    /// authenticator (see `rcypher::fido2`).
    pub fn try_fido2_secret(
        &mut self,
        raw_hmac_secret: &HmacSecretBytes,
    ) -> Result<Option<String>> {
        let kek = fido2_kek(raw_hmac_secret)?;
        let candidates: Vec<String> = self
            .factors
            .iter()
            .filter(|f| {
                matches!(f.kind, FactorKind::Fido2 { .. }) && !self.authkeks.contains_key(&f.id)
            })
            .map(|f| f.id.clone())
            .collect();

        for id in candidates {
            let verified = self
                .policy
                .leaves()
                .find(|leaf| leaf.factor == id)
                .is_some_and(|leaf| {
                    cypher_from_material(&kek, CypherVersion::default())
                        .decrypt_with_aad(&leaf.wrapped_share, &[])
                        .is_ok()
                });
            if verified {
                self.authkeks.insert(id.clone(), kek);
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// The unlock policy as a canonical expression (a prompt hint shown before any
    /// factor is supplied).
    #[must_use]
    pub fn policy_expr(&self) -> String {
        render_policy(&self.policy)
    }

    /// Reconstructs the data-encryption key from the gathered factors and returns
    /// the unlocked vault. Errors if the policy is not yet satisfied.
    pub fn finish(self) -> Result<PolicyVault> {
        // For each leaf in canonical order, unwrap its share if we hold the factor's
        // auth-KEK (and it authenticates), else `None` — exactly what `reconstruct`
        // consumes.
        let provided: Vec<Option<Share>> = self
            .policy
            .leaves()
            .map(|leaf| {
                self.authkeks.get(&leaf.factor).and_then(|kek| {
                    cypher_from_material(kek, CypherVersion::default())
                        .decrypt_with_aad(&leaf.wrapped_share, &[])
                        .ok()
                })
            })
            .collect();
        let dek_bytes = reconstruct(&self.policy, &provided)
            .ok_or_else(|| anyhow!("the provided factors do not satisfy the unlock policy"))?;
        let dek = to_key_material(&dek_bytes)?;
        Ok(PolicyVault {
            factors: self.factors,
            policy: self.policy,
            dek,
        })
    }
}

/// Distributes `dek` across `template` and wraps each leaf's share under its
/// factor's auth-KEK, returning the policy tree with shares filled in. Leaves are
/// visited in [`PolicyNode::leaves`] order, the same order `distribute` produced
/// the shares in.
fn distribute_and_wrap(
    template: &PolicyNode,
    dek: &KeyMaterialBytes,
    authkeks: &HashMap<String, KeyMaterial>,
) -> Result<PolicyNode> {
    let shares = distribute(dek, template)?;
    let mut policy = template.clone();
    let mut shares = shares.iter();
    for leaf in policy.leaves_mut() {
        let share = shares
            .next()
            .ok_or_else(|| anyhow!("internal error: share/leaf count mismatch"))?;
        let kek = authkeks
            .get(&leaf.factor)
            .ok_or_else(|| anyhow!("no key material for factor '{}'", leaf.factor))?;
        leaf.wrapped_share =
            cypher_from_material(kek, CypherVersion::default()).encrypt_with_aad(share, &[])?;
    }
    Ok(policy)
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
    if !id.chars().all(is_factor_id_char) {
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
/// too similar to it. Creating a vault and enrolling a factor apply the same check.
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

    /// Round-trips a vault through its serialized header, then unlocks it by
    /// presenting each provided password to an [`UnlockSession`] (the factor id is
    /// just a label here — the session matches the password against the factors).
    fn reopen(vault: &PolicyVault, provided: &[(&str, &str)]) -> Result<PolicyVault> {
        let mut session = UnlockSession::new(vault.header());
        for (_id, password) in provided {
            session.try_password(password)?;
        }
        session.finish()
    }

    #[test]
    fn single_password_unlock_and_payload() {
        let vault = PolicyVault::create("p1", "hunter2", &params()).unwrap();
        let blob = vault
            .encrypt_payload(b"top secret", &[], CypherVersion::default())
            .unwrap();

        let reopened = reopen(&vault, &[("p1", "hunter2")]).unwrap();
        assert_eq!(
            reopened
                .decrypt_payload(&blob, &[], CypherVersion::default())
                .unwrap()
                .as_slice(),
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
        vault.enroll_password("fido2", "two", &params()).unwrap();
        vault.set_policy("p1 or fido2").unwrap();
        let blob = vault
            .encrypt_payload(b"data", &[], CypherVersion::default())
            .unwrap();

        let via_p1 = reopen(&vault, &[("p1", "one")]).unwrap();
        let via_fido2 = reopen(&vault, &[("fido2", "two")]).unwrap();
        assert_eq!(
            via_p1
                .decrypt_payload(&blob, &[], CypherVersion::default())
                .unwrap()
                .as_slice(),
            b"data"
        );
        assert_eq!(
            via_fido2
                .decrypt_payload(&blob, &[], CypherVersion::default())
                .unwrap()
                .as_slice(),
            b"data"
        );
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
    fn rejects_duplicate_password_on_enroll() {
        let mut vault = PolicyVault::create("p1", "alpha-secret-1", &params()).unwrap();
        // The same password as an existing factor is refused.
        assert!(
            vault
                .enroll_password("p2", "alpha-secret-1", &params())
                .is_err()
        );
        // A distinct password enrolls fine.
        assert!(
            vault
                .enroll_password("p2", "bravo-secret-2", &params())
                .is_ok()
        );
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

    // A fixed `hmac-secret` standing in for an authenticator's output, so the FIDO2
    // factor's pure key path is exercised without hardware.
    fn fido2_secret(byte: u8) -> crate::constants::HmacSecretBytes {
        [byte; crate::constants::HMAC_SECRET_LEN]
    }

    fn enroll_fido2(vault: &mut PolicyVault, id: &str, secret: &crate::constants::HmacSecretBytes) {
        vault
            .enroll_fido2(
                id,
                vec![1, 2, 3],
                "rcypher".into(),
                SaltBytes::default(),
                false,
                secret,
            )
            .unwrap();
    }

    #[test]
    fn fido2_factor_unlocks_via_or_branch() {
        let secret = fido2_secret(42);
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        enroll_fido2(&mut vault, "key", &secret);
        vault.set_policy("p1 or key").unwrap();
        let blob = vault
            .encrypt_payload(b"data", &[], CypherVersion::default())
            .unwrap();

        // The FIDO2 secret alone reconstructs the DEK (OR replicates it).
        let mut session = UnlockSession::new(vault.header());
        assert_eq!(
            session.try_fido2_secret(&secret).unwrap().as_deref(),
            Some("key")
        );
        let reopened = session.finish().unwrap();
        assert_eq!(
            reopened
                .decrypt_payload(&blob, &[], CypherVersion::default())
                .unwrap()
                .as_slice(),
            b"data"
        );

        // A wrong secret matches no factor.
        let mut session = UnlockSession::new(vault.header());
        assert_eq!(session.try_fido2_secret(&fido2_secret(43)).unwrap(), None);
    }

    #[test]
    fn and_policy_needs_both_password_and_fido2() {
        let secret = fido2_secret(7);
        let mut vault = PolicyVault::create("p1", "one", &params()).unwrap();
        enroll_fido2(&mut vault, "key", &secret);
        vault.set_policy("p1 and key").unwrap();

        // Either alone is insufficient; together they complete the policy.
        let mut session = UnlockSession::new(vault.header());
        session.try_password("one").unwrap();
        assert!(!session.is_complete());
        session.try_fido2_secret(&secret).unwrap();
        assert!(session.is_complete());
        assert!(session.finish().is_ok());

        // The FIDO2 factor makes the store not satisfiable by passwords alone.
        let session = UnlockSession::new(vault.header());
        assert!(!session.satisfiable_by_passwords());
    }
}
