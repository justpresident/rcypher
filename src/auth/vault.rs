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

use super::factor::{Factor, FactorId, FactorKind, fido2_kek, new_password_kind, password_kek};
use super::header::VaultHeader;
use super::policy::{
    Leaf, PolicyExpr, PolicyNode, Share, distribute, is_factor_name_char, parse_policy,
    reconstruct, render_policy, validate_factors,
};
use crate::constants::{HmacSecretBytes, KEY_MATERIAL_LEN, KeyMaterialBytes, SaltBytes};
use crate::crypto::{
    Argon2Params, Cypher, EncryptionKey, KeyMaterial, cypher_from_material, generate_key_material,
};
use crate::version::CypherVersion;

/// An unlocked policy vault: the enrolled factors, the access policy (leaves
/// carrying wrapped shares), and the recovered data-encryption key.
///
/// A factor's [`FactorId`] (the link between [`Factor`] and the policy [`Leaf`]s,
/// and the only per-factor value visible in the cleartext header) is the factor's
/// human **name encrypted under the DEK**, so the name leaks nothing at rest. With
/// the DEK in hand the vault decrypts an id back to its name on demand (see
/// [`name_for_id`](Self::name_for_id)) for display and management — names are a
/// projection of `factors` + the DEK, not separate state to keep in sync.
pub struct PolicyVault {
    factors: Vec<Factor>,
    policy: PolicyNode,
    dek: KeyMaterial,
}

impl PolicyVault {
    /// Creates a new vault protected by a single password factor; the initial
    /// policy is just that factor. Enroll more factors and refine the policy with
    /// [`PolicyVault::enroll_password`] and [`PolicyVault::set_policy`].
    pub fn create_with_password(name: &str, password: &str, params: &Argon2Params) -> Result<Self> {
        check_factor_password(name, password)?;
        let dek = generate_key_material()?;
        let dek_cypher = cypher_from_material(&dek, CypherVersion::default());

        let kind = new_password_kind(params)?;
        let authkek = password_kek(password, &kind)?;
        let id = encrypt_factor_name(&dek_cypher, name)?;
        let factor = Factor {
            id: id.clone(),
            kind,
            authkek_under_dek: dek_cypher.encrypt_with_aad(authkek.as_slice(), &[])?,
        };

        let template = PolicyNode::Leaf(Leaf {
            factor: id.clone(),
            wrapped_share: Vec::new(),
        });
        let authkeks = HashMap::from([(id, authkek)]);
        let policy = distribute_and_wrap(&template, &dek, &authkeks)?;

        Ok(Self {
            factors: vec![factor],
            policy,
            dek,
        })
    }

    /// Creates a new vault protected by a single FIDO2 factor; the initial policy is
    /// just that factor. The caller supplies a freshly enrolled credential and its
    /// current `hmac-secret` output (both from [`crate::fido2`]).
    ///
    /// The password-free counterpart to
    /// [`create_with_password`](Self::create_with_password); add more factors and
    /// refine the policy with [`enroll_password`](Self::enroll_password) /
    /// [`enroll_fido2`](Self::enroll_fido2) and [`set_policy`](Self::set_policy).
    pub fn create_with_fido2(
        name: &str,
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
        raw_hmac_secret: &HmacSecretBytes,
    ) -> Result<Self> {
        validate_factor_name(name)?;
        let dek = generate_key_material()?;
        let dek_cypher = cypher_from_material(&dek, CypherVersion::default());

        let authkek = fido2_kek(raw_hmac_secret)?;
        let id = encrypt_factor_name(&dek_cypher, name)?;
        let factor = Factor {
            id: id.clone(),
            kind: FactorKind::Fido2 {
                credential_id,
                rp_id,
                salt,
                require_pin,
            },
            authkek_under_dek: dek_cypher.encrypt_with_aad(authkek.as_slice(), &[])?,
        };

        let template = PolicyNode::Leaf(Leaf {
            factor: id.clone(),
            wrapped_share: Vec::new(),
        });
        let authkeks = HashMap::from([(id, authkek)]);
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
        name: &str,
        password: &str,
        params: &Argon2Params,
    ) -> Result<()> {
        check_factor_password(name, password)?;
        if self.id_for_name(name).is_some() {
            bail!("a factor named '{name}' already exists");
        }
        if let Some(existing) = self.factor_matching_password(password)? {
            bail!(
                "that password is already in use by factor '{existing}'; each factor needs a \
                 distinct password"
            );
        }
        let kind = new_password_kind(params)?;
        let authkek = password_kek(password, &kind)?;
        let id = self.encrypt_name(name)?;
        self.factors.push(Factor {
            id,
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
        name: &str,
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
        raw_hmac_secret: &HmacSecretBytes,
    ) -> Result<()> {
        validate_factor_name(name)?;
        if self.id_for_name(name).is_some() {
            bail!("a factor named '{name}' already exists");
        }
        let authkek = fido2_kek(raw_hmac_secret)?;
        let id = self.encrypt_name(name)?;
        self.factors.push(Factor {
            id,
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

    /// The name of an enrolled password factor whose password equals `password`, if
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
                return Ok(Some(self.name_for_id(&factor.id)));
            }
        }
        Ok(None)
    }

    /// Removes a factor by name. Fails if the current policy still references it.
    pub fn remove_factor(&mut self, name: &str) -> Result<()> {
        let Some(id) = self.id_for_name(name) else {
            bail!("no factor named '{name}'");
        };
        if self.policy.leaves().any(|leaf| leaf.factor == id) {
            bail!("factor '{name}' is still used by the policy; change the policy first");
        }
        self.factors.retain(|f| f.id != id);
        Ok(())
    }

    /// Sets the access policy from an expression (e.g. `pass1 or (pass2 and fido2)`),
    /// rotating the DEK and re-distributing the new key across the new tree.
    ///
    /// Rotation is required for revocation: without it, an older snapshot protected
    /// by a weaker policy would reveal the same DEK used by all future snapshots.
    /// The container facade uses [`rotated_with_policy`](Self::rotated_with_policy)
    /// directly so it can re-key its payload before committing the new vault.
    #[cfg(test)]
    pub fn set_policy(&mut self, expr: &str) -> Result<()> {
        *self = self.rotated_with_policy(expr)?;
        Ok(())
    }

    /// Builds the vault produced by changing to `expr`, with a fresh DEK.
    ///
    /// The current vault is left untouched on every error. Factor names and
    /// auth-KEK bridges are re-encrypted under the new DEK, then fresh policy
    /// shares are distributed under the new opaque factor ids.
    pub(crate) fn rotated_with_policy(&self, expr: &str) -> Result<Self> {
        let parsed = parse_policy(expr)?;
        let names: Vec<String> = self
            .factors
            .iter()
            .map(|f| decrypt_factor_name(&self.dek_cypher(), &f.id))
            .collect::<Result<_>>()?;
        let known: HashSet<String> = names.iter().cloned().collect();
        validate_factors(&parsed, &known)?;

        let mut old_authkeks = self.recover_all_authkeks()?;
        let dek = generate_key_material()?;
        let dek_cypher = cypher_from_material(&dek, CypherVersion::default());
        let mut factors = Vec::with_capacity(self.factors.len());
        let mut ids_by_name = HashMap::with_capacity(self.factors.len());
        let mut authkeks = HashMap::with_capacity(self.factors.len());

        for (factor, name) in self.factors.iter().zip(names) {
            let authkek = old_authkeks
                .remove(&factor.id)
                .ok_or_else(|| anyhow!("missing auth-KEK for factor '{name}'"))?;
            let id = encrypt_factor_name(&dek_cypher, &name)?;
            factors.push(Factor {
                id: id.clone(),
                kind: factor.kind.clone(),
                authkek_under_dek: dek_cypher.encrypt_with_aad(authkek.as_slice(), &[])?,
            });
            ids_by_name.insert(name, id.clone());
            authkeks.insert(id, authkek);
        }

        // The parser produced name leaves; resolve them to the freshly encrypted
        // factor ids before sharing the new DEK across the policy.
        let template = parsed.resolve(&|name| {
            ids_by_name
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("unknown factor '{name}'"))
        })?;
        let policy = distribute_and_wrap(&template, &dek, &authkeks)?;

        Ok(Self {
            factors,
            policy,
            dek,
        })
    }

    /// The current policy as a canonical, human-readable expression (names restored).
    #[must_use]
    pub fn policy_expr(&self) -> String {
        render_policy(&self.named_expr())
    }

    /// The names of all enrolled factors.
    #[must_use]
    pub fn factor_names(&self) -> Vec<String> {
        self.factors
            .iter()
            .map(|f| self.name_for_id(&f.id))
            .collect()
    }

    /// Each enrolled factor's name paired with its kind (for display).
    #[must_use]
    pub fn factor_kinds(&self) -> Vec<(String, FactorKind)> {
        self.factors
            .iter()
            .map(|f| (self.name_for_id(&f.id), f.kind.clone()))
            .collect()
    }

    /// The opaque id of the factor named `name`, if enrolled — found by decrypting
    /// each factor's id and matching the name.
    fn id_for_name(&self, name: &str) -> Option<FactorId> {
        self.factors
            .iter()
            .find(|f| self.name_for_id(&f.id) == name)
            .map(|f| f.id.clone())
    }

    /// The human name for an opaque factor id: decrypts it under the DEK. Falls back
    /// to the id's hex on a decryption failure, which a validly unlocked vault never
    /// hits — every id is the ciphertext of its name under this DEK, and the header
    /// (factor ids included) is authenticated against the payload at unlock.
    fn name_for_id(&self, id: &FactorId) -> String {
        decrypt_factor_name(&self.dek_cypher(), id).unwrap_or_else(|_| id.to_hex())
    }

    /// The policy as a name-keyed [`PolicyExpr`] (each leaf's opaque id mapped back
    /// to its human name), for rendering.
    fn named_expr(&self) -> PolicyExpr {
        self.policy.to_expr(&|id| self.name_for_id(id))
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
    fn recover_all_authkeks(&self) -> Result<HashMap<FactorId, KeyMaterial>> {
        let mut authkeks = HashMap::new();
        for factor in &self.factors {
            let bytes = self
                .dek_cypher()
                .decrypt_with_aad(&factor.authkek_under_dek, &[])
                .map_err(|_| {
                    anyhow!(
                        "corrupt keyslot for factor '{}'",
                        self.name_for_id(&factor.id)
                    )
                })?;
            authkeks.insert(factor.id.clone(), to_key_material(&bytes)?);
        }
        Ok(authkeks)
    }

    /// Mints a factor's opaque id from its human `name`: the name encrypted under
    /// the DEK, so the name is absent from the cleartext header.
    fn encrypt_name(&self, name: &str) -> Result<FactorId> {
        encrypt_factor_name(&self.dek_cypher(), name)
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
    authkeks: HashMap<FactorId, KeyMaterial>,
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

    fn satisfied_ids(&self) -> HashSet<FactorId> {
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
        let passwords: HashSet<FactorId> = self
            .factors
            .iter()
            .filter(|f| matches!(f.kind, FactorKind::Password { .. }))
            .map(|f| f.id.clone())
            .collect();
        self.policy.is_satisfied_by(&passwords)
    }

    /// The kinds of the still-unsatisfied factors — so a caller can see which factor
    /// *types* remain (and read a pending FIDO2 factor's device parameters, carried
    /// in [`FactorKind::Fido2`]) and prompt only for those. The factor names stay
    /// hidden until unlock, so no id is exposed here.
    #[must_use]
    pub fn pending_factor_kinds(&self) -> Vec<FactorKind> {
        self.factors
            .iter()
            .filter(|f| !self.authkeks.contains_key(&f.id))
            .map(|f| f.kind.clone())
            .collect()
    }

    /// Tries `password` against the not-yet-satisfied password factors, recording its
    /// auth-KEK on the first match. Returns whether a factor matched. Each factor has
    /// a distinct password (enforced at enroll), so one match is conclusive — no need
    /// to try the rest. The matched factor's name stays hidden until unlock.
    pub fn try_password(&mut self, password: &str) -> Result<bool> {
        let candidates: Vec<(FactorId, FactorKind)> = self
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
                self.authkeks.insert(id, authkek);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Tries a FIDO2 `hmac-secret` output against the not-yet-satisfied FIDO2
    /// factors. The auth-KEK depends only on the secret, so it is derived once and
    /// matched against each FIDO2 leaf; on the first whose wrapped share
    /// authenticates, records it and returns `true`. Mirrors
    /// [`try_password`](Self::try_password); the caller obtains the secret from the
    /// authenticator (see `rcypher::fido2`).
    pub fn try_fido2_secret(&mut self, raw_hmac_secret: &HmacSecretBytes) -> Result<bool> {
        let kek = fido2_kek(raw_hmac_secret)?;
        let candidates: Vec<FactorId> = self
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
                self.authkeks.insert(id, kek);
                return Ok(true);
            }
        }
        Ok(false)
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
        // Names are decrypted on demand from each factor's id with the DEK (see
        // `PolicyVault::name_for_id`), so there is nothing to recover up front here.
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
    authkeks: &HashMap<FactorId, KeyMaterial>,
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
            .ok_or_else(|| anyhow!("no key material for factor '{}'", leaf.factor.to_hex()))?;
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

/// Mints a factor's opaque [`FactorId`]: its human `name` encrypted under the DEK
/// (via a DEK-keyed `cypher`) as raw bytes, so the name is absent from the
/// cleartext header. Encryption is non-deterministic, so the id is minted once at
/// enrolment and reused thereafter.
fn encrypt_factor_name(cypher: &Cypher, name: &str) -> Result<FactorId> {
    Ok(FactorId(cypher.encrypt_with_aad(name.as_bytes(), &[])?))
}

/// Recovers a factor's human name from its opaque [`FactorId`] — the inverse of
/// [`encrypt_factor_name`], using the same DEK-keyed `cypher`.
fn decrypt_factor_name(cypher: &Cypher, id: &FactorId) -> Result<String> {
    let plaintext = cypher.decrypt_with_aad(&id.0, &[])?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| anyhow!("corrupt factor name in keyslot"))
}

fn validate_factor_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a factor name cannot be empty");
    }
    if name.eq_ignore_ascii_case("and") || name.eq_ignore_ascii_case("or") {
        bail!("'{name}' is a reserved keyword and cannot be a factor name");
    }
    if !name.chars().all(is_factor_name_char) {
        bail!("factor name '{name}' may contain only letters, digits, '-' and '_'");
    }
    Ok(())
}

/// Guards against a password that is too similar to the factor *name*.
///
/// A password equal or close to the factor name is almost always a mistake — the
/// name typed into the password slot and then repeated — and a weak, guessable
/// choice. Require the password to be at least twice as long as any prefix it
/// shares with the name, which rejects that mix-up. Comparison is case-insensitive.
/// (The name itself is now encrypted in the store, so this is about the password's
/// quality, not a plaintext-name leak.)
/// Validates that `password` is acceptable for a factor named `name`, independent
/// of any vault — so a caller can check it before doing more work (e.g. a
/// strength prompt). The name must be well-formed and the password must not be
/// too similar to it. Creating a vault and enrolling a factor apply the same check.
pub fn check_factor_password(name: &str, password: &str) -> Result<()> {
    validate_factor_name(name)?;
    reject_password_resembling_name(name, password)
}

fn reject_password_resembling_name(name: &str, password: &str) -> Result<()> {
    let shared_prefix = name
        .chars()
        .flat_map(char::to_lowercase)
        .zip(password.chars().flat_map(char::to_lowercase))
        .take_while(|(a, b)| a == b)
        .count();
    if password.chars().count() < 2 * shared_prefix {
        bail!(
            "the password is too similar to the factor name '{name}': they share a \
             {shared_prefix}-character prefix. A password close to the factor name is a weak, \
             guessable choice — use one at least twice as long as any shared prefix (or pick a \
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
    /// presenting each provided password to an [`UnlockSession`] (the factor name is
    /// just a label here — the session matches the password against the factors).
    fn reopen(vault: &PolicyVault, provided: &[(&str, &str)]) -> Result<PolicyVault> {
        let mut session = UnlockSession::new(vault.header());
        for (_name, password) in provided {
            session.try_password(password)?;
        }
        session.finish()
    }

    #[test]
    fn single_password_unlock_and_payload() {
        let vault = PolicyVault::create_with_password("p1", "hunter2", &params()).unwrap();
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
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
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
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
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
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.set_policy("p1 and p2").unwrap();

        assert!(reopen(&vault, &[("p1", "one")]).is_err()); // one alone no longer enough
        assert!(reopen(&vault, &[("p1", "one"), ("p2", "two")]).is_ok());
    }

    #[test]
    fn remove_factor_rules() {
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
        vault.enroll_password("p2", "two", &params()).unwrap();
        vault.set_policy("p1 or p2").unwrap();

        assert!(vault.remove_factor("p2").is_err()); // still referenced
        vault.set_policy("p1").unwrap();
        assert!(vault.remove_factor("p2").is_ok());
        assert!(vault.remove_factor("nope").is_err());
    }

    #[test]
    fn rejects_bad_factor_names_and_dupes() {
        assert!(PolicyVault::create_with_password("and", "x", &params()).is_err());
        assert!(PolicyVault::create_with_password("a b", "x", &params()).is_err());
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
        assert!(vault.enroll_password("p1", "x", &params()).is_err());
        assert!(vault.set_policy("p1 or missing").is_err()); // unknown factor
    }

    #[test]
    fn rejects_duplicate_password_on_enroll() {
        let mut vault =
            PolicyVault::create_with_password("p1", "alpha-secret-1", &params()).unwrap();
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
        assert!(PolicyVault::create_with_password("hunter2", "hunter2", &params()).is_err());

        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
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

    fn enroll_fido2(
        vault: &mut PolicyVault,
        name: &str,
        secret: &crate::constants::HmacSecretBytes,
    ) {
        vault
            .enroll_fido2(
                name,
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
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
        enroll_fido2(&mut vault, "key", &secret);
        vault.set_policy("p1 or key").unwrap();
        let blob = vault
            .encrypt_payload(b"data", &[], CypherVersion::default())
            .unwrap();

        // The FIDO2 secret alone reconstructs the DEK (OR replicates it). The match
        // is reported generically (true/false) — the factor name stays hidden.
        let mut session = UnlockSession::new(vault.header());
        assert!(session.try_fido2_secret(&secret).unwrap());
        let reopened = session.finish().unwrap();
        assert_eq!(
            reopened
                .decrypt_payload(&blob, &[], CypherVersion::default())
                .unwrap()
                .as_slice(),
            b"data"
        );
        // After unlock the human name is restored.
        assert!(reopened.factor_names().contains(&"key".to_string()));

        // A wrong secret matches no factor.
        let mut session = UnlockSession::new(vault.header());
        assert!(!session.try_fido2_secret(&fido2_secret(43)).unwrap());
    }

    #[test]
    fn create_with_fido2_bootstraps_a_key_only_vault() {
        let secret = fido2_secret(9);
        let vault = PolicyVault::create_with_fido2(
            "key",
            vec![7, 7, 7],
            "rcypher".into(),
            SaltBytes::default(),
            false,
            &secret,
        )
        .unwrap();
        // The sole factor is the key; the initial policy is just that key.
        assert_eq!(vault.policy_expr(), "key");

        let blob = vault
            .encrypt_payload(b"data", &[], CypherVersion::default())
            .unwrap();

        // The key's secret alone reconstructs the fresh DEK.
        let mut session = UnlockSession::new(vault.header());
        assert!(session.try_fido2_secret(&secret).unwrap());
        let reopened = session.finish().unwrap();
        assert_eq!(
            reopened
                .decrypt_payload(&blob, &[], CypherVersion::default())
                .unwrap()
                .as_slice(),
            b"data"
        );
        assert!(reopened.factor_names().contains(&"key".to_string()));

        // A different secret matches nothing.
        let mut session = UnlockSession::new(vault.header());
        assert!(!session.try_fido2_secret(&fido2_secret(10)).unwrap());
    }

    #[test]
    fn and_policy_needs_both_password_and_fido2() {
        let secret = fido2_secret(7);
        let mut vault = PolicyVault::create_with_password("p1", "one", &params()).unwrap();
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

    #[test]
    fn factor_names_are_encrypted_in_the_header() {
        // A distinctive name + a recognizable substring inside the policy.
        let mut vault =
            PolicyVault::create_with_password("secret-bank", "a-strong-passphrase", &params())
                .unwrap();
        vault
            .enroll_password("recovery-stash", "another-strong-one", &params())
            .unwrap();
        vault.set_policy("secret-bank or recovery-stash").unwrap();

        let header = vault.header();
        let bytes = bincode::encode_to_vec(&header, bincode::config::standard()).unwrap();
        for name in [b"secret-bank".as_slice(), b"recovery-stash".as_slice()] {
            assert!(
                !bytes.windows(name.len()).any(|w| w == name),
                "factor name leaked into the cleartext header"
            );
        }

        // After unlock the human names are restored (id ↔ name round-trips).
        let reopened = reopen(&vault, &[("secret-bank", "a-strong-passphrase")]).unwrap();
        let ids = reopened.factor_names();
        assert!(ids.contains(&"secret-bank".to_string()));
        assert!(ids.contains(&"recovery-stash".to_string()));
        assert_eq!(reopened.policy_expr(), "secret-bank or recovery-stash");
    }
}
