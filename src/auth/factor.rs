//! Factors: the data model for an enrolled factor, and turning a satisfied factor
//! into 64-byte key material that wraps/unwraps its policy leaves' shares.
//!
//! A password factor derives its key material with Argon2id (memory-hard, since
//! the input is a human password). A FIDO2 security-key factor derives it by
//! HKDF-expanding the authenticator's `hmac-secret` output — already high-entropy,
//! so no memory-hard work is needed.

use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use rand::TryRngCore;

use crate::constants::{HmacSecretBytes, SaltBytes};
use crate::crypto::{Argon2Params, KeyMaterial, derive_key_material, expand_key_material};

/// Domain-separation label binding a FIDO2 factor's auth-KEK to its purpose (the
/// HKDF `info`); version it so a future scheme change is unambiguous.
const FIDO2_AUTHKEK_INFO: &[u8] = b"rcypher fido2 auth-kek v1";

/// Key-derivation parameters for one enrolled factor.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub enum FactorKind {
    /// A passphrase factor: Argon2id over the password and a per-factor salt.
    Password {
        salt: SaltBytes,
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    },
    /// A FIDO2 security-key factor via the `hmac-secret` extension. `require_pin`
    /// asks the authenticator for user verification (a PIN) in addition to the
    /// touch that is always required.
    Fido2 {
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
    },
}

/// A factor's opaque identifier: its human **name encrypted under the DEK**, kept
/// as raw bytes.
///
/// It is the only per-factor value in the cleartext header and the link between a
/// [`Factor`] and the policy leaves that reference it. Being ciphertext it reveals
/// nothing about the name at rest; the unlocked vault decrypts it back to the name.
/// The policy treats it purely as an opaque identity token (equality/hash only),
/// so the access tree stays agnostic to what a factor is.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, Hash)]
pub struct FactorId(pub Vec<u8>);

impl FactorId {
    /// A lowercase-hex rendering of the opaque id — for diagnostics, and as a
    /// last-resort label when the human name is unavailable (e.g. an error raised
    /// before the names have been recovered at unlock).
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.0
            .iter()
            .fold(String::with_capacity(self.0.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

/// A named, enrolled factor and its derivation parameters.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Factor {
    pub id: FactorId,
    pub kind: FactorKind,
    /// This factor's auth-KEK (the 64-byte material it derives from its password
    /// or security key) encrypted under the DEK. It lets a holder of the unlocked
    /// DEK re-derive every factor's auth-KEK — so the policy can be changed
    /// without presenting every factor again — while revealing nothing to an
    /// attacker who lacks the DEK.
    pub authkek_under_dek: Vec<u8>,
}

/// Builds the parameters for a new password factor: a fresh random salt and the
/// given Argon2 cost parameters.
pub fn new_password_kind(params: &Argon2Params) -> Result<FactorKind> {
    let mut salt = SaltBytes::default();
    rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
    Ok(FactorKind::Password {
        salt,
        memory_cost: params.memory_cost,
        time_cost: params.time_cost,
        parallelism: params.parallelism,
    })
}

/// Derives a password factor's 64-byte auth-KEK by running the crypto layer's
/// Argon2id over the password and the factor's stored salt and cost parameters.
pub fn password_kek(password: &str, kind: &FactorKind) -> Result<KeyMaterial> {
    let FactorKind::Password {
        salt,
        memory_cost,
        time_cost,
        parallelism,
    } = kind
    else {
        bail!("factor is not a password factor");
    };

    derive_key_material(
        password,
        salt,
        &Argon2Params {
            memory_cost: *memory_cost,
            time_cost: *time_cost,
            parallelism: *parallelism,
        },
    )
}

/// Derives a FIDO2 factor's 64-byte auth-KEK from the authenticator's
/// `hmac-secret` output by HKDF-expanding it (the secret is already high-entropy,
/// so no Argon2 and no extract salt — see [`expand_key_material`]). The KEK depends
/// only on the secret, so the unlock path derives it once and matches it against
/// every FIDO2 leaf, just as a password is tried against every password factor.
pub fn fido2_kek(raw_hmac_secret: &HmacSecretBytes) -> Result<KeyMaterial> {
    expand_key_material(raw_hmac_secret, FIDO2_AUTHKEK_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::KEY_MATERIAL_LEN;
    use crate::crypto::cypher_from_material;
    use crate::version::CypherVersion;

    fn insecure_kind() -> FactorKind {
        new_password_kind(&Argon2Params::insecure()).unwrap()
    }

    #[test]
    fn same_password_same_kek() {
        let kind = insecure_kind();
        let a = password_kek("hunter2", &kind).unwrap();
        let b = password_kek("hunter2", &kind).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_password_or_salt_differs() {
        let kind = insecure_kind();
        let a = password_kek("hunter2", &kind).unwrap();
        let other_pw = password_kek("hunter3", &kind).unwrap();
        assert_ne!(a.as_slice(), other_pw.as_slice());

        let other_salt = insecure_kind();
        let c = password_kek("hunter2", &other_salt).unwrap();
        assert_ne!(a.as_slice(), c.as_slice());
    }

    #[test]
    fn kek_wraps_a_share_only_for_the_right_password() {
        let kind = insecure_kind();
        let share = [9u8; KEY_MATERIAL_LEN];

        let kek = password_kek("correct", &kind).unwrap();
        let wrapped = cypher_from_material(&kek, CypherVersion::default())
            .encrypt_with_aad(&share, &[])
            .unwrap();
        assert_eq!(
            cypher_from_material(&kek, CypherVersion::default())
                .decrypt_with_aad(&wrapped, &[])
                .unwrap()
                .as_slice(),
            &share[..]
        );

        let wrong = password_kek("wrong", &kind).unwrap();
        assert!(
            cypher_from_material(&wrong, CypherVersion::default())
                .decrypt_with_aad(&wrapped, &[])
                .is_err()
        );
    }

    #[test]
    fn rejects_non_password_kind() {
        let fido2 = FactorKind::Fido2 {
            credential_id: vec![1],
            rp_id: "rcypher".into(),
            salt: SaltBytes::default(),
            require_pin: false,
        };
        assert!(password_kek("x", &fido2).is_err());
    }

    #[test]
    fn same_fido2_secret_same_kek_different_secret_differs() {
        let secret = [7u8; crate::constants::HMAC_SECRET_LEN];
        assert_eq!(
            fido2_kek(&secret).unwrap().as_slice(),
            fido2_kek(&secret).unwrap().as_slice()
        );

        let mut other = secret;
        other[0] ^= 0x01;
        assert_ne!(
            fido2_kek(&secret).unwrap().as_slice(),
            fido2_kek(&other).unwrap().as_slice()
        );
    }

    #[test]
    fn fido2_kek_wraps_a_share_only_for_the_right_secret() {
        let secret = [3u8; crate::constants::HMAC_SECRET_LEN];
        let share = [9u8; KEY_MATERIAL_LEN];

        let kek = fido2_kek(&secret).unwrap();
        let wrapped = cypher_from_material(&kek, CypherVersion::default())
            .encrypt_with_aad(&share, &[])
            .unwrap();
        assert_eq!(
            cypher_from_material(&kek, CypherVersion::default())
                .decrypt_with_aad(&wrapped, &[])
                .unwrap()
                .as_slice(),
            &share[..]
        );

        let mut wrong_secret = secret;
        wrong_secret[0] ^= 0x01;
        let wrong = fido2_kek(&wrong_secret).unwrap();
        assert!(
            cypher_from_material(&wrong, CypherVersion::default())
                .decrypt_with_aad(&wrapped, &[])
                .is_err()
        );
    }
}
