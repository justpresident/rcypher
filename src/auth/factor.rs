//! Factors: the data model for an enrolled factor, and turning a satisfied factor
//! into 64-byte key material that wraps/unwraps its policy leaves' shares.
//!
//! A password factor derives its key material with Argon2id (memory-hard, since
//! the input is a human password). The FIDO2 yubikey factor is not yet
//! implemented; its key material will come from the authenticator's
//! `hmac-secret` output.

use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use rand::TryRngCore;

use crate::constants::SaltBytes;
use crate::crypto::{Argon2Params, KeyMaterial, derive_key_material};

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
    Yubikey {
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
    },
}

/// A named, enrolled factor and its derivation parameters.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Factor {
    pub id: String,
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
        let yk = FactorKind::Yubikey {
            credential_id: vec![1],
            rp_id: "rcypher".into(),
            salt: SaltBytes::default(),
            require_pin: false,
        };
        assert!(password_kek("x", &yk).is_err());
    }
}
