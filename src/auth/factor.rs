//! Factor key derivation — turning a satisfied factor into 64-byte key material
//! that wraps/unwraps its policy leaves' shares.
//!
//! A password factor derives its key material with Argon2id (memory-hard, since
//! the input is a human password). The FIDO2 yubikey factor lands in a later
//! task; its key material comes from the authenticator's `hmac-secret` output.

use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use zeroize::Zeroizing;

use super::format::FactorKind;
use super::keyslot::KeyMaterial;
use crate::crypto::Argon2Params;

/// Builds the parameters for a new password factor: a fresh random salt and the
/// given Argon2 cost parameters.
pub fn new_password_kind(params: &Argon2Params) -> Result<FactorKind> {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
    Ok(FactorKind::Password {
        salt,
        memory_cost: params.memory_cost,
        time_cost: params.time_cost,
        parallelism: params.parallelism,
    })
}

/// Derives a password factor's 64-byte key material (cipher key ‖ HMAC key) via
/// Argon2id over the password and the factor's stored parameters.
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

    let params = Params::new(*memory_cost, *time_cost, *parallelism, Some(64))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut material = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(password.as_bytes(), salt, material.as_mut())
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::keyslot::{unwrap_share, wrap_share};

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
        let share = [9u8; 64];

        let kek = password_kek("correct", &kind).unwrap();
        let wrapped = wrap_share(&kek, &share).unwrap();
        assert_eq!(unwrap_share(&kek, &wrapped), Some(share.to_vec()));

        let wrong = password_kek("wrong", &kind).unwrap();
        assert_eq!(unwrap_share(&wrong, &wrapped), None);
    }

    #[test]
    fn rejects_non_password_kind() {
        let yk = FactorKind::Yubikey {
            credential_id: vec![1],
            rp_id: "rcypher".into(),
            salt: [0u8; 32],
            require_pin: false,
        };
        assert!(password_kek("x", &yk).is_err());
    }
}
