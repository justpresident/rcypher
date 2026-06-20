//! The data-encryption key (DEK) and per-leaf share wrapping.
//!
//! The vault payload is encrypted under a random 64-byte DEK (cipher key ‖ HMAC
//! key). Each policy leaf's secret-share is wrapped under that leaf's factor key
//! by reusing the [`Cypher`] envelope, whose authentication tag doubles as the
//! "was this factor satisfied?" check on unwrap.

use anyhow::Result;
use rand::TryRngCore;
use zeroize::Zeroizing;

use crate::constants::{KEY_LEN, KEY_MATERIAL_LEN, KeyBytes, KeyMaterialBytes};
use crate::crypto::{Cypher, EncryptionKey};

/// Full key material: a cipher key followed by an HMAC key.
pub type KeyMaterial = Zeroizing<KeyMaterialBytes>;

/// Generates fresh random DEK material.
pub fn generate_dek() -> Result<KeyMaterial> {
    let mut dek = Zeroizing::new([0u8; KEY_MATERIAL_LEN]);
    rand::rngs::OsRng.try_fill_bytes(dek.as_mut())?;
    Ok(dek)
}

/// Builds a `Cypher` from key material, with the anti-debug check disabled — it is
/// enforced once at the unlock entry point, not per wrap.
fn cypher_from_material(material: &KeyMaterialBytes) -> Cypher {
    let mut key = KeyBytes::default();
    let mut hmac_key = KeyBytes::default();
    key.copy_from_slice(&material[..KEY_LEN]);
    hmac_key.copy_from_slice(&material[KEY_LEN..]);
    Cypher::with_trace_detection(EncryptionKey::from_key_material(key, hmac_key), false)
}

/// Encrypts the vault payload under the DEK.
pub fn encrypt_payload(dek: &KeyMaterialBytes, plaintext: &[u8]) -> Result<Vec<u8>> {
    cypher_from_material(dek).encrypt(plaintext)
}

/// Decrypts the vault payload under the DEK.
pub fn decrypt_payload(dek: &KeyMaterialBytes, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    cypher_from_material(dek).decrypt(ciphertext)
}

/// Wraps a leaf's secret-share under a factor's key material.
pub fn wrap_share(kek: &KeyMaterialBytes, share: &[u8]) -> Result<Vec<u8>> {
    cypher_from_material(kek).encrypt(share)
}

/// Unwraps a leaf's secret-share with a factor's key material.
///
/// Returns `None` when the material does not match (the wrap's HMAC fails) — i.e.
/// the factor was not satisfied.
pub fn unwrap_share(kek: &KeyMaterialBytes, wrapped: &[u8]) -> Option<Vec<u8>> {
    cypher_from_material(kek)
        .decrypt(wrapped)
        .ok()
        .map(|plaintext| plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrips_under_dek() {
        let dek = [7u8; KEY_MATERIAL_LEN];
        let data = b"the vault payload";
        let ct = encrypt_payload(&dek, data).unwrap();
        let pt = decrypt_payload(&dek, &ct).unwrap();
        assert_eq!(pt.as_slice(), data);
    }

    #[test]
    fn share_wraps_and_unwraps_with_right_key() {
        let kek = [3u8; KEY_MATERIAL_LEN];
        let share = [42u8; KEY_MATERIAL_LEN];
        let wrapped = wrap_share(&kek, &share).unwrap();
        assert_eq!(unwrap_share(&kek, &wrapped), Some(share.to_vec()));
    }

    #[test]
    fn wrong_key_does_not_unwrap() {
        let kek = [3u8; KEY_MATERIAL_LEN];
        let other = [4u8; KEY_MATERIAL_LEN];
        let wrapped = wrap_share(&kek, &[1u8; KEY_MATERIAL_LEN]).unwrap();
        assert_eq!(unwrap_share(&other, &wrapped), None);
    }

    #[test]
    fn generated_deks_differ() {
        let a = generate_dek().unwrap();
        let b = generate_dek().unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }
}
