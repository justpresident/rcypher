use std::mem::size_of;

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use zeroize::Zeroizing;

use crate::constants::{KEY_LEN, KeyBytes, SaltBytes};
use crate::version::CypherVersion;

#[derive(Clone, Default)]
pub struct EncryptionKey {
    pub version: CypherVersion,
    key: Zeroizing<KeyBytes>,
    salt: SaltBytes,
    hmac_key: Zeroizing<KeyBytes>,
}

impl EncryptionKey {
    /// Creates a key from password without KDF (for backward compatibility)
    pub fn from_password(version: CypherVersion, password: &str) -> Result<Self> {
        match version {
            CypherVersion::LegacyWithoutKdf => {
                let mut key = [b'~'; KEY_LEN];
                let bytes = password.as_bytes();
                let len = bytes.len().min(KEY_LEN);

                key[..len].copy_from_slice(&bytes[..len]);

                Ok(Self {
                    version,
                    key: Zeroizing::new(key),
                    ..Default::default()
                })
            }
            CypherVersion::V7WithKdf => {
                let mut salt = SaltBytes::default();
                rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
                Self::from_password_with_salt(version, password, &salt)
            }
        }
    }

    /// Derives a key from password and salt using Argon2id
    pub(crate) fn from_password_with_salt(
        version: CypherVersion,
        password: &str,
        salt: &SaltBytes,
    ) -> Result<Self> {
        // Argon2id parameters: memory=64MB, iterations=3, parallelism=1
        let params = Params::new(65536, 3, 1, Some(2 * size_of::<KeyBytes>()))
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {e}"))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut all_key_bytes = Zeroizing::new([0u8; 2 * size_of::<KeyBytes>()]);
        argon2
            .hash_password_into(password.as_bytes(), salt, all_key_bytes.as_mut())
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {e}"))?;

        let mut key = KeyBytes::default();
        let mut hmac_key = KeyBytes::default();
        key.copy_from_slice(&all_key_bytes[0..KEY_LEN]);
        hmac_key.copy_from_slice(&all_key_bytes[KEY_LEN..]);

        Ok(Self {
            version,
            key: Zeroizing::new(key),
            hmac_key: Zeroizing::new(hmac_key),
            salt: *salt,
        })
    }

    pub fn as_bytes(&self) -> &KeyBytes {
        &self.key
    }
    pub fn hmac_key(&self) -> &KeyBytes {
        &self.hmac_key
    }
    pub const fn salt(&self) -> &SaltBytes {
        &self.salt
    }
    pub const fn version(&self) -> &CypherVersion {
        &self.version
    }
}
