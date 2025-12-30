use std::fs;
use std::mem::size_of;
use std::path::Path;

use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use zeroize::Zeroizing;

use crate::constants::{KEY_LEN, KeyBytes, SaltBytes};
use crate::version::{CypherVersion, Version7Header};

/// Argon2 key derivation parameters
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    /// Memory cost in KiB (kilobytes)
    pub memory_cost: u32,
    /// Number of iterations (time cost)
    pub time_cost: u32,
    /// Degree of parallelism
    pub parallelism: u32,
}

impl Default for Argon2Params {
    /// Secure default parameters for production use
    /// - Memory: 64 MB
    /// - Iterations: 3
    /// - Parallelism: 1
    fn default() -> Self {
        Self {
            memory_cost: 65536,
            time_cost: 3,
            parallelism: 1,
        }
    }
}

impl Argon2Params {
    /// Insecure parameters for testing only - minimal computational cost
    /// WARNING: These parameters provide almost no protection against brute force attacks.
    /// Only use with --insecure-password flag in tests.
    pub const fn insecure() -> Self {
        Self {
            memory_cost: Params::MIN_M_COST,
            time_cost: Params::MIN_T_COST,
            parallelism: Params::MIN_P_COST,
        }
    }
}

#[derive(Clone, Default)]
pub struct EncryptionKey {
    pub version: CypherVersion,
    key: Zeroizing<KeyBytes>,
    salt: SaltBytes,
    hmac_key: Zeroizing<KeyBytes>,
}

impl EncryptionKey {
    /// Creates a key from password with default secure Argon2 parameters
    pub fn from_password(version: CypherVersion, password: &str) -> Result<Self> {
        Self::from_password_with_params(version, password, &Argon2Params::default())
    }

    /// Creates a key from password with custom Argon2 parameters
    ///
    /// # Arguments
    /// * `version` - Cipher version to use
    /// * `password` - Password to derive key from
    /// * `argon2_params` - Argon2 parameters (use `Argon2Params::insecure()` for testing)
    pub fn from_password_with_params(
        version: CypherVersion,
        password: &str,
        argon2_params: &Argon2Params,
    ) -> Result<Self> {
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
                Self::from_password_with_salt(version, password, &salt, argon2_params)
            }
        }
    }

    /// Derives a key from password and salt using Argon2id with specified parameters
    fn from_password_with_salt(
        version: CypherVersion,
        password: &str,
        salt: &SaltBytes,
        argon2_params: &Argon2Params,
    ) -> Result<Self> {
        let params = Params::new(
            argon2_params.memory_cost,
            argon2_params.time_cost,
            argon2_params.parallelism,
            Some(2 * size_of::<KeyBytes>()),
        )
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

    /// Creates a key for an existing file with default secure Argon2 parameters
    pub fn for_file(password: &str, path: &Path) -> Result<Self> {
        Self::for_file_with_params(password, path, &Argon2Params::default())
    }

    /// Creates a key for an existing file with custom Argon2 parameters
    ///
    /// # Arguments
    /// * `password` - Password to derive key from
    /// * `path` - Path to the encrypted file
    /// * `argon2_params` - Argon2 parameters (use `Argon2Params::insecure()` for testing)
    pub fn for_file_with_params(
        password: &str,
        path: &Path,
        argon2_params: &Argon2Params,
    ) -> Result<Self> {
        let version = CypherVersion::probe_file(path)?;

        let key = match version {
            CypherVersion::LegacyWithoutKdf => {
                Self::from_password_with_params(version, password, argon2_params)?
            }
            CypherVersion::V7WithKdf => {
                if !fs::exists(path)? {
                    return Self::from_password_with_params(version, password, argon2_params);
                }
                let mut file = fs::File::open(path)?;
                if file.metadata()?.len() < u64::try_from(size_of::<Version7Header>())? {
                    bail!("file size is too small");
                }
                let header: Version7Header =
                    bincode::decode_from_std_read(&mut file, bincode::config::standard())?;
                header.validate()?;
                Self::from_password_with_salt(version, password, &header.salt, argon2_params)?
            }
        };

        Ok(key)
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
