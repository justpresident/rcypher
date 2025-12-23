use std::fmt;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::Cypher;
use crate::version::CypherVersion;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    // Store encrypted bytes instead of plaintext
    ciphertext: Vec<u8>,
}

// This is a helper constructor only available in tests
#[cfg(debug_assertions)]
impl<T: AsRef<str>> From<T> for EncryptedValue {
    fn from(value: T) -> Self {
        Self {
            ciphertext: value.as_ref().as_bytes().to_vec(),
        }
    }
}

impl EncryptedValue {
    /// Creates an encrypted value from raw ciphertext bytes (for deserialization)
    pub(crate) const fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    /// Creates an encrypted value from plaintext
    pub fn encrypt(cypher: &Cypher, plaintext: &str) -> Result<Self> {
        match cypher.version() {
            CypherVersion::LegacyWithoutKdf => Ok(Self {
                ciphertext: plaintext.to_string().into(),
            }),
            CypherVersion::V7WithKdf => {
                let ciphertext = cypher.encrypt(plaintext.as_bytes())?;
                Ok(Self { ciphertext })
            }
        }
    }

    /// Decrypts the value temporarily (result is zeroized after use)
    pub fn decrypt(&self, cypher: &Cypher) -> Result<Zeroizing<String>> {
        match cypher.version() {
            CypherVersion::LegacyWithoutKdf => {
                Ok(Zeroizing::new(String::from_utf8(self.ciphertext.clone())?))
            }
            CypherVersion::V7WithKdf => {
                let mut decrypted_bytes = cypher.decrypt(&self.ciphertext)?;

                let bytes = std::mem::take(&mut *decrypted_bytes);
                Ok(Zeroizing::new(String::from_utf8(bytes)?))
            }
        }
    }

    pub const fn as_bytes(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }
}

impl fmt::Display for EncryptedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<encrypted:{} bytes>", self.ciphertext.len())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueEntry {
    pub value: EncryptedValue,
    pub timestamp: u64,
}
