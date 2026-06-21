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

#[cfg(debug_assertions)]
impl EncryptedValue {
    /// Wraps plaintext bytes as if they were ciphertext, performing **no
    /// encryption**. Intended only for tests and benchmarks that exercise the
    /// storage format without a real key — never use it in production code.
    ///
    /// Replaces a former `From<&str>` impl: an explicit, clearly-named call site
    /// makes it obvious the bytes are not actually encrypted.
    #[doc(hidden)]
    pub fn from_plaintext_unchecked(plaintext: impl AsRef<str>) -> Self {
        Self {
            ciphertext: plaintext.as_ref().as_bytes().to_vec(),
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
            CypherVersion::V7WithKdf => {
                let ciphertext = cypher.encrypt(plaintext.as_bytes())?;
                Ok(Self { ciphertext })
            }
        }
    }

    /// Decrypts the value temporarily (result is zeroized after use)
    pub fn decrypt(&self, cypher: &Cypher) -> Result<Zeroizing<String>> {
        match cypher.version() {
            CypherVersion::V7WithKdf => {
                let decrypted_bytes = cypher.decrypt(&self.ciphertext)?;
                // Validate UTF-8 by borrowing, so the plaintext is never moved out
                // of its zeroizing buffer (and isn't carried by a `FromUtf8Error`
                // on the failure path); copy straight into a zeroizing `String`.
                let text = std::str::from_utf8(&decrypted_bytes)?;
                Ok(Zeroizing::new(text.to_owned()))
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
