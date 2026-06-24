//! The legacy version-7 store file: the whole file is a single password-keyed
//! AEAD envelope (`Version7Header ‖ AES-256-CBC ‖ HMAC`).
//!
//! Read-only. On open it is decrypted and transparently converted to a
//! version-8 policy vault; rcypher never writes this format, so the codec
//! implements parsing and unlocking but not serialization.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use super::{ContainerCodec, FileContainerFormat, Secrets};
use crate::crypto::{Argon2Params, Cypher, EncryptionKey};

/// A parsed legacy version-7 store file: a borrow of the whole encrypted
/// envelope (the salt lives in its header; the body is the encrypted payload).
pub struct FileContainerV7<'a> {
    data: &'a [u8],
}

impl<'a> ContainerCodec<'a> for FileContainerV7<'a> {
    type Key = EncryptionKey;
    const FORMAT: FileContainerFormat = FileContainerFormat::V7;

    fn parse(data: &'a [u8]) -> Result<Self> {
        if FileContainerFormat::probe(data)? != Self::FORMAT {
            bail!("not a version-7 store file");
        }
        Ok(Self { data })
    }

    fn describe(&self) -> String {
        "a single password".to_string()
    }

    fn unlock(&self, secrets: &Secrets, params: &Argon2Params) -> Result<EncryptionKey> {
        match secrets {
            // The salt is read back from the envelope header, so the derived key
            // matches the one that encrypted it.
            Secrets::Password(password) => {
                EncryptionKey::for_data_with_params(password, self.data, params)
            }
            Secrets::Factors(_) => {
                bail!("a legacy version-7 store is unlocked by a single password, not factors")
            }
        }
    }

    fn decrypt_payload(&self, key: &EncryptionKey) -> Result<Zeroizing<Vec<u8>>> {
        // The whole file is the envelope, so decrypting it yields the payload.
        Cypher::new(key.clone()).decrypt(self.data)
    }
}
