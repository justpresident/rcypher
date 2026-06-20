//! The key/vault backend the interactive session operates over: either a plain
//! password-derived `Cypher` (legacy version-7 vaults) or a multi-factor
//! `PolicyVault` (version-8). Both expose a `Cypher` for per-value operations and
//! a uniform store load/save.

use std::path::Path;

use anyhow::Result;
use rcypher::{
    Cypher, PolicyVault, Storage, deserialize_storage, load_storage, save_storage,
    serialize_storage,
};

pub enum Backend {
    /// A plain password-derived key (version-7 vault).
    Legacy { cypher: Cypher },
    /// A multi-factor policy vault (version-8). `cypher` is keyed by the DEK and
    /// stays valid for the session (the DEK never changes across saves).
    Policy { vault: PolicyVault, cypher: Cypher },
}

impl Backend {
    /// The `Cypher` for encrypting/decrypting individual stored values.
    pub const fn cypher(&self) -> &Cypher {
        match self {
            Self::Legacy { cypher } | Self::Policy { cypher, .. } => cypher,
        }
    }

    /// The underlying policy vault, if this is a multi-factor store. `None` for a
    /// legacy single-password store.
    pub const fn policy_vault(&self) -> Option<&PolicyVault> {
        match self {
            Self::Policy { vault, .. } => Some(vault),
            Self::Legacy { .. } => None,
        }
    }

    /// Mutable access to the policy vault, for factor/policy management. `None` for
    /// a legacy single-password store. Mutating factors or the policy leaves the
    /// DEK — and therefore the session [`Cypher`] — unchanged.
    pub const fn policy_vault_mut(&mut self) -> Option<&mut PolicyVault> {
        match self {
            Self::Policy { vault, .. } => Some(vault),
            Self::Legacy { .. } => None,
        }
    }

    /// Loads the store from `filename`.
    pub fn load_store(&self, filename: &Path) -> Result<Storage> {
        match self {
            Self::Legacy { cypher } => load_storage(cypher, filename),
            Self::Policy { vault, .. } => {
                if !filename.exists() {
                    return Ok(Storage::new());
                }
                let payload = vault.load_payload(filename)?;
                deserialize_storage(&payload)
            }
        }
    }

    /// Saves the store to `filename`.
    pub fn save_store(&self, storage: &Storage, filename: &Path) -> Result<()> {
        match self {
            Self::Legacy { cypher } => save_storage(cypher, storage, filename),
            Self::Policy { vault, .. } => {
                let payload = serialize_storage(storage)?;
                vault.save(&payload, filename)
            }
        }
    }
}
