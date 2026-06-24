//! Multi-factor unlock: factors, the access policy, and the vault they protect.
//!
//! A policy vault is encrypted with a random data-encryption key (DEK). The DEK
//! is secret-shared down a boolean [`PolicyNode`] access tree — an `Or` replicates
//! its secret to each child, an `And` XOR-splits it — and each [`Leaf`] holds its
//! share wrapped under the referenced factor's key. Recovering the DEK therefore
//! requires satisfying the policy (e.g. `pass1 OR (pass2 AND yubikey)`).
//!
//! Layers: [`factor`] (a credential), [`policy`] (the boolean rule over factor
//! names + its sharing), [`header`] ([`VaultHeader`] = factors + policy, the
//! serialized projection of a vault), and [`vault`] ([`PolicyVault`], the unlocked
//! vault + unlock session).

mod factor;
mod header;
mod policy;
mod vault;

pub use factor::{Factor, FactorKind};
pub use header::VaultHeader;
pub use policy::{Leaf, PolicyNode, Share, distribute, reconstruct};
pub use vault::{FactorSecret, PolicyVault, UnlockSession, check_factor_password};
