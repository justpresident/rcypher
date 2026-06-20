//! Multi-factor unlock: access policies, factors, and the keyslot vault format.
//!
//! A policy vault is encrypted with a random data-encryption key (DEK). The DEK
//! is secret-shared down a boolean [`PolicyNode`] access tree — an `Or` replicates
//! its secret to each child, an `And` XOR-splits it — and each [`Leaf`] holds its
//! share wrapped under the referenced factor's key. Recovering the DEK therefore
//! requires satisfying the policy (e.g. `pass1 OR (pass2 AND yubikey)`).
//!
//! This module owns the data model and on-disk format; the sharing algorithms and
//! factor key derivation land in sibling tasks.

mod factor;
mod format;
mod keyslot;
mod parser;
mod policy;
mod vault;

pub use format::{
    Factor, FactorKind, POLICY_VAULT_VERSION, PolicyMetadata, parse_policy_vault,
    serialize_policy_header,
};
pub use policy::{Leaf, PolicyNode, Share, distribute, reconstruct};
pub use vault::{FactorSecret, PolicyVault};
