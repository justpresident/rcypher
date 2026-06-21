//! `rcypher` — reusable authenticated encryption for password-protected,
//! versioned encrypted storage.
//!
//! This crate is the cryptographic core behind the `rcypher` CLI, exposed so
//! that any application can encrypt and sign **its own data format** with the
//! same envelope the CLI writes. The construction is:
//!
//! - **Key derivation:** Argon2id, per-file random salt, tunable cost
//!   ([`Argon2Params`]).
//! - **Encryption:** AES-256-CBC with a per-operation random IV.
//! - **Authentication:** HMAC-SHA256 over header + ciphertext (encrypt-then-MAC),
//!   verified in constant time *before* any decryption.
//!
//! Each blob produced by [`Cypher::encrypt`] is self-contained:
//! `[ header (version, salt, IV, padding) | ciphertext | HMAC ]`. The salt and
//! IV travel in the header, so a blob can be decrypted given only the password.
//!
//! # Bring your own format
//!
//! ```no_run
//! use rcypher::{Cypher, CypherVersion, EncryptionKey};
//!
//! # fn main() -> anyhow::Result<()> {
//! let my_bytes = b"...your own serialized data...";
//!
//! // Encrypt (a fresh salt is generated and embedded in the blob's header):
//! let cypher = Cypher::new(EncryptionKey::from_password(CypherVersion::default(), "pw")?);
//! let blob = cypher.encrypt(my_bytes)?;
//!
//! // Decrypt in memory — the key is re-derived from the salt inside `blob`:
//! let reopened = Cypher::new(EncryptionKey::for_data("pw", &blob)?);
//! let plaintext = reopened.decrypt(&blob)?;
//! # Ok(()) }
//! ```
//!
//! See `examples/custom_format.rs` for the full round-trip, including the atomic
//! file helpers [`save_encrypted`] / [`load_encrypted`].
//!
//! # Features
//!
//! - `storage` *(default)* — rcypher's bundled key-value storage format
//!   ([`Storage`] and friends). Disable with `default-features = false` to depend
//!   on only the crypto envelope.
//!
//! # Anti-debug detection
//!
//! [`Cypher`] refuses to operate while a debugger/tracer is attached. This is
//! **on by default**; disable it for legitimately-traced hosts with
//! [`Cypher::with_trace_detection`]. The detection primitive
//! ([`is_debugger_attached`]) and the stronger ptrace/core-dump hardening
//! ([`enable_ptrace_protection`], [`disable_core_dumps`]) are reusable on their own.
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::dbg_macro,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::redundant_pub_crate
)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::multiple_crate_versions,
    clippy::missing_panics_doc
)]

// Module declarations
mod auth;
mod constants;
mod crypto;
mod file_io;
mod security;
#[cfg(feature = "storage")]
mod storage;
mod version;

// Public re-exports
pub use auth::{
    Factor, FactorKind, FactorSecret, Leaf, POLICY_VAULT_VERSION, PolicyMetadata, PolicyNode,
    PolicyVault, Share, check_factor_password, distribute, parse_policy_vault, reconstruct,
    serialize_policy_header,
};
pub use crypto::{Argon2Params, Cypher, EncryptionKey};
pub use file_io::{load_encrypted, save_encrypted};
pub use security::{disable_core_dumps, enable_ptrace_protection, is_debugger_attached};
#[cfg(feature = "storage")]
pub use storage::{
    EncryptedValue, Storage, ValueEntry, deserialize_storage, load_storage, save_storage,
    serialize_storage,
};
pub use version::CypherVersion;

// Re-export for convenience
pub use anyhow::{Result, bail};
