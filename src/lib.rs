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
//! # Encrypted stores (the high-level API)
//!
//! For a complete password- or policy-protected store — multi-factor unlock,
//! transparent legacy upgrade, and atomic save — use the version-agnostic facade
//! instead of the raw envelope above. [`LockedContainer`] loads a file of any
//! on-disk format; you satisfy its lock with passwords and
//! [`unlock`](LockedContainer::unlock) it into an [`UnlockedContainer<T>`] over your
//! own [`DataContainer`] payload, which exposes the data, its data-key [`Cypher`], and
//! lock management. Clients never name a format version, so a future format is
//! adopted without any client change.
//!
//! # Features
//!
//! - `storage` *(default)* — rcypher's bundled key-value storage format
//!   ([`SecretStore`] and friends). Disable with `default-features = false` to depend
//!   on only the crypto envelope.
//! - `fido2` — hardware FIDO2 security-key factors (adds the `fido2` device module).
//! - `cli` — reusable interactive terminal plumbing (adds the `cli` module):
//!   password prompts, the zxcvbn strength gate, and the policy-unlock prompt loop,
//!   for building an rcypher-like CLI on top of the library.
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
#[cfg(feature = "cli")]
pub mod cli;
mod constants;
mod container;
mod crypto;
mod data_container;
mod file_io;
mod security;
#[cfg(feature = "storage")]
mod storage;
mod version;

// Public re-exports
// The public surface is the version-agnostic facade plus the crypto primitives.
// The on-disk formats (`FileContainer*`), the keyslot vault (`PolicyVault`,
// `UnlockSession`, …), and the policy types are internal: a client never names a
// format version, and a new format is added without touching any client.
/// FIDO2 security-key device I/O (enrol/read `hmac-secret`); requires the `fido2`
/// feature and a connected authenticator.
#[cfg(feature = "fido2")]
pub use auth::fido2;
pub use auth::{FactorKind, check_factor_password};
pub use container::{LockedContainer, UnlockedContainer, backup_path};
pub use crypto::{Argon2Params, Cypher, EncryptionKey};
pub use data_container::DataContainer;
pub use file_io::{load_encrypted, save_encrypted};
pub use security::{disable_core_dumps, enable_ptrace_protection, is_debugger_attached};
#[cfg(feature = "storage")]
pub use storage::{EncryptedValue, SecretStore, ValueEntry};
pub use version::CypherVersion;

// Re-export for convenience. `Zeroizing` appears in public signatures
// (`DataContainer::encode`, `load_encrypted`), so callers can name those return types
// without depending on `zeroize` directly.
pub use anyhow::{Result, bail};
pub use zeroize::Zeroizing;
