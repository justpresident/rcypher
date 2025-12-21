#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::unwrap_used,
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
pub mod cli;
mod constants;
mod crypto;
mod security;
mod storage;
mod version;

// Public re-exports (maintaining exact same API)
pub use cli::utils::{Spinner, ThreadStopGuard, copy_to_clipboard, format_timestamp, secure_print};
pub use crypto::{Cypher, EncryptionKey};
pub use security::{disable_core_dumps, enable_ptrace_protection, is_debugger_attached};
pub use storage::{
    EncryptedValue, Storage, ValueEntry, deserialize_storage, load_storage, save_storage,
    serialize_storage,
};
pub use version::CypherVersion;

// Re-export for convenience
pub use anyhow::{Result, bail};
