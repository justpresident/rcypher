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
mod constants;
mod version;
mod crypto;
mod storage;
mod utils;

// Public re-exports (maintaining exact same API)
pub use version::CypherVersion;
pub use storage::{
    EncryptedValue,
    ValueEntry,
    Storage,
    serialize_storage,
    deserialize_storage,
    load_storage,
    save_storage,
};
pub use crypto::{Cypher, EncryptionKey};
pub use utils::format_timestamp;

// Re-export for convenience
pub use anyhow::{Result, bail};
