mod completer;
mod interactive;
pub mod update;
pub mod utils;

pub const STANDBY_TIMEOUT: u64 = 300;
pub const SECURITY_WATCHDOG_TIMEOUT_SECS: u64 = 2; // 2× the 1-second timer interval
const CLIPBOARD_TTL_MS: u64 = 10000;

/// The factor name given to the password enrolled when a new store is created, or
/// when a legacy store is converted on open.
pub const DEFAULT_FACTOR_NAME: &str = "primary";

/// The FIDO2 relying-party id bound into enrolled credentials. Stored in each
/// factor and replayed at unlock, so it must stay stable across versions.
#[cfg(feature = "fido2")]
pub const FIDO2_RP_ID: &str = "rcypher";

pub use interactive::InteractiveCli;
