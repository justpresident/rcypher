mod backend;
mod completer;
mod interactive;
pub mod update;
pub mod utils;

pub const STANDBY_TIMEOUT: u64 = 300;
pub const SECURITY_WATCHDOG_TIMEOUT_SECS: u64 = 2; // 2× the 1-second timer interval
const CLIPBOARD_TTL_MS: u64 = 10000;

/// The factor id given to the password enrolled when a new store is created, or
/// when a legacy store is upgraded to a policy vault.
pub const DEFAULT_FACTOR_ID: &str = "primary";

pub use backend::Backend;
pub use interactive::InteractiveCli;
