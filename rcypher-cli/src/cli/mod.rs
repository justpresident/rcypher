mod completer;
mod interactive;
pub mod update;
pub mod utils;

pub const STANDBY_TIMEOUT: u64 = 300;
pub const SECURITY_WATCHDOG_TIMEOUT_SECS: u64 = 2; // 2× the 1-second timer interval
const CLIPBOARD_TTL_MS: u64 = 10000;

pub use interactive::InteractiveCli;
