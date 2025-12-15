mod completer;
mod interactive;

const STANDBY_TIMEOUT: u64 = 300;
const CLIPBOARD_TTL_MS: u64 = 10000;

pub use interactive::InteractiveCli;
