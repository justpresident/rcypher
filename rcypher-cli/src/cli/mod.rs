mod completer;
mod interactive;
pub mod update;
pub mod utils;

use std::path::{Path, PathBuf};

use anyhow::Result;
use rcypher::{DataContainer, PolicyVault};

pub const STANDBY_TIMEOUT: u64 = 300;
pub const SECURITY_WATCHDOG_TIMEOUT_SECS: u64 = 2; // 2× the 1-second timer interval
const CLIPBOARD_TTL_MS: u64 = 10000;

/// The factor id given to the password enrolled when a new store is created, or
/// when a legacy store is converted on open.
pub const DEFAULT_FACTOR_ID: &str = "primary";

pub use interactive::InteractiveCli;

/// The path of the backup written before a legacy store is upgraded in place:
/// `<path>.bak`.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

/// Writes the store's `data` to `path` in the current store format. When
/// `backup_first` (the legacy-upgrade case), the original file is first copied to
/// `<path>.bak` and the user is told.
pub fn persist_store(
    vault: &PolicyVault,
    data: &DataContainer,
    path: &Path,
    backup_first: bool,
) -> Result<()> {
    if backup_first {
        let bak = backup_path(path);
        std::fs::copy(path, &bak)?;
        eprintln!(
            "Upgraded '{}' to the current format; original backed up to {}.",
            path.display(),
            bak.display()
        );
    }
    let payload = data.safe_serialize()?;
    vault.save(&payload, path)
}
