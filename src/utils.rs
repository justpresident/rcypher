use anyhow::{Result, bail};
use chrono::{Local, TimeZone};
use indicatif::ProgressBar;
use nix::fcntl::{Flock, FlockArg};
use std::fs::OpenOptions;
use std::io::Write;

pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }
    let dt = Local
        .timestamp_opt(ts.try_into().expect("invalid timestamp"), 0)
        .unwrap();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Prints directly to tty to avoid
/// - snooping passwords from process stdout
/// - lingering passwords in memory
pub fn secure_print(what: impl AsRef<str>, insecure_stdout: bool) -> Result<()> {
    if insecure_stdout {
        println!("{}", what.as_ref());
        return Ok(());
    }
    let tty = OpenOptions::new().write(true).open("/dev/tty")?;
    let mut lock = match Flock::lock(tty, FlockArg::LockExclusive) {
        Ok(l) => l,
        Err((_, e)) => bail!(e),
    };
    lock.write_all(what.as_ref().as_bytes())?;
    lock.write_all(b"\n")?;
    lock.flush()?;
    Ok(())
}

pub struct Spinner {
    inner: Option<ProgressBar>,
}

impl Spinner {
    pub fn new(message: &str, quiet: bool) -> Self {
        let inner = if quiet {
            None
        } else {
            let s = ProgressBar::new_spinner();
            s.set_message(message.to_string());
            s.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(s)
        };
        Self { inner }
    }

    pub fn set_message(&self, message: &str) {
        if let Some(s) = &self.inner {
            s.set_message(message.to_string());
        }
    }

    pub fn finish_and_clear(&self) {
        if let Some(s) = &self.inner {
            s.finish_and_clear();
        }
    }
}
