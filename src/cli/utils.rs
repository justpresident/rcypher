use anyhow::{Result, bail};
use arboard::Clipboard;
use chrono::{Local, TimeZone};
use indicatif::ProgressBar;
use nix::fcntl::{Flock, FlockArg};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

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

/// A guard to signal background thread to stop when dropped
pub struct ThreadStopGuard {
    flag: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

impl ThreadStopGuard {
    pub const fn new(flag: Arc<AtomicBool>, handle: std::thread::JoinHandle<()>) -> Self {
        Self { flag, handle }
    }
}

impl Drop for ThreadStopGuard {
    fn drop(&mut self) {
        // Signal the thread to stop
        self.flag.store(true, Ordering::Relaxed);

        // Try to join with a short timeout
        let start = std::time::Instant::now();
        while !self.handle.is_finished() && start.elapsed() < std::time::Duration::from_millis(200)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
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

pub fn copy_to_clipboard(secret: &str, ttl: std::time::Duration) -> Result<()> {
    println!(
        "Secret copied to the clipboard and will be automatically removed in {} seconds.\n
        Warning: Clipboard managers may retain history",
        ttl.as_secs()
    );

    let copy = Zeroizing::from(secret.to_string());

    // Spawn a background thread to clear clipboard after TTL
    std::thread::spawn(move || {
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text(copy.to_string());
            std::thread::sleep(ttl);
            if clipboard.get_text().ok().as_deref() == Some(copy.as_ref()) {
                let _ = clipboard.set_text("deleted");
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        } else {
            println!("Can't access clipboard");
        }
    });

    Ok(())
}
