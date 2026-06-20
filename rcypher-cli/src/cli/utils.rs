use anyhow::{Result, bail};
use arboard::Clipboard;
use chrono::{Local, TimeZone};
use indicatif::ProgressBar;
use nix::fcntl::{Flock, FlockArg};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

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
///
/// This function takes ownership of the string and zeroizes it after printing
/// to ensure sensitive data doesn't linger in memory.
pub fn secure_print(mut what: String, insecure_stdout: bool) -> Result<()> {
    if insecure_stdout {
        println!("{}", &what);
        return Ok(());
    }
    let tty = OpenOptions::new().write(true).open("/dev/tty")?;
    let mut lock = match Flock::lock(tty, FlockArg::LockExclusive) {
        Ok(l) => l,
        Err((_, e)) => bail!(e),
    };
    lock.write_all(what.as_bytes())?;
    lock.write_all(b"\n")?;
    lock.flush()?;

    // Zeroize the string before returning
    what.zeroize();
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

pub fn copy_to_clipboard(secret: &str, ttl: std::time::Duration) {
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
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else {
            println!("Can't access clipboard");
        }
    });
}

pub fn get_password(filename: &Path, require_confirmation: bool) -> Result<String> {
    if require_confirmation {
        show_password_warning();
    }

    let mut password =
        rpassword::prompt_password(format!("Enter Password for {}: ", filename.display()))?;

    if require_confirmation {
        let mut confirmation = rpassword::prompt_password("Confirm Password: ")?;
        if password != confirmation {
            password.zeroize();
            confirmation.zeroize();
            bail!("Passwords do not match");
        }
    }

    Ok(password)
}

fn show_password_warning() {
    eprintln!("\n╔════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                         ⚠️  IMPORTANT! ⚠️                          ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                    ║");
    eprintln!("║  Your password CANNOT be recovered if lost or forgotten.           ║");
    eprintln!("║  Without it, your encrypted data will be PERMANENTLY inaccessible. ║");
    eprintln!("║                                                                    ║");
    eprintln!("║  → Use a strong, memorable password                                ║");
    eprintln!("║  → Store it under a secret name in another password manager        ║");
    eprintln!("║  → Never share it with anyone                                      ║");
    eprintln!("║                                                                    ║");
    eprintln!("╚════════════════════════════════════════════════════════════════════╝\n");
}

#[cfg(test)]
mod tests {
    use super::format_timestamp;

    #[test]
    fn test_format_timestamp() {
        let ts = 1609459200; // 2021-01-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2021"));
        assert!(formatted.contains("01"));

        // Test zero timestamp
        let formatted_zero = format_timestamp(0);
        assert_eq!(formatted_zero, "N/A");
    }
}
