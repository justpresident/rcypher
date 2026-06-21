use anyhow::{Result, bail};
use arboard::Clipboard;
use chrono::{Local, TimeZone};
use indicatif::ProgressBar;
use nix::fcntl::{Flock, FlockArg};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};
use zxcvbn::{Score, zxcvbn};

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

/// Prompts for one factor's password while unlocking a multi-factor vault.
///
/// An empty entry means "skip this factor" — the caller may be able to satisfy
/// the policy another way — and returns `None`.
pub fn prompt_factor_password(id: &str) -> Result<Option<String>> {
    let password =
        rpassword::prompt_password(format!("Password for factor '{id}' (empty to skip): "))?;
    if password.is_empty() {
        Ok(None)
    } else {
        Ok(Some(password))
    }
}

/// Scores a candidate password with zxcvbn and, when it is weak (below "safely
/// unguessable" — crackable in fewer than ~10^10 guesses), prints a prominent
/// warning with the estimated crack time and feedback, then requires a double
/// confirmation. Returns whether the caller should proceed with this password.
///
/// `user_inputs` (e.g. the factor name) make a password derived from them score
/// lower. The confirmation is read from the controlling terminal.
pub fn confirm_if_weak_password(password: &str, user_inputs: &[&str]) -> Result<bool> {
    let entropy = zxcvbn(password, user_inputs);
    if entropy.score() >= Score::Three {
        return Ok(true);
    }
    show_weak_password_warning(&entropy);
    // Double confirmation — both answers must be an explicit "yes".
    if !read_tty_confirmation("Use this weak password anyway? [y/N]: ")? {
        return Ok(false);
    }
    read_tty_confirmation("A weak password undermines the whole vault — are you sure? [y/N]: ")
}

fn show_weak_password_warning(entropy: &zxcvbn::Entropy) {
    let crack_time = entropy.crack_times().offline_slow_hashing_1e4_per_second();
    eprintln!("\n╔════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                        ⚠️  WEAK PASSWORD  ⚠️                       ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║  This password is easy to guess. Anyone who obtains the vault file  ║");
    eprintln!("║  could crack it offline far faster than is safe.                    ║");
    eprintln!("╚════════════════════════════════════════════════════════════════════╝");
    eprintln!("  Estimated offline crack time (slow hashing): {crack_time}");
    if let Some(feedback) = entropy.feedback() {
        if let Some(warning) = feedback.warning() {
            eprintln!("  • {warning}");
        }
        for suggestion in feedback.suggestions() {
            eprintln!("  • {suggestion}");
        }
    }
    eprintln!("  Tip: a long passphrase of several random words is both strong and memorable.\n");
}

/// Reads a yes/no answer from the controlling terminal (`/dev/tty`), so the
/// prompt works even while the interactive line editor owns stdin. Returns
/// `false` for anything other than an explicit yes.
fn read_tty_confirmation(prompt: &str) -> Result<bool> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let mut writer = tty.try_clone()?;
    writer.write_all(prompt.as_bytes())?;
    writer.flush()?;

    let mut reader = BufReader::new(tty);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Warns (on stderr) if any single password factor alone can unlock the store,
/// silently bypassing a stronger policy. No-op when `unlockers` is empty.
pub fn warn_single_password_unlock(unlockers: &[String]) {
    if unlockers.is_empty() {
        return;
    }
    eprintln!(
        "⚠ Weak policy: factor(s) {} each unlock this store on their own — \
         an OR branch is only as strong as its weakest factor.",
        unlockers.join(", ")
    );
}

/// Prompts for a new password, twice, and fails unless the two entries match.
/// Used when enrolling a new factor into an unlocked store.
pub fn prompt_new_password(label: &str) -> Result<String> {
    let mut password = rpassword::prompt_password(format!("New password for {label}: "))?;
    let mut confirmation = rpassword::prompt_password("Confirm password: ")?;
    if password != confirmation {
        password.zeroize();
        confirmation.zeroize();
        bail!("Passwords do not match");
    }
    confirmation.zeroize();
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
