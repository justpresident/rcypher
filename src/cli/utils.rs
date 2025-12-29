use anyhow::{Result, bail};
use arboard::Clipboard;
use chrono::{Local, TimeZone};
use indicatif::ProgressBar;
use nix::fcntl::{Flock, FlockArg};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Format a full path from folder path and key
/// Handles both absolute paths ("/", "/work") and relative paths ("", "work/", "../work")
/// If `is_folder` is true, appends a trailing "/" to the result
pub fn format_full_path(folder_path: &str, key: &str, is_folder: bool) -> String {
    let path = if folder_path.is_empty() {
        key.to_string()
    } else if folder_path == "/" {
        format!("/{key}")
    } else {
        format!("{}/{key}", folder_path.trim_end_matches('/'))
    };

    if is_folder { format!("{path}/") } else { path }
}

/// Compute relative path from root to path
/// Examples:
/// - `relative_path_from`("/", "/work") = "work"
/// - `relative_path_from`("/", "/work/api") = "work/api"
/// - `relative_path_from("/work`", "/work/api") = "api"
/// - `relative_path_from`("/", "/") = ""
pub fn relative_path_from(root: &str, path: &str) -> String {
    if path == root {
        String::new()
    } else if root == "/" {
        path.strip_prefix('/').unwrap_or(path).to_string()
    } else {
        path.strip_prefix(root)
            .and_then(|p| p.strip_prefix('/'))
            .unwrap_or("")
            .to_string()
    }
}

/// Resolve a path (absolute or relative) from a given current directory
pub fn resolve_path(current_path: &str, path: &str) -> String {
    if path.is_empty() {
        return current_path.to_string();
    }

    if path.starts_with('/') {
        // Absolute path
        return normalize_path(path);
    }

    // Relative path - resolve from current directory
    let mut components: Vec<&str> = if current_path == "/" {
        Vec::new()
    } else {
        current_path.trim_matches('/').split('/').collect()
    };

    // Process each component of the path
    for component in path.trim_end_matches('/').split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            name => {
                components.push(name);
            }
        }
    }

    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

/// Normalize an absolute path by resolving . and .. components
pub fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            name => {
                components.push(name);
            }
        }
    }

    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

/// Parse a key argument that may include a path (e.g., "`work/api_key`")
/// Returns (`resolved_folder_path`, `key_name`)
pub fn parse_key_path<'a>(current_path: &str, key_arg: &'a str) -> (String, &'a str) {
    if let Some(last_slash) = key_arg.rfind('/') {
        let dir_part = &key_arg[..last_slash];
        let key_name = &key_arg[last_slash + 1..];
        let resolved_path = resolve_path(current_path, dir_part);
        (resolved_path, key_name)
    } else {
        (current_path.to_string(), key_arg)
    }
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
