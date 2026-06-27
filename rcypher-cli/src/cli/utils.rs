use arboard::Clipboard;
use chrono::{Local, TimeZone};
use indicatif::ProgressBar;
use rcypher::cli::UnlockProgress;
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

/// Bridges the library's [`UnlockProgress`] to a CLI [`Spinner`]: each slow step of
/// the unlock loop shows a spinner (suppressed when `quiet`).
pub struct SpinnerProgress {
    quiet: bool,
    current: Option<Spinner>,
}

impl SpinnerProgress {
    pub const fn new(quiet: bool) -> Self {
        Self {
            quiet,
            current: None,
        }
    }
}

impl UnlockProgress for SpinnerProgress {
    fn start(&mut self, label: &str) {
        self.current = Some(Spinner::new(label, self.quiet));
    }

    fn finish(&mut self) {
        if let Some(s) = self.current.take() {
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

#[cfg(test)]
mod tests {
    use super::format_timestamp;

    #[test]
    fn test_format_timestamp() {
        let ts = 1_609_459_200; // 2021-01-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2021"));
        assert!(formatted.contains("01"));

        // Test zero timestamp
        let formatted_zero = format_timestamp(0);
        assert_eq!(formatted_zero, "N/A");
    }
}
