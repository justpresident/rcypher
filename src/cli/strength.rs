//! Password-strength gating with [zxcvbn] — a guess-resistance estimator (not a
//! composition-rule checker), aligned with current NIST guidance.
//!
//! [zxcvbn]: https://github.com/dropbox/zxcvbn

use anyhow::{Result, bail};
use zxcvbn::{Score, zxcvbn};

use super::prompt::read_tty_confirmation;

/// Scores a candidate password with zxcvbn and gates on the result:
/// - score 3–4 (safely unguessable): accepted silently (`Ok(true)`);
/// - score 1–2 (weak): a prominent warning, then proceed only after a double
///   confirmation (`Ok(true)`/`Ok(false)`);
/// - score 0 (too guessable — the factor name, the app name, "abc123", …):
///   refused outright (`Err`), with no override.
///
/// `user_inputs` (e.g. the factor name and the application name) make a password
/// derived from them score lower, so those land in the hard-rejected tier. The
/// confirmations are read from the controlling terminal.
pub fn confirm_if_weak_password(password: &str, user_inputs: &[&str]) -> Result<bool> {
    let entropy = zxcvbn(password, user_inputs);
    let score = entropy.score();
    if score >= Score::Three {
        return Ok(true);
    }
    show_weak_password_warning(&entropy);

    // Score 0 is "too guessable" (crackable in under ~1000 guesses) — this is
    // where the factor name, the app name, and the worst passwords land (the name
    // is passed as a zxcvbn input). Refuse outright; do not offer an override.
    if score == Score::Zero {
        bail!(
            "this password is far too weak to use — it (or something very close, such as \
             the factor name) would be cracked almost instantly. Choose a stronger one."
        );
    }

    // Scores 1–2 are weak but not trivial: allow proceeding after a double
    // confirmation, where both answers must be an explicit "yes".
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
