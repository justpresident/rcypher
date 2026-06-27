//! The interactive policy-unlock loop: prompt for factors on the controlling
//! terminal until a [`LockedContainer`] is satisfiable, then let the caller
//! [`unlock`](LockedContainer::unlock) it.

use anyhow::{Result, bail};

use super::prompt::prompt_password;
#[cfg(feature = "fido2")]
use super::prompt::read_tty_confirmation;
use crate::LockedContainer;

/// Progress feedback for the slow steps of an interactive unlock.
///
/// Chiefly the Argon2 derivation run on each password attempt — implement it to
/// show a spinner or status line; [`NoProgress`] reports nothing.
/// [`prompt_until_unlocked`] calls [`start`](Self::start) just before a slow step
/// and [`finish`](Self::finish) just after, so it can show progress for exactly
/// that span.
pub trait UnlockProgress {
    /// A slow step labelled `label` (e.g. `"Checking"`) is about to begin.
    fn start(&mut self, label: &str);
    /// The current step has finished.
    fn finish(&mut self);
}

/// An [`UnlockProgress`] that reports nothing — for quiet or non-interactive callers.
pub struct NoProgress;

impl UnlockProgress for NoProgress {
    fn start(&mut self, _label: &str) {}
    fn finish(&mut self) {}
}

/// Drives `locked` toward a satisfiable state by prompting for factors on the tty.
///
/// Loops until [`can_unlock`](LockedContainer::can_unlock) holds; the caller then
/// calls [`LockedContainer::unlock`].
///
/// It prompts for a password while an unsatisfied password factor remains and —
/// when the `fido2` feature is built in — offers a security key while an
/// unsatisfied FIDO2 factor remains (asking for a touch, and a PIN if the key has
/// one). Factor names are encrypted until unlock, so a match is reported
/// generically rather than named. `progress` brackets each Argon2 attempt; pass
/// [`NoProgress`] for none.
///
/// Returns an error if the user cancels (an empty entry) or the policy cannot be
/// met by this build (e.g. it requires a security key and `fido2` is not compiled
/// in).
pub fn prompt_until_unlocked(
    locked: &mut LockedContainer,
    progress: &mut dyn UnlockProgress,
) -> Result<()> {
    // Without FIDO2 support compiled in, a policy that needs a security key cannot
    // be satisfied here — say so up front rather than looping.
    #[cfg(not(feature = "fido2"))]
    if !locked.satisfiable_by_password() {
        bail!(
            "this store's policy requires a FIDO2 security key, but this build has no FIDO2 \
             support; rebuild with the `fido2` feature"
        );
    }

    while !locked.can_unlock() {
        let needs_password = locked.needs_password();
        let needs_fido2 = pending_fido2(locked);

        if !needs_password && !needs_fido2 {
            bail!(
                "cannot satisfy the unlock policy with the available factors (a required \
                 security key may need a build with the `fido2` feature)"
            );
        }

        // Prompt for a password only while one is still needed.
        if needs_password {
            let prompt = if needs_fido2 {
                "Password (empty to use a security key, or to cancel)"
            } else {
                "Password (empty to cancel)"
            };
            let password = prompt_password(prompt)?;
            if !password.is_empty() {
                progress.start("Checking");
                let matched = locked.try_password(&password);
                progress.finish();
                report_unlocked(matched?, locked);
                continue;
            }
            // Empty entry: use a key if one applies, else cancel.
            if !needs_fido2 {
                bail!("unlock cancelled");
            }
        }

        // A security key is the (or an) option — present it.
        #[cfg(feature = "fido2")]
        if !present_fido2_factor(locked)? && !needs_password {
            // Only a key can unlock and it satisfied nothing; offer a retry or cancel.
            if !read_tty_confirmation("Try the security key again? [Y/n]: ")? {
                bail!("unlock cancelled");
            }
        }
    }
    Ok(())
}

/// Reports a factor attempt and whether more factors are still needed. Factor
/// names are hidden until unlock, so a match is reported without naming the factor.
fn report_unlocked(matched: bool, locked: &LockedContainer) {
    if matched {
        eprintln!("Factor unlocked.");
        if !locked.can_unlock() {
            eprintln!("More factors are required to satisfy the policy.");
        }
    } else {
        eprintln!("That did not match any factor — try again.");
    }
}

/// Whether the lock still needs a FIDO2 security key this build can use.
#[cfg(feature = "fido2")]
fn pending_fido2(locked: &LockedContainer) -> bool {
    locked
        .pending_factor_kinds()
        .iter()
        .any(|kind| matches!(kind, crate::FactorKind::Fido2 { .. }))
}
#[cfg(not(feature = "fido2"))]
const fn pending_fido2(_locked: &LockedContainer) -> bool {
    false
}

/// Presents each still-pending FIDO2 factor: prompts for a touch (and a PIN if the
/// factor needs one), reads its `hmac-secret`, and tries it. Returns `true` once a
/// factor is satisfied.
#[cfg(feature = "fido2")]
fn present_fido2_factor(locked: &mut LockedContainer) -> Result<bool> {
    // `pending_factor_kinds()` is owned, so we can iterate it while mutably trying.
    for kind in locked.pending_factor_kinds() {
        let crate::FactorKind::Fido2 {
            credential_id,
            rp_id,
            salt,
            require_pin,
        } = kind
        else {
            continue;
        };

        eprintln!("Touch your FIDO2 security key…");
        let pin = if require_pin {
            Some(prompt_password("Security key PIN")?)
        } else {
            None
        };
        let pin = pin.as_ref().map(|p| p.as_str());
        match crate::fido2::hmac_secret(&credential_id, &rp_id, &salt, pin) {
            Ok(secret) => {
                if locked.try_fido2_secret(&secret)? {
                    report_unlocked(true, locked);
                    return Ok(true);
                }
                eprintln!("  That key did not match any factor.");
            }
            Err(e) => eprintln!("  {e}"),
        }
    }
    Ok(false)
}
