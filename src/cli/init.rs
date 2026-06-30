//! The interactive new-store flow: enrol the caller-chosen factors on the
//! controlling terminal, let the user pick the unlock policy, and return a
//! ready-to-use unlocked container — the creation-side counterpart to
//! [`prompt_until_unlocked`](super::prompt_until_unlocked).

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;

#[cfg(feature = "fido2")]
use super::prompt::prompt_password;
use super::prompt::{prompt_new_password, read_tty_confirmation, show_password_warning};
use super::strength::confirm_if_weak_password;
use super::unlock::UnlockProgress;
use crate::{Argon2Params, DataContainer, UnlockedContainer};

/// A factor kind the new-store flow can enrol.
#[derive(Clone, Copy)]
pub enum InitFactorKind {
    /// A password factor — prompted (twice), strength-gated, and re-prompted while
    /// a weak one is declined.
    Password,
    /// A FIDO2 security-key factor — enrolled with a touch. Only available with the
    /// `fido2` feature built in.
    #[cfg(feature = "fido2")]
    Fido2,
}

/// A factor to enrol at store creation: a [kind](InitFactorKind) and the name it is
/// stored under.
pub struct InitFactor<'a> {
    /// The kind of factor to enrol.
    pub kind: InitFactorKind,
    /// The factor's name (a label; encrypted in the store).
    pub name: &'a str,
}

/// Configuration for [`prompt_until_initialized`].
pub struct NewStoreConfig<'a> {
    /// The factors to enrol, in order. Must be non-empty; the first one bootstraps
    /// the store and the rest are enrolled into it.
    pub factors: &'a [InitFactor<'a>],
    /// The FIDO2 relying-party id bound into any enrolled key. Leave `None` to use
    /// rcypher's [`DEFAULT_RP_ID`](crate::fido2::DEFAULT_RP_ID) — recommended, so a
    /// key enrolled by one rcypher-based tool unlocks in another. Ignored without
    /// the `fido2` feature.
    pub fido2_rp_id: Option<&'a str>,
}

/// Interactively creates a new store from `config.factors`.
///
/// The first factor bootstraps the store and is required; the rest are *offered*
/// one at a time after it, so the user can decline each — and a missing security
/// key is skipped rather than fatal. With more than one factor enrolled, the user
/// then chooses whether *all* are required (AND) or *any one* suffices (OR).
/// Password factors show the unrecoverable-password warning on the first factor,
/// are confirmed and strength-gated, and re-prompt while a weak one is declined;
/// key factors are enrolled with a touch. `progress` brackets the bootstrap Argon2
/// derivation (pass [`NoProgress`](super::NoProgress) for none).
///
/// Returns the unlocked container; the caller saves it. The creation-side
/// counterpart to [`prompt_until_unlocked`](super::prompt_until_unlocked).
pub fn prompt_until_initialized<T: DataContainer>(
    data: T,
    config: &NewStoreConfig,
    argon2: &Argon2Params,
    progress: &mut dyn UnlockProgress,
) -> Result<UnlockedContainer<T>> {
    let (first, rest) = config
        .factors
        .split_first()
        .ok_or_else(|| anyhow!("at least one factor is required to create a store"))?;

    // The first factor bootstraps the store; it is required.
    let mut container = match first.kind {
        InitFactorKind::Password => {
            let password = prompt_factor_password(first.name, true)?;
            progress.start("Deriving encryption key");
            let created =
                UnlockedContainer::create_with_password(first.name, &password, data, argon2);
            progress.finish();
            drop(password);
            created?
        }
        #[cfg(feature = "fido2")]
        InitFactorKind::Fido2 => {
            let rp_id = fido2_rp_id(config);
            let (cred, require_pin) = register_fido2_credential(rp_id)?;
            UnlockedContainer::create_with_fido2(
                first.name,
                cred.credential_id,
                rp_id.to_string(),
                cred.salt,
                require_pin,
                &cred.raw_hmac_secret,
                data,
            )?
        }
    };

    // Offer each remaining factor after the store exists, recording which were
    // actually enrolled so the policy covers only those.
    let mut enrolled = vec![first.name];
    for factor in rest {
        let added = match factor.kind {
            InitFactorKind::Password => {
                if read_tty_confirmation(&format!(
                    "Add an additional password factor '{}'? [y/N]: ",
                    factor.name
                ))? {
                    let password = prompt_factor_password(factor.name, false)?;
                    container.enroll_password(factor.name, &password, argon2)?;
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "fido2")]
            InitFactorKind::Fido2 => offer_fido2(&mut container, factor.name, fido2_rp_id(config))?,
        };
        if added {
            enrolled.push(factor.name);
        }
    }

    // With more than one enrolled factor, let the user choose the policy.
    if enrolled.len() > 1 {
        let all = read_tty_confirmation(
            "Require ALL factors to unlock? [y/N] (No = any one of them) : ",
        )?;
        let joiner = if all { " and " } else { " or " };
        container.set_policy(&enrolled.join(joiner))?;
        eprintln!("Unlock policy: {}", container.policy_expr());
    }

    Ok(container)
}

/// Prompts for (and confirms) a new factor password, re-prompting while a weak one
/// is declined. `warn` shows the unrecoverable-password notice, for the first
/// factor of a brand-new store.
fn prompt_factor_password(name: &str, warn: bool) -> Result<Zeroizing<String>> {
    if warn {
        show_password_warning();
    }
    loop {
        let candidate = prompt_new_password(name)?;
        if confirm_if_weak_password(&candidate, &[name])? {
            return Ok(candidate);
        }
        eprintln!("Please choose a different password.");
    }
}

/// The relying-party id to enrol a key under: the caller's, or rcypher's default.
#[cfg(feature = "fido2")]
fn fido2_rp_id<'a>(config: &NewStoreConfig<'a>) -> &'a str {
    config.fido2_rp_id.unwrap_or(crate::fido2::DEFAULT_RP_ID)
}

/// Offers to enrol a FIDO2 key as factor `name`. Returns whether one was enrolled:
/// `false` if the user declines, and — so a missing or failing key never aborts a
/// store creation that already has a working factor — also `false` (with a notice)
/// if registering the credential fails.
#[cfg(feature = "fido2")]
fn offer_fido2<T: DataContainer>(
    container: &mut UnlockedContainer<T>,
    name: &str,
    rp_id: &str,
) -> Result<bool> {
    if !read_tty_confirmation(&format!(
        "Enrol a FIDO2 security key as the factor '{name}'? [y/N]: "
    ))? {
        return Ok(false);
    }
    match register_fido2_credential(rp_id) {
        Ok((cred, require_pin)) => {
            container.enroll_fido2(
                name,
                cred.credential_id,
                rp_id.to_string(),
                cred.salt,
                require_pin,
                &cred.raw_hmac_secret,
            )?;
            Ok(true)
        }
        Err(e) => {
            eprintln!("Could not enrol a security key: {e}");
            eprintln!("Continuing without it — add one later with 'auth factor add fido2'.");
            Ok(false)
        }
    }
}

/// Registers a fresh FIDO2 credential on the authenticator under `rp_id` (this does
/// not add a factor to any store): prompts for a PIN if the key has one, asks for a
/// touch, and returns the credential and whether a PIN is required. Errors if no
/// authenticator is connected.
#[cfg(feature = "fido2")]
fn register_fido2_credential(rp_id: &str) -> Result<(crate::fido2::EnrolledCredential, bool)> {
    // A PIN is usable only if one is set on the key — detect it rather than asking.
    // This is also the first device access, so a missing authenticator surfaces here.
    let require_pin = crate::fido2::device_has_pin()?;
    let pin = if require_pin {
        Some(prompt_password("Security key PIN")?)
    } else {
        eprintln!("This key has no PIN set — the factor will unlock with a touch only.");
        None
    };
    eprintln!("Touch your FIDO2 security key to enrol it…");
    let cred = crate::fido2::enroll(rp_id, pin.as_ref().map(|p| p.as_str()))?;
    Ok((cred, require_pin))
}
