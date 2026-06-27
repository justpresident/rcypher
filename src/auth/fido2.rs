//! FIDO2 device I/O: obtaining a factor's `hmac-secret` from a security key over
//! USB-HID (CTAP2).
//!
//! Compiled only with the `fido2` feature; the pure FIDO2 KEK and the enroll/unlock
//! primitives (in the sibling `factor` and `vault` modules) need no hardware and are
//! always available.
//!
//! This is the one place rcypher talks to a device. Enrollment runs a
//! `make_credential` with the `hmac-secret` extension (a *non-resident* credential —
//! the key stores no rcypher state) and then one `get_assertion` to read the initial
//! secret. Unlock runs `get_assertion` with the stored `credential_id` and the
//! per-factor `salt`. Both require a user touch; a PIN is supplied (`pin = Some`)
//! when the factor requires user verification.
//!
//! The device calls target `ctap-hid-fido2` 3.5 (the `Extension::HmacSecret` request
//! carries the 32-byte salt; the authenticator returns the 32-byte output in the
//! assertion's `extensions`). This module is exercised against real hardware by the
//! maintainer — it cannot be built in a sandbox without `libudev`/`hidapi`.

use anyhow::{Result, anyhow, bail};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::{
    Assertion, Extension as GetExt,
};
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as MakeExt;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};
use rand::TryRngCore;
use zeroize::Zeroizing;

use crate::constants::{HMAC_SECRET_LEN, HmacSecretBytes, SALT_SIZE, SaltBytes};

/// A FIDO2 credential enrolled for an rcypher factor, plus the `hmac-secret` it
/// currently yields.
///
/// The secret is consumed once at enrollment to wrap the factor's policy share; the
/// `credential_id` and `salt` are stored in the factor and replayed at unlock.
pub struct EnrolledCredential {
    /// The authenticator's credential handle.
    pub credential_id: Vec<u8>,
    /// The per-factor `hmac-secret` salt generated here.
    pub salt: SaltBytes,
    /// The `hmac-secret` output for `salt` — the FIDO2 factor's auth-KEK input.
    /// Wiped on drop.
    pub raw_hmac_secret: Zeroizing<HmacSecretBytes>,
}

/// Opens the first connected FIDO2 authenticator.
fn open_device() -> Result<FidoKeyHid> {
    FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| anyhow!("no FIDO2 authenticator found: {e}"))
}

/// Whether the connected authenticator has a client PIN configured.
///
/// A PIN can only be presented if one is actually set on the key; otherwise enrol
/// and unlock must run touch-only. Lets a caller decide whether to prompt for a PIN
/// before [`enroll`]/[`hmac_secret`], rather than guessing.
pub fn device_has_pin() -> Result<bool> {
    Ok(open_device()?.enable_info_option(&InfoOption::ClientPin)? == Some(true))
}

/// A fresh random challenge. rcypher does not verify attestation (the key is a
/// secret source, not an asserted identity), so the challenge only needs to be
/// unpredictable, never replayed.
fn fresh_challenge() -> Result<[u8; SALT_SIZE]> {
    let mut challenge = [0u8; SALT_SIZE];
    rand::rngs::OsRng.try_fill_bytes(&mut challenge)?;
    Ok(challenge)
}

/// Enrolls a new `hmac-secret` credential on the connected authenticator and reads
/// its initial secret.
///
/// Requires a user touch; pass `pin = Some(_)` to create a PIN/uv-protected
/// credential. `rp_id` (e.g. `"rcypher"`) is bound into it.
pub fn enroll(rp_id: &str, pin: Option<&str>) -> Result<EnrolledCredential> {
    let device = open_device()?;
    let challenge = fresh_challenge()?;

    let builder = MakeCredentialArgsBuilder::new(rp_id, &challenge)
        .extensions(&[MakeExt::HmacSecret(Some(true))]);
    // A PIN is usable only if one is actually set on the key. With a PIN we do user
    // verification; without one the credential is touch-only (`without_pin_and_uv`).
    // Calling `.pin()` on a PIN-less key fails with CTAP2_ERR_PIN_NOT_SET, and
    // omitting both fails with CTAP2_ERR_UNSUPPORTED_OPTION.
    let builder = match pin {
        Some(pin) => builder.pin(pin),
        None => builder.without_pin_and_uv(),
    };
    let attestation = device
        .make_credential_with_args(&builder.build())
        .map_err(|e| anyhow!("FIDO2 registration (make_credential) failed: {e:#}"))?;

    let credential_id = attestation.credential_descriptor.id;
    if credential_id.is_empty() {
        bail!("the authenticator returned an empty credential id");
    }

    // A per-factor salt and the secret it currently produces, to wrap the share.
    let mut salt = SaltBytes::default();
    rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
    let raw_hmac_secret = hmac_secret(&credential_id, rp_id, &salt, pin)?;
    Ok(EnrolledCredential {
        credential_id,
        salt,
        raw_hmac_secret,
    })
}

/// Reads the `hmac-secret` output for an enrolled credential and `salt`.
///
/// This is the input to the factor's auth-KEK at unlock. Requires a user touch; pass
/// `pin = Some(_)` when the factor requires user verification.
pub fn hmac_secret(
    credential_id: &[u8],
    rp_id: &str,
    salt: &SaltBytes,
    pin: Option<&str>,
) -> Result<Zeroizing<HmacSecretBytes>> {
    let device = open_device()?;
    let challenge = fresh_challenge()?;

    let builder = GetAssertionArgsBuilder::new(rp_id, &challenge)
        .credential_id(credential_id)
        .extensions(&[GetExt::HmacSecret(Some(*salt))]);
    let builder = match pin {
        Some(pin) => builder.pin(pin),
        None => builder.without_pin_and_uv(),
    };
    let assertions = device
        .get_assertion_with_args(&builder.build())
        .map_err(|e| assertion_error(&e, pin.is_some()))?;

    read_hmac_secret(&assertions)
}

/// Wraps a `get_assertion` failure with the underlying CTAP cause and — when it
/// looks like a PIN / user-verification mismatch — a hint that the key's uv policy
/// may no longer match how this factor was enrolled.
///
/// An `hmac-secret` credential has two secrets, one used when user verification is
/// performed and one when it is not, so a factor enrolled touch-only can't be read
/// if the key was later set to always require uv, and one enrolled with a PIN can't
/// be read if that PIN was removed (see `docs/auth-protocol.md`).
fn assertion_error(cause: &anyhow::Error, used_pin: bool) -> anyhow::Error {
    let cause = format!("{cause:#}");
    let looks_like_uv_mismatch = ["0x35", "0x36", "0x37", "PIN", "UV", "verification"]
        .iter()
        .any(|needle| cause.contains(needle));
    if !looks_like_uv_mismatch {
        return anyhow!("FIDO2 authentication (get_assertion) failed: {cause}");
    }
    let detail = if used_pin {
        "this factor was enrolled with a PIN; if the key's PIN was since removed or reset, \
         its hmac-secret is no longer reachable"
    } else {
        "this factor was enrolled touch-only; if the key was since set to always require \
         user verification, its hmac-secret is no longer reachable"
    };
    anyhow!(
        "FIDO2 authentication (get_assertion) failed: {cause}. {detail} — unlock via another \
         factor and re-enrol this key."
    )
}

/// Extracts the 32-byte `hmac-secret` output the authenticator returned in the
/// assertion's extensions, in a zeroizing buffer.
fn read_hmac_secret(assertions: &[Assertion]) -> Result<Zeroizing<HmacSecretBytes>> {
    let assertion = assertions
        .first()
        .ok_or_else(|| anyhow!("the authenticator returned no assertion"))?;
    for ext in &assertion.extensions {
        if let GetExt::HmacSecret(Some(output)) = ext {
            // The crate's payload is [u8; 32]; assert the contract on our alias.
            debug_assert_eq!(output.len(), HMAC_SECRET_LEN);
            return Ok(Zeroizing::new(*output));
        }
    }
    bail!("the assertion carried no hmac-secret output (does the key support the extension?)")
}
