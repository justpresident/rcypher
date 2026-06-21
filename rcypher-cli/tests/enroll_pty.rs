//! PTY-driven end-to-end tests for the in-store `enroll password` command.
//!
//! Its password prompt is read from `/dev/tty` (so a snooped pipe can't capture
//! it), which the stdin-based `cli_tests` cannot drive. Here the binary is run
//! under a real pseudo-terminal so the prompts can be answered.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use assert_cmd::cargo;
use rcypher::{
    Argon2Params, Cypher, CypherVersion, EncryptedValue, EncryptionKey, FactorSecret, PolicyVault,
    Storage, save_storage, serialize_storage,
};
use rexpect::session::{PtySession, spawn_command};
use tempfile::TempDir;
use zeroize::Zeroizing;

// A passphrase zxcvbn rates as strong, so the weak-password prompt is skipped.
const STRONG_PASSWORD: &str = "Vermilion-Trombone-Glacier-Quartz-581";

/// Writes a version-8 single-password policy vault holding an empty store, with
/// insecure Argon2 params so the binary's `--insecure-password` path unlocks it
/// quickly and a newly enrolled factor derives fast.
fn create_policy_vault(path: &Path, factor_id: &str, password: &str) {
    let vault = PolicyVault::create(factor_id, password, &Argon2Params::insecure()).unwrap();
    let payload = serialize_storage(&Storage::new()).unwrap();
    vault.save(&payload, path).unwrap();
}

/// Writes a legacy version-7 single-password store holding `key`=`value`,
/// encrypted with "test_password" under insecure Argon2 params.
fn create_legacy_store_with_value(path: &Path, key: &str, value: &str) {
    let enc_key = EncryptionKey::from_password_with_params(
        CypherVersion::default(),
        "test_password",
        &Argon2Params::insecure(),
    )
    .unwrap();
    let cypher = Cypher::new(enc_key);
    let mut storage = Storage::new();
    storage.put(
        key.to_string(),
        EncryptedValue::encrypt(&cypher, value).unwrap(),
    );
    save_storage(&cypher, &storage, path).unwrap();
}

/// Spawns the binary against `path` under a PTY. `--insecure-password` unlocks
/// without the TTY unlock prompt; the enroll command's own prompts still use the
/// PTY.
fn spawn_session(path: &Path) -> PtySession {
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.args([
        "--quiet",
        "--insecure-stdout",
        "--insecure-password",
        "test_password",
        "--insecure-allow-debugging",
    ]);
    cmd.arg(path);
    cmd.env("TERM", "xterm");
    spawn_command(cmd, Some(30_000)).expect("spawn under PTY")
}

fn unlocks_with(path: &Path, id: &str, password: &str) -> bool {
    let secrets: HashMap<String, FactorSecret> = [(
        id.to_string(),
        FactorSecret::Password(Zeroizing::new(password.to_string())),
    )]
    .into_iter()
    .collect();
    PolicyVault::open(path, &secrets).is_ok()
}

#[test]
fn enroll_password_via_pty_persists_a_working_factor() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    // Enroll a new (strong) password factor through the interactive TTY prompts.
    p.send_line("enroll password backup").unwrap();
    p.exp_string("New password for factor 'backup'").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Factor 'backup' enrolled").unwrap();

    // Make the new factor usable: either factor now unlocks the store.
    p.send_line("policy set primary or backup").unwrap();
    p.exp_string("Policy: primary or backup").unwrap();

    p.send_line("factors").unwrap();
    p.exp_string("backup (password)").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // The enrolled factor was persisted and really works.
    assert!(unlocks_with(&path, "backup", STRONG_PASSWORD));
}

#[test]
fn enroll_rejects_password_typed_as_factor_name() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    // The footgun: a password typed where the factor NAME belongs, then repeated
    // at the prompt. The store must refuse rather than persist it as a label.
    p.send_line("enroll password hunter2").unwrap();
    p.exp_string("New password for factor 'hunter2'").unwrap();
    p.send_line("hunter2").unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line("hunter2").unwrap();
    p.exp_string("too similar").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    assert!(!unlocks_with(&path, "hunter2", "hunter2"));
}

#[test]
fn enroll_trivially_weak_password_is_hard_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    // A "too guessable" password (zxcvbn score 0) — like the factor name, the app
    // name, or "abc123" — is refused outright, with no override prompt.
    p.send_line("enroll password backup").unwrap();
    p.exp_string("New password for factor 'backup'").unwrap();
    p.send_line("abc123").unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line("abc123").unwrap();
    p.exp_string("too weak").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    assert!(!unlocks_with(&path, "backup", "abc123"));
}

#[test]
fn enroll_weak_password_warns_and_can_be_declined() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    p.send_line("enroll password backup").unwrap();
    p.exp_string("New password for factor 'backup'").unwrap();
    p.send_line("letmein99").unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line("letmein99").unwrap();

    // A weak password triggers the warning; declining cancels enrollment.
    p.exp_string("WEAK PASSWORD").unwrap();
    p.exp_string("anyway").unwrap();
    p.send_line("n").unwrap();
    p.exp_string("cancelled").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    assert!(!unlocks_with(&path, "backup", "letmein99"));
}

#[test]
fn enroll_weak_password_accepted_after_double_confirm() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    p.send_line("enroll password backup").unwrap();
    p.exp_string("New password for factor 'backup'").unwrap();
    p.send_line("letmein99").unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line("letmein99").unwrap();

    // The double confirmation lets a determined user proceed anyway.
    p.exp_string("WEAK PASSWORD").unwrap();
    p.exp_string("anyway").unwrap();
    p.send_line("y").unwrap();
    p.exp_string("are you sure").unwrap();
    p.send_line("y").unwrap();
    p.exp_string("Factor 'backup' enrolled").unwrap();

    // Reference the new factor in the policy so it can unlock on its own.
    p.send_line("policy set primary or backup").unwrap();
    p.exp_string("Policy: primary or backup").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // The weak password was accepted and works as the factor's secret.
    assert!(unlocks_with(&path, "backup", "letmein99"));
}

#[test]
fn upgrade_legacy_store_to_policy_vault() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_legacy_store_with_value(&path, "k", "v");

    // Initially a legacy version-7 store (not a version-8 policy vault).
    let head = fs::read(&path).unwrap();
    assert_ne!(&head[..2], &rcypher::POLICY_VAULT_VERSION.to_be_bytes());

    let mut p = spawn_session(&path);

    p.send_line("upgrade").unwrap();
    p.exp_string("New password for the upgraded store").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Upgraded to a multi-factor policy vault")
        .unwrap();

    // Auth commands now work, and the existing value survives the re-encryption.
    p.send_line("factors").unwrap();
    p.exp_string("primary (password)").unwrap();
    p.send_line("get k").unwrap();
    p.exp_string("k: v").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // On disk it is now a version-8 policy vault, unlockable with the new password.
    let head = fs::read(&path).unwrap();
    assert_eq!(&head[..2], &rcypher::POLICY_VAULT_VERSION.to_be_bytes());
    assert!(unlocks_with(&path, "primary", STRONG_PASSWORD));
}

#[test]
fn upgrade_rejected_on_a_policy_vault() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut p = spawn_session(&path);
    p.send_line("upgrade").unwrap();
    p.exp_string("already a multi-factor policy vault").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}

const P1_PASSWORD: &str = "alpha-one-vault-secret";
const P2_PASSWORD: &str = "bravo-two-vault-secret";

/// Writes a version-8 vault requiring BOTH `p1` and `p2` password factors.
fn create_and_vault(path: &Path) {
    let mut vault = PolicyVault::create("p1", P1_PASSWORD, &Argon2Params::insecure()).unwrap();
    vault
        .enroll_password("p2", P2_PASSWORD, &Argon2Params::insecure())
        .unwrap();
    vault.set_policy("p1 and p2").unwrap();
    let payload = serialize_storage(&Storage::new()).unwrap();
    vault.save(&payload, path).unwrap();
}

/// Spawns the binary under a PTY without `--insecure-password`, so the multi-
/// factor unlock prompts interactively.
fn spawn_interactive_unlock(path: &Path) -> PtySession {
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.args(["--quiet", "--insecure-stdout", "--insecure-allow-debugging"]);
    cmd.arg(path);
    cmd.env("TERM", "xterm");
    spawn_command(cmd, Some(30_000)).expect("spawn under PTY")
}

#[test]
fn interactive_unlock_prompts_generically_and_loops() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_and_vault(&path);

    let mut p = spawn_interactive_unlock(&path);

    // One generic prompt (not per-factor); a wrong password is reported and retried.
    p.exp_string("Password (empty to cancel)").unwrap();
    p.send_line("totally-wrong-password").unwrap();
    p.exp_string("did not match any factor").unwrap();

    // Either password works in any order; each unlock is reported, and the AND
    // policy keeps asking until it is satisfied.
    p.send_line(P2_PASSWORD).unwrap();
    p.exp_string("Factor 'p2' unlocked").unwrap();
    p.exp_string("More factors are required").unwrap();
    p.send_line(P1_PASSWORD).unwrap();
    p.exp_string("Factor 'p1' unlocked").unwrap();

    // Unlocked: the interactive session is live.
    p.send_line("put k v").unwrap();
    p.exp_string("k stored").unwrap();
    p.send_line("get k").unwrap();
    p.exp_string("k: v").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}
