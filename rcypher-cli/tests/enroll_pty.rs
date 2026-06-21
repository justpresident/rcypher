//! PTY-driven end-to-end test for the in-store `enroll password` command.
//!
//! Its password prompt is read from `/dev/tty` (so a snooped pipe can't capture
//! it), which the stdin-based `cli_tests` cannot drive. Here the binary is run
//! under a real pseudo-terminal so the prompt can be answered.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use assert_cmd::cargo;
use rcypher::{Argon2Params, FactorSecret, PolicyVault, Storage, serialize_storage};
use rexpect::session::spawn_command;
use tempfile::TempDir;

/// Writes a version-8 single-password policy vault holding an empty store, with
/// insecure Argon2 params so the binary's `--insecure-password` path unlocks it
/// quickly and a newly enrolled factor derives fast.
fn create_policy_vault(path: &Path, factor_id: &str, password: &str) {
    let vault = PolicyVault::create(factor_id, password, &Argon2Params::insecure()).unwrap();
    let payload = serialize_storage(&Storage::new()).unwrap();
    vault.save(&payload, path).unwrap();
}

#[test]
fn enroll_password_via_pty_persists_a_working_factor() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    // `--insecure-password` unlocks without the TTY unlock prompt; the enroll
    // command's own password prompt still reads from the PTY below.
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.args([
        "--quiet",
        "--insecure-stdout",
        "--insecure-password",
        "test_password",
        "--insecure-allow-debugging",
    ]);
    cmd.arg(&path);
    cmd.env("TERM", "xterm");

    let mut p = spawn_command(cmd, Some(30_000)).expect("spawn under PTY");

    // Enroll a new password factor through the interactive TTY prompts.
    p.send_line("enroll password backup").unwrap();
    p.exp_string("New password for factor 'backup'").unwrap();
    p.send_line("backup_pw").unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line("backup_pw").unwrap();
    p.exp_string("Factor 'backup' enrolled").unwrap();

    // Make the new factor usable: either factor now unlocks the store.
    p.send_line("policy set primary or backup").unwrap();
    p.exp_string("Policy: primary or backup").unwrap();

    p.send_line("factors").unwrap();
    p.exp_string("backup (password)").unwrap();

    // Exit the session (Ctrl-D → EOF).
    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // The enrolled factor was persisted and really works: the store now unlocks
    // with the backup password alone.
    let secrets: HashMap<String, FactorSecret> = [(
        "backup".to_string(),
        FactorSecret::Password("backup_pw".to_string()),
    )]
    .into_iter()
    .collect();
    let (vault, _payload) = PolicyVault::open(&path, &secrets).expect("unlock via enrolled factor");
    assert!(vault.factor_ids().contains(&"backup".to_string()));
}

#[test]
fn enroll_rejects_password_typed_as_factor_name() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_policy_vault(&path, "primary", "test_password");

    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.args([
        "--quiet",
        "--insecure-stdout",
        "--insecure-password",
        "test_password",
        "--insecure-allow-debugging",
    ]);
    cmd.arg(&path);
    cmd.env("TERM", "xterm");

    let mut p = spawn_command(cmd, Some(30_000)).expect("spawn under PTY");

    // The footgun: a password typed where the factor NAME belongs, then repeated
    // at the prompt. The store must refuse rather than persist it as a label.
    p.send_line("enroll password hunter2").unwrap();
    p.exp_string("New password for factor 'hunter2'").unwrap();
    p.send_line("hunter2").unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line("hunter2").unwrap();
    p.exp_string("must differ").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // Nothing named 'hunter2' was enrolled.
    let secrets: HashMap<String, FactorSecret> = [(
        "hunter2".to_string(),
        FactorSecret::Password("hunter2".to_string()),
    )]
    .into_iter()
    .collect();
    assert!(PolicyVault::open(&path, &secrets).is_err());
}
