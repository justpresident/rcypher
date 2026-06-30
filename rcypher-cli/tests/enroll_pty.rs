//! PTY-driven end-to-end tests for the interactive auth commands (factor
//! enrollment, transparent legacy conversion, multi-factor unlock).
//!
//! Their password prompts are read from `/dev/tty` (so a snooped pipe can't
//! capture them), which the stdin-based `cli_tests` cannot drive. Here the binary
//! is run under a real pseudo-terminal so the prompts can be answered.

use std::fs;
use std::path::Path;
use std::process::Command;

use assert_cmd::cargo;
use rcypher::{
    Argon2Params, Cypher, CypherVersion, EncryptedValue, EncryptionKey, LockedContainer,
    SecretStore, UnlockedContainer,
};
use rexpect::session::{PtySession, spawn_command};
use tempfile::TempDir;

// A passphrase zxcvbn rates as strong, so the weak-password prompt is skipped.
const STRONG_PASSWORD: &str = "Vermilion-Trombone-Glacier-Quartz-581";

/// Writes a version-8 single-password store with no entries, with insecure Argon2
/// params so the binary's `--insecure-password` path unlocks it quickly and a
/// newly enrolled factor derives fast.
fn create_store(path: &Path, factor_name: &str, password: &str) {
    let mut store = UnlockedContainer::create_with_password(
        factor_name,
        password,
        SecretStore::new(),
        &Argon2Params::insecure(),
    )
    .unwrap();
    store.save(path).unwrap();
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
    let mut storage = SecretStore::new();
    storage.put(
        key.to_string(),
        EncryptedValue::encrypt(&cypher, value).unwrap(),
    );
    storage.save(&cypher, path).unwrap();
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

#[test]
fn put_history_replays_the_command_without_its_value() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);
    p.send_line("put account").unwrap();
    p.exp_string("echoed; not saved in history").unwrap();
    p.send_line("first-value").unwrap();
    p.exp_string("account stored").unwrap();

    // Up recalls the sanitized command. If the value were retained instead,
    // executing the recalled line would not produce another value prompt.
    p.send("\x1b[A").unwrap();
    p.send_line("").unwrap();
    p.exp_string("Value for 'account'").unwrap();
    p.send_line("second-value").unwrap();
    p.exp_string("account stored").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn failed_command_is_recorded_and_recallable() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);
    // A `get` for a missing key fails…
    p.send_line("get no-such-key").unwrap();
    p.exp_string("No keys matching 'no-such-key' found")
        .unwrap();
    // …but the failed command is still recorded, so Up recalls it for a quick fix.
    p.send("\x1b[A").unwrap();
    p.send_line("").unwrap();
    p.exp_string("No keys matching 'no-such-key' found")
        .unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn value_prompt_has_no_history_navigation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);
    // Put a command (and its key) into the session history first.
    p.send_line("put first").unwrap();
    p.exp_string("echoed; not saved in history").unwrap();
    p.send_line("first-value").unwrap();
    p.exp_string("first stored").unwrap();

    // At the value prompt, Up must be a no-op: its editor carries no history, so it
    // can't recall a previous command line into the value.
    p.send_line("put second").unwrap();
    p.exp_string("Value for 'second'").unwrap();
    p.send("\x1b[A").unwrap();
    p.send_line("second-value").unwrap();
    p.exp_string("second stored").unwrap();

    // The stored value is exactly what was typed — Up injected nothing.
    p.send_line("get second").unwrap();
    p.exp_string("second: second-value").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn killed_value_text_does_not_leak_into_a_later_command() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);
    p.send_line("put secret-key").unwrap();
    p.exp_string("Value for 'secret-key'").unwrap();
    // Type a secret, then kill the whole line (Ctrl-U) into the value editor's kill
    // ring, and submit an empty value.
    p.send("supersecretvalue").unwrap();
    p.send_control('u').unwrap();
    p.send_line("").unwrap();
    p.exp_string("secret-key stored").unwrap();

    // Back at the main prompt, yank (Ctrl-Y). The session editor's kill ring is
    // separate from the (now dropped) value editor's, so nothing is pasted: the
    // command we run is exactly `zzz`, never the killed secret.
    p.send_control('y').unwrap();
    p.send_line("zzz").unwrap();
    p.exp_string("No such command 'zzz'").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}

/// Creating a store with no `--insecure-password` runs the library's interactive
/// new-store flow: the FIDO2 offer (this build has the feature), then a prompted
/// primary password, then a live session.
#[cfg(feature = "fido2")]
#[test]
fn interactive_create_prompts_then_opens_a_session() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fresh-vault");

    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.args(["--quiet", "--insecure-stdout", "--insecure-allow-debugging"]);
    cmd.arg(&path);
    cmd.env("TERM", "xterm");
    let mut p = spawn_command(cmd, Some(30_000)).expect("spawn under PTY");

    // The password is prompted first (a strong one skips the weak-password gate)…
    p.exp_string("New password for primary").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    // …then the library offers a key, which we decline (no device here anyway).
    p.exp_string("Enrol a FIDO2 security key").unwrap();
    p.send_line("n").unwrap();

    // A single factor needs no policy prompt — the session is live.
    p.send_line("put k").unwrap();
    p.exp_string("echoed; not saved in history").unwrap();
    p.send_line("v").unwrap();
    p.exp_string("k stored").unwrap();
    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // The store now exists in the current (v8) format.
    let head = fs::read(&path).unwrap();
    assert_eq!(&head[..2], &[0u8, 8]);
}

/// True iff `password` unlocks the store at `path` and, after unlock, the factor
/// named `name` is present — exercising the public load/unlock path. (Factor names
/// are opaque encrypted ids pre-unlock, so the name is verified after unlocking.)
fn unlocks_with(path: &Path, name: &str, password: &str) -> bool {
    let data = std::fs::read(path).unwrap();
    let Ok(mut locked) = LockedContainer::from_slice_with_params(&data, &Argon2Params::insecure())
    else {
        return false;
    };
    if !matches!(locked.try_password(password), Ok(true)) || !locked.can_unlock() {
        return false;
    }
    locked
        .unlock::<SecretStore>()
        .is_ok_and(|store| store.factor_names().contains(&name.to_string()))
}

#[test]
fn enroll_password_via_pty_persists_a_working_factor() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    // Enroll a new (strong) password factor through the interactive TTY prompts.
    p.send_line("auth factor add password backup").unwrap();
    p.exp_string("New password for factor 'backup'").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Confirm password").unwrap();
    p.send_line(STRONG_PASSWORD).unwrap();
    p.exp_string("Factor 'backup' enrolled").unwrap();

    // Make the new factor usable: either factor now unlocks the store.
    p.send_line("auth policy set primary or backup").unwrap();
    p.exp_string("Policy: primary or backup").unwrap();

    p.send_line("auth factor list").unwrap();
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
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    // The footgun: a password typed where the factor NAME belongs, then repeated
    // at the prompt. The store must refuse rather than persist it as a label.
    p.send_line("auth factor add password hunter2").unwrap();
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
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    // A "too guessable" password (zxcvbn score 0) — like the factor name, the app
    // name, or "abc123" — is refused outright, with no override prompt.
    p.send_line("auth factor add password backup").unwrap();
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
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    p.send_line("auth factor add password backup").unwrap();
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
    create_store(&path, "primary", "test_password");

    let mut p = spawn_session(&path);

    p.send_line("auth factor add password backup").unwrap();
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
    p.send_line("auth policy set primary or backup").unwrap();
    p.exp_string("Policy: primary or backup").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // The weak password was accepted and works as the factor's secret.
    assert!(unlocks_with(&path, "backup", "letmein99"));
}

#[test]
fn legacy_store_auto_converts_and_backs_up_on_write() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault");
    create_legacy_store_with_value(&path, "k", "v");

    // Initially a legacy version-7 store (not yet in the version-8 format).
    let head = fs::read(&path).unwrap();
    assert_eq!(&head[..2], &[0u8, 7] /* V7 tag */);

    let mut p = spawn_session(&path);

    // Opening a legacy store announces the in-memory conversion to the current format.
    p.exp_string("Legacy store format detected").unwrap();

    // The first write triggers the upgrade: rewrites the file as v8 and backs up
    // the original. The pre-existing value survives the re-encryption, and auth
    // commands work because the converted store carries a real multi-factor policy in memory.
    p.send_line("put x").unwrap();
    p.exp_string("echoed; not saved in history").unwrap();
    p.send_line("y").unwrap();
    p.exp_string("x stored").unwrap();
    p.send_line("auth factor list").unwrap();
    p.exp_string("primary (password)").unwrap();
    p.send_line("get k").unwrap();
    p.exp_string("k: v").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();

    // On disk it is now in the version-8 format, unlockable with the original
    // password (now the 'primary' factor)...
    let head = fs::read(&path).unwrap();
    assert_eq!(&head[..2], &[0u8, 8] /* V8 tag */);
    assert!(unlocks_with(&path, "primary", "test_password"));

    // ...and the untouched original is preserved as a <path>.bak (still v7).
    let bak = {
        let mut p = path.clone().into_os_string();
        p.push(".bak");
        std::path::PathBuf::from(p)
    };
    assert!(bak.exists(), "expected a .bak backup of the original");
    assert_eq!(&fs::read(&bak).unwrap()[..2], &[0u8, 7] /* V7 tag */);
}

const P1_PASSWORD: &str = "alpha-one-vault-secret";
const P2_PASSWORD: &str = "bravo-two-vault-secret";

/// Writes a version-8 vault requiring BOTH `p1` and `p2` password factors.
fn create_and_vault(path: &Path) {
    let mut store = UnlockedContainer::create_with_password(
        "p1",
        P1_PASSWORD,
        SecretStore::new(),
        &Argon2Params::insecure(),
    )
    .unwrap();
    store
        .enroll_password("p2", P2_PASSWORD, &Argon2Params::insecure())
        .unwrap();
    store.set_policy("p1 and p2").unwrap();
    store.save(path).unwrap();
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
    // (The exact tail varies with the `fido2` feature, so match the stable prefix.)
    p.exp_string("Password (empty").unwrap();
    p.send_line("totally-wrong-password").unwrap();
    p.exp_string("did not match any factor").unwrap();

    // Either password works in any order; a match is reported generically (factor
    // names are hidden until unlock), and the AND policy keeps asking until satisfied.
    p.send_line(P2_PASSWORD).unwrap();
    p.exp_string("Factor unlocked").unwrap();
    p.exp_string("More factors are required").unwrap();
    p.send_line(P1_PASSWORD).unwrap();
    p.exp_string("Factor unlocked").unwrap();

    // Unlocked: the interactive session is live.
    p.send_line("put k").unwrap();
    p.exp_string("echoed; not saved in history").unwrap();
    p.send_line("v").unwrap();
    p.exp_string("k stored").unwrap();
    p.send_line("get k").unwrap();
    p.exp_string("k: v").unwrap();

    p.send_control('d').unwrap();
    p.exp_eof().unwrap();
}
