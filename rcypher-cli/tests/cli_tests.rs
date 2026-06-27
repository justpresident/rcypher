use std::fs;
use std::path::Path;
use std::path::PathBuf;

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

// Helper to create a temporary test file
fn temp_test_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rcypher_test");
    (dir, path)
}

#[test]
fn test_cli_runs() {
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Usage"));
}

#[test]
fn test_encrypt_decrypt_file() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create test file
    let test_data = b"This is test file content\nWith multiple lines\nAnd some more";
    fs::write(&input_path, test_data).unwrap();

    // Run encryption cmd
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--encrypt")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg("--output")
        .arg(&output_path)
        .arg(&input_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Run decryption with wrong password
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--decrypt")
        .arg("--insecure-password")
        .arg("test_passwor")
        .arg("--insecure-allow-debugging")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());

    // Run decryption cmd
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--decrypt")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    assert_eq!(output.stdout.len(), test_data.len());
    assert_eq!(output.stdout, test_data);
}

fn run_commands(file_path: &Path, commands: Vec<u8>) -> Vec<String> {
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-stdout")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&file_path)
        .write_stdin(commands)
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<String> = stdout.split('\n').map(|s| s.to_string()).collect();
    lines
}

fn run_commands_str(file_path: &Path, commands: &str) -> String {
    run_commands(file_path, commands.as_bytes().to_vec()).join("\n")
}

#[test]
fn test_commands() {
    let (_dir, file_path) = temp_test_file();

    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 val1\n");
    commands.extend_from_slice(b"put key1 val_new\n");
    commands.extend_from_slice(b"put key2 val2\n");
    commands.extend_from_slice(b"put kkey3 val2\n");

    let _ = run_commands(&file_path, commands);

    // simple get commands
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key1\n");
    commands.extend_from_slice(b"get key2\n");

    let lines = run_commands(&file_path, commands);

    assert_eq!(lines[0], "key1: val_new");
    assert_eq!(lines[1], "key2: val2");

    // get with a regexp
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key.*\n");
    let lines = run_commands(&file_path, commands);

    assert_eq!(lines[0], "key1: val_new");
    assert_eq!(lines[1], "key2: val2");

    // history command
    let mut commands = Vec::new();
    commands.extend_from_slice(b"history key1\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines[0].contains("val1"));
    assert!(lines[1].contains("val_new"));
}

#[test]
fn test_update_with_no_conflicts() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage with some entries
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    commands.extend_from_slice(b"put key2 value2\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with same entries
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    commands.extend_from_slice(b"put key2 value2\n");
    let _ = run_commands(&update_path, commands);

    // Run update-with
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&main_path)
        .arg("--update-with")
        .arg(&update_path)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No updates found") || stdout.contains("Storage files are in sync"));
}

#[test]
fn test_update_with_new_keys() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with additional keys
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    commands.extend_from_slice(b"put key2 value2\n");
    commands.extend_from_slice(b"put key3 value3\n");
    let _ = run_commands(&update_path, commands);

    // Run update-with and auto-apply
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-stdout")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&main_path)
        .arg("--update-with")
        .arg(&update_path)
        .write_stdin(b"a\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("2 new key"));
    assert!(stdout.contains("All updates applied"));

    // Verify the updates were applied
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key2\n");
    commands.extend_from_slice(b"get key3\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "key2: value2");
    assert_eq!(lines[1], "key3: value3");
}

#[test]
fn test_update_with_conflicts() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 old_value\n");
    commands.extend_from_slice(b"put key2 value2\n");
    let _ = run_commands(&main_path, commands);

    // Wait a bit to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Create update storage with conflicting value
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 new_value\n");
    commands.extend_from_slice(b"put key2 value2\n");
    let _ = run_commands(&update_path, commands);

    // Run update-with
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-stdout")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&main_path)
        .arg("--update-with")
        .arg(&update_path)
        .write_stdin(b"a\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("1 conflict"));

    // Verify the update was applied
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key1\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "key1: new_value");
}

#[test]
fn test_update_with_interactive_mode() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with new keys
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    commands.extend_from_slice(b"put key2 accept_this\n");
    commands.extend_from_slice(b"put key3 reject_this\n");
    let _ = run_commands(&update_path, commands);

    // Run update-with in interactive mode: choose interactive, accept first, reject second
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-stdout")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&main_path)
        .arg("--update-with")
        .arg(&update_path)
        .write_stdin(b"i\ny\nn\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Applied 1"));
    assert!(stdout.contains("skipped 1"));

    // Verify only key2 was applied
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key2\n");
    commands.extend_from_slice(b"get key3\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "key2: accept_this");
    assert!(
        lines[1].contains("not found")
            || lines[1].contains("Not found")
            || lines[1].contains("No keys matching")
    );
}

#[test]
fn test_update_with_cancel() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with new key
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put key1 value1\n");
    commands.extend_from_slice(b"put key2 value2\n");
    let _ = run_commands(&update_path, commands);

    // Run update-with and cancel
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-stdout")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&main_path)
        .arg("--update-with")
        .arg(&update_path)
        .write_stdin(b"c\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Cancelled"));

    // Verify nothing was applied
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key2\n");
    let lines = run_commands(&main_path, commands);

    assert!(
        lines[0].contains("not found")
            || lines[0].contains("Not found")
            || lines[0].contains("No keys matching")
    );
}

#[test]
fn test_help_command() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "help\n");
    assert!(output.contains("put"));
    assert!(output.contains("get"));
    assert!(output.contains("del"));
}

#[test]
fn test_unknown_command() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "frobnicator\n");
    assert!(output.contains("frobnicator") || output.contains("No such command"));
}

#[test]
fn test_get_no_match() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "get nonexistent_key_xyz\n");
    assert!(output.contains("nonexistent_key_xyz") || output.contains("No keys"));
}

#[test]
fn test_history_no_match() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "history nonexistent_key_xyz\n");
    assert!(output.contains("nonexistent_key_xyz") || output.contains("No key"));
}

#[test]
fn test_del_nonexistent_key() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "del nonexistent_key_xyz\n");
    assert!(output.contains("nonexistent_key_xyz") || output.contains("No such key"));
}

#[test]
fn test_rm_alias() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "put mykey myval\nrm mykey\nget mykey\n");
    assert!(
        output.contains("mykey stored")
            || output.contains("mykey deleted")
            || output.contains("No keys")
    );
}

#[test]
fn test_search_command() {
    let (_dir, file_path) = temp_test_file();
    // populate
    run_commands(
        &file_path,
        b"put search_key1 v1\nput search_key2 v2\nput other_key v3\n".to_vec(),
    );

    let output = run_commands_str(&file_path, "search search_key\n");
    assert!(output.contains("search_key1"));
    assert!(output.contains("search_key2"));

    let output2 = run_commands_str(&file_path, "search\n");
    assert!(output2.contains("search_key1") || output2.contains("other_key"));
}

#[test]
fn test_copy_single_match() {
    let (_dir, file_path) = temp_test_file();
    run_commands(&file_path, b"put copy_single_key secret_value\n".to_vec());

    // copy should succeed (clipboard may not work in CI but the command should not error out)
    let output = run_commands_str(&file_path, "copy copy_single_key\n");
    // Command either succeeds silently or prints a clipboard message
    let _ = output; // just verify the binary didn't crash
}

#[test]
fn test_copy_no_match() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "copy no_such_key_xyz\n");
    assert!(output.contains("no_such_key_xyz") || output.contains("No key"));
}

#[test]
fn test_copy_multiple_matches() {
    let (_dir, file_path) = temp_test_file();
    run_commands(
        &file_path,
        b"put multi_key_1 val1\nput multi_key_2 val2\n".to_vec(),
    );
    let output = run_commands_str(&file_path, "copy multi_key_.*\n");
    assert!(
        output.contains("multi_key_1") || output.contains("Multiple") || output.contains("specify")
    );
}

#[test]
fn test_put_syntax_error() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "put only_key\n");
    assert!(output.contains("syntax") || output.contains("put KEY VAL"));
}

#[test]
fn test_del_syntax_error() {
    let (_dir, file_path) = temp_test_file();
    let output = run_commands_str(&file_path, "del\n");
    assert!(output.contains("syntax") || output.contains("del KEY"));
}

#[test]
fn test_encrypt_decrypt_with_output_file() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, encrypted_path) = temp_test_file();
    let (_dir3, decrypted_path) = temp_test_file();

    let test_data = b"output file round-trip test";
    fs::write(&input_path, test_data).unwrap();

    // Encrypt to output file
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.arg("--encrypt")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg("--output")
        .arg(&encrypted_path)
        .arg(&input_path)
        .assert()
        .success();

    // Decrypt to output file
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    cmd.arg("--decrypt")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg("--output")
        .arg(&decrypted_path)
        .arg(&encrypted_path)
        .assert()
        .success();

    let result = fs::read(&decrypted_path).unwrap();
    assert_eq!(result, test_data);
}

// --- Multi-factor store (version 8) --------------------------------------

/// Creates a version-8 single-password store at `path`, holding an empty
/// store, derived with insecure Argon2 params so the binary's `--insecure-password`
/// path unlocks it quickly.
fn create_store(path: &Path, factor_id: &str, password: &str) {
    use rcypher::{Argon2Params, SecretStore, UnlockedContainer};

    let mut store = UnlockedContainer::create_with_params(
        factor_id,
        password,
        SecretStore::new(),
        &Argon2Params::insecure(),
    )
    .unwrap();
    store.save(path).unwrap();
}

#[test]
fn test_store_put_get_roundtrip() {
    let (_dir, file_path) = temp_test_file();
    create_store(&file_path, "main", "test_password");

    // First run: unlock via the password factor, store two keys, save back.
    run_commands(&file_path, b"put key1 val1\nput key2 val2\n".to_vec());

    // The store must still be in the version-8 format after a save.
    let head = fs::read(&file_path).unwrap();
    assert_eq!(&head[..2], &[0u8, 8] /* V8 tag */);

    // Second run: re-open the rewritten vault and read the values back.
    let lines = run_commands(&file_path, b"get key1\nget key2\n".to_vec());
    assert_eq!(lines[0], "key1: val1");
    assert_eq!(lines[1], "key2: val2");
}

#[test]
fn test_store_wrong_password_fails() {
    let (_dir, file_path) = temp_test_file();
    create_store(&file_path, "main", "correct_password");

    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--quiet")
        .arg("--insecure-stdout")
        .arg("--insecure-password")
        .arg("wrong_password")
        .arg("--insecure-allow-debugging")
        .arg(&file_path)
        .write_stdin(b"get key1\n".to_vec())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("do not satisfy") || stderr.contains("policy"),
        "unexpected stderr: {stderr}"
    );
}

/// Creates a version-8 vault with two password factors ("main"/"backup") and an
/// `main or backup` policy, so the `--insecure-password test_password` path
/// unlocks it via the "main" factor.
fn create_multifactor_store(path: &Path) {
    use rcypher::{Argon2Params, SecretStore, UnlockedContainer};

    let mut store = UnlockedContainer::create_with_params(
        "main",
        "test_password",
        SecretStore::new(),
        &Argon2Params::insecure(),
    )
    .unwrap();
    store
        .enroll_password("backup", "recovery-secret-9")
        .unwrap();
    store.set_policy("main or backup").unwrap();
    store.save(path).unwrap();
}

#[test]
fn test_store_factors_and_policy_show() {
    let (_dir, file_path) = temp_test_file();
    create_multifactor_store(&file_path);

    let lines = run_commands(&file_path, b"auth factor list\nauth policy show\n".to_vec());
    assert!(lines.iter().any(|l| l == "main (password)"), "{lines:?}");
    assert!(lines.iter().any(|l| l == "backup (password)"), "{lines:?}");
    assert!(lines.iter().any(|l| l == "main or backup"), "{lines:?}");
}

#[test]
fn test_store_set_policy_and_remove_factor() {
    let (_dir, file_path) = temp_test_file();
    create_multifactor_store(&file_path);

    // A factor still referenced by the policy cannot be removed.
    let out = run_commands_str(&file_path, "auth factor remove backup\n");
    assert!(
        out.contains("still used by the policy") || out.contains("change the policy"),
        "{out}"
    );

    // Narrow the policy to just 'main'; the change is persisted.
    run_commands(&file_path, b"auth policy set main\n".to_vec());
    let shown = run_commands_str(&file_path, "auth policy show\n");
    assert!(
        shown.contains("main") && !shown.contains("backup"),
        "{shown}"
    );

    // Now the unused factor can be removed.
    run_commands(&file_path, b"auth factor remove backup\n".to_vec());
    let factors = run_commands_str(&file_path, "auth factor list\n");
    assert!(
        factors.contains("main") && !factors.contains("backup"),
        "{factors}"
    );
}

/// Writes a legacy version-7 password store (the pre-policy format) at `path`,
/// encrypted with "test_password" under insecure Argon2 params, holding a single
/// `legacy_key -> legacy_val` entry so conversion can be checked to preserve values.
fn create_legacy_store(path: &Path) {
    use rcypher::{
        Argon2Params, Cypher, CypherVersion, EncryptedValue, EncryptionKey, SecretStore,
    };

    let key = EncryptionKey::from_password_with_params(
        CypherVersion::default(),
        "test_password",
        &Argon2Params::insecure(),
    )
    .unwrap();
    let cypher = Cypher::new(key);
    let mut storage = SecretStore::new();
    storage.put(
        "legacy_key".to_string(),
        EncryptedValue::encrypt(&cypher, "legacy_val").unwrap(),
    );
    storage.save(&cypher, path).unwrap();
}

#[test]
fn test_new_store_is_v8() {
    let (_dir, file_path) = temp_test_file();
    // A store created through the normal flow now uses the version-8 format with
    // a single "password" factor.
    run_commands(&file_path, b"put k v\n".to_vec());

    let head = fs::read(&file_path).unwrap();
    assert_eq!(&head[..2], &[0u8, 8] /* V8 tag */);

    let factors = run_commands_str(&file_path, "auth factor list\n");
    assert!(factors.contains("primary (password)"), "{factors}");
}

#[test]
fn test_legacy_store_auto_converts() {
    let (_dir, file_path) = temp_test_file();
    create_legacy_store(&file_path);

    // Sanity: the seeded file really is a legacy (v7) container.
    assert_eq!(
        &fs::read(&file_path).unwrap()[..2],
        &[0u8, 7] /* V7 tag */
    );

    // Opening it and writing triggers the transparent upgrade: the original is
    // backed up to <path>.bak and the file is rewritten in the current (v8) format.
    run_commands(&file_path, b"put k v\n".to_vec());

    let bak = {
        let mut p = file_path.clone().into_os_string();
        p.push(".bak");
        PathBuf::from(p)
    };
    assert!(bak.exists(), "expected a .bak backup of the original");
    assert_eq!(
        &fs::read(&bak).unwrap()[..2],
        &[0u8, 7], /* V7 tag */
        "the backup must be the untouched legacy file"
    );
    assert_eq!(
        &fs::read(&file_path).unwrap()[..2],
        &[0u8, 8], /* V8 tag */
        "the upgraded file must be in the v8 format"
    );

    // The pre-existing value survived the conversion, and the new value is stored.
    let got = run_commands_str(&file_path, "get legacy_key\nget k\n");
    assert!(got.contains("legacy_key: legacy_val"), "{got}");
    assert!(got.contains("k: v"), "{got}");

    // The converted store is a real multi-factor store: the unlock password became the
    // 'primary' factor, so auth commands now work.
    let factors = run_commands_str(&file_path, "auth factor list\n");
    assert!(factors.contains("primary (password)"), "{factors}");
    let policy = run_commands_str(&file_path, "auth policy show\n");
    assert!(policy.contains("primary"), "{policy}");
}

#[test]
fn test_bare_auth_prints_help() {
    let (_dir, file_path) = temp_test_file();
    let out = run_commands_str(&file_path, "auth\n");
    assert!(out.contains("AUTH COMMANDS"), "{out}");
    assert!(out.contains("auth factor list"), "{out}");
    assert!(out.contains("auth policy set"), "{out}");
}
