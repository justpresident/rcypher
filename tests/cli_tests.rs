use rcypher::save_storage;
use rcypher::{Cypher, CypherVersion, EncryptedValue, EncryptionKey, Storage};
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
fn test_upgrade_storage() {
    let (_dir, storage_path) = temp_test_file();

    // Create a legacy format storage file
    let legacy_key =
        EncryptionKey::from_password(CypherVersion::LegacyWithoutKdf, "test_password").unwrap();
    let legacy_cypher = Cypher::new(legacy_key);

    let mut storage = Storage::new();
    storage.put(
        "key1".to_string(),
        EncryptedValue::encrypt(&legacy_cypher, "value1").unwrap(),
    );
    storage.put(
        "key2".to_string(),
        EncryptedValue::encrypt(&legacy_cypher, "value2").unwrap(),
    );

    save_storage(&legacy_cypher, &storage, &storage_path).unwrap();

    // Run upgrade command
    let mut cmd = Command::new(cargo::cargo_bin!("rcypher"));
    let output = cmd
        .arg("--upgrade-storage")
        .arg("--quiet")
        .arg("--insecure-password")
        .arg("test_password")
        .arg("--insecure-allow-debugging")
        .arg(&storage_path)
        .output()
        .unwrap();

    assert!(output.status.success());

    // Verify the file was upgraded by trying to read it with new format
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key1\n");
    commands.extend_from_slice(b"get key2\n");
    let lines = run_commands(&storage_path, commands);

    assert_eq!(lines[0], "key1: value1");
    assert_eq!(lines[1], "key2: value2");
}
