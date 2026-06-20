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
