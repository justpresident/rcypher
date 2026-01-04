use rcypher::{Cypher, CypherVersion, EncryptionKey, StorageV4, save_storage_v4};
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

    assert_eq!(lines[0], "/key1: val_new");
    assert_eq!(lines[1], "/key2: val2");

    // get with a regexp
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key.*\n");
    let lines = run_commands(&file_path, commands);

    assert_eq!(lines[0], "/key1: val_new");
    assert_eq!(lines[1], "/key2: val2");

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

    assert_eq!(lines[0], "/key2: value2");
    assert_eq!(lines[1], "/key3: value3");
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

    assert_eq!(lines[0], "/key1: new_value");
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

    assert_eq!(lines[0], "/key2: accept_this");
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

    let mut storage = StorageV4::new();
    storage.put("key1".to_string(), "value1".into());
    storage.put("key2".to_string(), "value2".into());

    save_storage_v4(&legacy_cypher, &storage, &storage_path).unwrap();

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

    println!("{:?}", String::from_utf8(output.stderr));
    assert!(output.status.success());

    // Verify the file was upgraded by trying to read it with new format
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get key1\n");
    commands.extend_from_slice(b"get key2\n");
    let lines = run_commands(&storage_path, commands);

    assert_eq!(lines[0], "/key1: value1");
    assert_eq!(lines[1], "/key2: value2");
}

#[test]
fn test_folders_and_paths() {
    let (_dir, file_path) = temp_test_file();

    // Create folders and store keys in different locations
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"mkdir personal\n");
    commands.extend_from_slice(b"put /key1 root_value\n");
    commands.extend_from_slice(b"put work/api_key work_value\n");
    commands.extend_from_slice(b"put personal/password personal_value\n");
    run_commands(&file_path, commands);

    // Test get with absolute paths
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get /key1\n");
    commands.extend_from_slice(b"get work/api_key\n");
    commands.extend_from_slice(b"get personal/password\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/key1: root_value");
    assert_eq!(lines[1], "/work/api_key: work_value");
    assert_eq!(lines[2], "/personal/password: personal_value");

    // Test cd and relative paths
    let mut commands = Vec::new();
    commands.extend_from_slice(b"cd work\n");
    commands.extend_from_slice(b"put local_key local_value\n");
    let _ = run_commands(&file_path, commands);

    let mut commands = Vec::new();
    commands.extend_from_slice(b"cd work\n");
    commands.extend_from_slice(b"get local_key\n");
    commands.extend_from_slice(b"get ../personal/password\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/work/local_key: local_value");
    assert_eq!(lines[1], "/personal/password: personal_value");

    // Test search with paths
    let mut commands = Vec::new();
    commands.extend_from_slice(b"search work/.*\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("/work/api_key")));
    assert!(lines.iter().any(|l| l.contains("/work/local_key")));

    // Test delete with paths
    let mut commands = Vec::new();
    commands.extend_from_slice(b"del work/local_key\n");
    commands.extend_from_slice(b"search work/.*\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("/work/api_key")));
    assert!(!lines.iter().any(|l| l.contains("/work/local_key")));

    // Test mkdir with paths and nested folders
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work/projects\n");
    commands.extend_from_slice(b"put work/projects/secret nested_value\n");
    let _ = run_commands(&file_path, commands);

    let mut commands = Vec::new();
    commands.extend_from_slice(b"cd work/projects\n");
    commands.extend_from_slice(b"get secret\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/work/projects/secret: nested_value");

    // Test complex relative paths
    let mut commands = Vec::new();
    commands.extend_from_slice(b"cd work/projects\n");
    commands.extend_from_slice(b"get ../../key1\n");
    commands.extend_from_slice(b"get ../api_key\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/key1: root_value");
    assert_eq!(lines[1], "/work/api_key: work_value");

    // Test pwd
    let mut commands = Vec::new();
    commands.extend_from_slice(b"cd work\n");
    commands.extend_from_slice(b"pwd\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/work");

    // Test history with paths
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put work/api_key updated_value\n");
    let _ = run_commands(&file_path, commands);

    let mut commands = Vec::new();
    commands.extend_from_slice(b"history work/api_key\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("work_value")));
    assert!(lines.iter().any(|l| l.contains("updated_value")));
}

#[test]
fn test_update_with_nested_folders() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage with nested folder structure
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"mkdir work/projects\n");
    commands.extend_from_slice(b"mkdir personal\n");
    commands.extend_from_slice(b"put /root_key root_value\n");
    commands.extend_from_slice(b"put work/api_key work_api\n");
    commands.extend_from_slice(b"put work/projects/secret project_secret\n");
    commands.extend_from_slice(b"put personal/password personal_pw\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with same structure but different values
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"mkdir work/projects\n");
    commands.extend_from_slice(b"mkdir personal\n");
    commands.extend_from_slice(b"put /root_key root_value\n");
    commands.extend_from_slice(b"put work/api_key updated_api\n");
    commands.extend_from_slice(b"put work/projects/secret updated_secret\n");
    commands.extend_from_slice(b"put personal/password personal_pw\n");
    let _ = run_commands(&update_path, commands);

    // Wait to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Create update file with newer timestamps
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"mkdir work/projects\n");
    commands.extend_from_slice(b"put work/api_key updated_api\n");
    commands.extend_from_slice(b"put work/projects/secret updated_secret\n");
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
    assert!(stdout.contains("2 conflict"));

    // Verify updates were applied in nested folders
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get work/api_key\n");
    commands.extend_from_slice(b"get work/projects/secret\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "/work/api_key: updated_api");
    assert_eq!(lines[1], "/work/projects/secret: updated_secret");
}

#[test]
fn test_update_with_new_keys_in_nested_folders() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage with basic structure
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"put work/api_key work_api\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with additional nested keys
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"mkdir work/projects\n");
    commands.extend_from_slice(b"mkdir work/projects/client_a\n");
    commands.extend_from_slice(b"put work/api_key work_api\n");
    commands.extend_from_slice(b"put work/projects/secret project_secret\n");
    commands.extend_from_slice(b"put work/projects/client_a/token client_token\n");
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

    // Verify the new keys were added in nested folders
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get work/projects/secret\n");
    commands.extend_from_slice(b"get work/projects/client_a/token\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "/work/projects/secret: project_secret");
    assert_eq!(lines[1], "/work/projects/client_a/token: client_token");
}

#[test]
fn test_update_with_deep_nesting() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage with deeply nested structure (4 levels)
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir org\n");
    commands.extend_from_slice(b"mkdir org/dept\n");
    commands.extend_from_slice(b"mkdir org/dept/team\n");
    commands.extend_from_slice(b"mkdir org/dept/team/project\n");
    commands.extend_from_slice(b"put org/dept/team/project/secret old_secret\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with new value
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir org\n");
    commands.extend_from_slice(b"mkdir org/dept\n");
    commands.extend_from_slice(b"mkdir org/dept/team\n");
    commands.extend_from_slice(b"mkdir org/dept/team/project\n");
    commands.extend_from_slice(b"put org/dept/team/project/secret old_secret\n");
    let _ = run_commands(&update_path, commands);

    // Wait and update with new value
    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put org/dept/team/project/secret new_secret\n");
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

    // Verify the deeply nested key was updated
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get org/dept/team/project/secret\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "/org/dept/team/project/secret: new_secret");
}

#[test]
fn test_update_with_mixed_nested_and_root_keys() {
    let (_dir, main_path) = temp_test_file();
    let (_dir2, update_path) = temp_test_file();

    // Create main storage with mixed structure
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"put /root1 root_value1\n");
    commands.extend_from_slice(b"put work/nested1 nested_value1\n");
    let _ = run_commands(&main_path, commands);

    // Create update storage with new keys at both levels
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"put /root1 root_value1\n");
    commands.extend_from_slice(b"put /root2 root_value2\n");
    commands.extend_from_slice(b"put work/nested1 nested_value1\n");
    commands.extend_from_slice(b"put work/nested2 nested_value2\n");
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
    assert!(stdout.contains("2 new key"));

    // Verify both root and nested keys were added
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get /root2\n");
    commands.extend_from_slice(b"get work/nested2\n");
    let lines = run_commands(&main_path, commands);

    assert_eq!(lines[0], "/root2: root_value2");
    assert_eq!(lines[1], "/work/nested2: nested_value2");
}

#[test]
fn test_move_single_key_to_folder() {
    let (_dir, file_path) = temp_test_file();

    // Setup: create folders and keys
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir source\n");
    commands.extend_from_slice(b"mkdir dest\n");
    commands.extend_from_slice(b"put source/key1 value1\n");
    run_commands(&file_path, commands);

    // Move key to dest folder
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv source/key1 dest/\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("Moved")));

    // Verify key moved
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get dest/key1\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/dest/key1: value1");

    // Verify key gone from source
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get source/key1\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines[0].contains("not found") || lines[0].contains("No keys matching"));
}

#[test]
fn test_move_with_rename() {
    let (_dir, file_path) = temp_test_file();

    // Setup
    let mut commands = Vec::new();
    commands.extend_from_slice(b"put /old_name old_value\n");
    run_commands(&file_path, commands);

    // Move and rename
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv old_name new_name\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("Moved")));

    // Verify new name exists
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get new_name\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/new_name: old_value");

    // Verify old name gone
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get old_name\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines[0].contains("not found") || lines[0].contains("No keys matching"));
}

#[test]
fn test_move_multiple_keys_to_folder() {
    let (_dir, file_path) = temp_test_file();

    // Setup: create keys with pattern
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir dest\n");
    commands.extend_from_slice(b"put /api_key1 value1\n");
    commands.extend_from_slice(b"put /api_key2 value2\n");
    commands.extend_from_slice(b"put /api_key3 value3\n");
    run_commands(&file_path, commands);

    // Move all api_* keys to dest
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv api_.* dest/\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("Moved 3 keys")));

    // Verify all keys moved
    let mut commands = Vec::new();
    commands.extend_from_slice(b"search dest/.*\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("/dest/api_key1")));
    assert!(lines.iter().any(|l| l.contains("/dest/api_key2")));
    assert!(lines.iter().any(|l| l.contains("/dest/api_key3")));
}

#[test]
fn test_move_across_nested_folders() {
    let (_dir, file_path) = temp_test_file();

    // Setup: create nested structure
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work\n");
    commands.extend_from_slice(b"mkdir work/old_project\n");
    commands.extend_from_slice(b"mkdir work/new_project\n");
    commands.extend_from_slice(b"put work/old_project/secret old_secret\n");
    run_commands(&file_path, commands);

    // Move from nested folder to another nested folder
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv work/old_project/secret work/new_project/\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("Moved")));

    // Verify moved
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get work/new_project/secret\n");
    let lines = run_commands(&file_path, commands);
    assert_eq!(lines[0], "/work/new_project/secret: old_secret");
}

#[test]
fn test_move_preserves_history() {
    let (_dir, file_path) = temp_test_file();

    // Setup: create key with history
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir dest\n");
    commands.extend_from_slice(b"put /key1 v1\n");
    commands.extend_from_slice(b"put /key1 v2\n");
    commands.extend_from_slice(b"put /key1 v3\n");
    run_commands(&file_path, commands);

    // Move the key
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv key1 dest/\n");
    run_commands(&file_path, commands);

    // Check history preserved
    let mut commands = Vec::new();
    commands.extend_from_slice(b"cd dest\n");
    commands.extend_from_slice(b"history key1\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("v1")));
    assert!(lines.iter().any(|l| l.contains("v2")));
    assert!(lines.iter().any(|l| l.contains("v3")));
}

#[test]
fn test_move_single_match_with_pattern() {
    let (_dir, file_path) = temp_test_file();

    // Setup: create a key that matches a pattern uniquely
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir dest\n");
    commands.extend_from_slice(b"put /api_key value1\n");
    commands.extend_from_slice(b"put /other_key value2\n");
    run_commands(&file_path, commands);

    // Move using pattern that matches only one key
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv api_.* dest/\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("Moved")));

    // Verify the key was moved
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get dest/api_key\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("value1")));

    // Verify original location is empty
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get /api_key\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("No keys matching")));
}

#[test]
fn test_move_single_folder_with_pattern() {
    let (_dir, file_path) = temp_test_file();

    // Setup: create folders where pattern matches only one
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mkdir work_project\n");
    commands.extend_from_slice(b"mkdir personal\n");
    commands.extend_from_slice(b"mkdir archive\n");
    commands.extend_from_slice(b"put work_project/secret value1\n");
    run_commands(&file_path, commands);

    // Move folder using pattern
    let mut commands = Vec::new();
    commands.extend_from_slice(b"mv work_.* archive/\n");
    let lines = run_commands(&file_path, commands);
    eprintln!("Lines after mv work_.* archive/: {:?}", lines);
    assert!(lines.iter().any(|l| l.contains("Moved folder")));

    // Verify folder was moved with contents
    let mut commands = Vec::new();
    commands.extend_from_slice(b"get archive/work_project/secret\n");
    let lines = run_commands(&file_path, commands);
    assert!(lines.iter().any(|l| l.contains("value1")));
}
