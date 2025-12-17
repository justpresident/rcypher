use anyhow::Result;
use rcypher::*;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

// Helper to create a temporary test file
fn temp_test_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rcypher_test");
    (dir, path)
}

#[test]
fn test_encrypt_decrypt_basic() {
    let cypher = Cypher::new(
        EncryptionKey::from_password(CypherVersion::V7WithKdf, "test_password").unwrap(),
    );
    let data = b"Hello, World!";

    let encrypted = cypher.encrypt(data).unwrap();
    assert_ne!(encrypted.as_slice(), data);
    assert!(encrypted.len() > data.len()); // Should be larger due to padding and metadata

    let decrypted = cypher.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted.as_slice(), data);
}

#[test]
fn test_encrypt_decrypt_empty() {
    let cypher = Cypher::new(
        EncryptionKey::from_password(CypherVersion::V7WithKdf, "test_password").unwrap(),
    );
    let data = b"";

    let encrypted = cypher.encrypt(data).unwrap();
    let decrypted = cypher.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted.as_slice(), data);
}

#[test]
fn test_encrypt_decrypt_large_data() {
    let cypher = Cypher::new(
        EncryptionKey::from_password(CypherVersion::V7WithKdf, "test_password").unwrap(),
    );
    let data = vec![42u8; 10000]; // 10KB of data

    let encrypted = cypher.encrypt(&data).unwrap();
    let decrypted = cypher.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, data.into());
}

#[test]
fn test_decrypt_wrong_password() {
    let cypher1 =
        Cypher::new(EncryptionKey::from_password(CypherVersion::V7WithKdf, "password1").unwrap());
    let cypher2 =
        Cypher::new(EncryptionKey::from_password(CypherVersion::V7WithKdf, "password2").unwrap());
    let data = b"Secret data";

    let encrypted = cypher1.encrypt(data).unwrap();
    let decrypted = cypher2.decrypt(&encrypted);

    // Should either fail or return garbage (not original data)
    if let Ok(result) = decrypted {
        assert_ne!(result.as_slice(), data);
    }
}

#[test]
fn test_decrypt_corrupted_data() {
    let cypher = Cypher::new(
        EncryptionKey::from_password(CypherVersion::V7WithKdf, "test_password").unwrap(),
    );

    // Too short
    let result = cypher.decrypt(&[0, 1]);
    assert!(result.is_err());

    // Wrong version
    let mut encrypted = cypher.encrypt(b"test").unwrap();
    encrypted[0] = 99; // Invalid version
    let result = cypher.decrypt(&encrypted);
    assert!(result.is_err());
}

fn encrypt_decrypt(
    input_path: &Path,
    output_path: &Path,
    in_between: impl FnOnce() -> (),
) -> Result<Vec<u8>> {
    let cypher = Cypher::new(EncryptionKey::from_password(
        CypherVersion::V7WithKdf,
        "test_password",
    )?);

    // Encrypt
    let mut file = fs::File::create(&output_path)?;
    cypher.encrypt_file(&input_path, &mut file)?;

    in_between();

    // Decrypt
    let mut buffer = std::io::Cursor::new(Vec::new());
    cypher.decrypt_file(&output_path, &mut buffer)?;
    buffer.seek(SeekFrom::Start(0))?;

    let mut decrypted = Vec::new();
    buffer.read_to_end(&mut decrypted)?;

    Ok(decrypted)
}

fn noop() {}

#[test]
fn test_encrypt_decrypt_file() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create test file
    let test_data = b"This is test file content\nWith multiple lines\nAnd some more";
    fs::write(&input_path, test_data).unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, noop).unwrap();

    assert_eq!(decrypted.as_slice(), test_data);
}

#[test]
fn test_encrypt_decrypt_large_file() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create large test file (> 4KB to test chunking)
    let mut test_data = vec![0u8; 12345];
    for i in 1..test_data.len() {
        test_data[i] = (test_data[i - 1] + 1) % 255;
    }
    fs::write(&input_path, &test_data).unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, noop).unwrap();

    assert_eq!(decrypted.len(), test_data.len());
    assert_eq!(decrypted, test_data);
}

#[test]
fn test_encrypt_decrypt_empty_file() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    fs::write(&input_path, b"").unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, noop).unwrap();

    assert_eq!(decrypted.len(), 0);
}

#[test]
fn test_corrupted_file_hmac() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create test file
    let test_data = b"This is test file content\nWith multiple lines\nAnd some more";
    fs::write(&input_path, test_data).unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, || {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&output_path)
            .unwrap();
        let mut buf = [0u8; 1];
        file.seek(SeekFrom::End(-1)).unwrap();
        file.read(&mut buf).unwrap();
        buf[0] += 1;
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write(&buf).unwrap();
    });

    assert!(decrypted.is_err());
}

#[test]
fn test_invalid_file_version() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create test file
    let test_data = b"This is test file content\nWith multiple lines\nAnd some more";
    fs::write(&input_path, test_data).unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, || {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&output_path)
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write(&[5u8]).unwrap();
    });

    assert!(decrypted.is_err());
}

#[test]
fn test_invalid_file_padding() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create test file
    let test_data = b"This is test file content\nWith multiple lines\nAnd some more";
    fs::write(&input_path, test_data).unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, || {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&output_path)
            .unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let mut padding = [0u8; 1];
        file.read(&mut padding).unwrap();
        padding[0] += 1;
        file.seek(SeekFrom::Start(3)).unwrap();
        file.write(&padding).unwrap();
    });

    assert!(decrypted.is_err());
}

#[test]
fn test_invalid_file_truncated() {
    let (_dir, input_path) = temp_test_file();
    let (_dir2, output_path) = temp_test_file();

    // Create test file
    let test_data = b"This is test file content\nWith multiple lines\nAnd some more";
    fs::write(&input_path, test_data).unwrap();

    let decrypted = encrypt_decrypt(&input_path, &output_path, || {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&output_path)
            .unwrap();
        file.set_len(file.metadata().unwrap().len() - 16).unwrap();
    });

    assert!(decrypted.is_err());
}

#[test]
fn test_format_timestamp() {
    let ts = 1609459200; // 2021-01-01 00:00:00 UTC
    let formatted = format_timestamp(ts);
    assert!(formatted.contains("2021"));
    assert!(formatted.contains("01"));

    // Test zero timestamp
    let formatted_zero = format_timestamp(0);
    assert_eq!(formatted_zero, "N/A");
}
