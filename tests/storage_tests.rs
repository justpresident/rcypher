//! Tests for the bundled key-value storage format (the `storage` feature).
#![cfg(feature = "storage")]

use rcypher::*;
use std::ops::Add;
use std::path::PathBuf;
use tempfile::TempDir;

/// Wraps plaintext as a pseudo-`EncryptedValue` for storage-format tests that
/// exercise (de)serialization without performing real encryption.
fn enc(s: impl AsRef<str>) -> EncryptedValue {
    EncryptedValue::from_plaintext_unchecked(s)
}

/// Build a minimal valid V4 serialized byte sequence with one entry.
fn build_v4_entry(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    // version = 4
    data.extend_from_slice(&4u16.to_be_bytes());
    // count = 1
    data.extend_from_slice(&1u32.to_be_bytes());
    // key_len
    data.extend_from_slice(&(key.len() as u16).to_be_bytes());
    data.extend_from_slice(key);
    // val_len
    data.extend_from_slice(&(value.len() as u32).to_be_bytes());
    data.extend_from_slice(value);
    // timestamp
    data.extend_from_slice(&0u32.to_be_bytes());
    data
}

// Helper to create a temporary test file
fn temp_test_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rcypher_test");
    (dir, path)
}

#[test]
fn test_storage_new() {
    let storage = SecretStore::new();
    assert_eq!(storage.len(), 0);
}

#[test]
fn test_storage_put_get() {
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));
    storage.put("key2".to_string(), enc("value2"));

    let results: Vec<_> = storage.get("key1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0.as_bytes(), "key1".as_bytes());
    assert_eq!(results[0].1.as_bytes(), "value1".as_bytes());
}

#[test]
fn test_storage_put_multiple_values() {
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));
    storage.put("key1".to_string(), enc("value2"));
    storage.put("key1".to_string(), enc("value3"));

    // get should return the latest value
    let results: Vec<_> = storage.get("key1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1.as_bytes(), "value3".as_bytes());

    // history should return all values
    let history = storage.history("key1").unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].value.as_bytes(), "value1".as_bytes());
    assert_eq!(history[1].value.as_bytes(), "value2".as_bytes());
    assert_eq!(history[2].value.as_bytes(), "value3".as_bytes());
}

#[test]
fn test_storage_get_with_regex() {
    let mut storage = SecretStore::new();
    storage.put("test1".to_string(), enc("value1"));
    storage.put("test2".to_string(), enc("value2"));
    storage.put("prod1".to_string(), enc("value3"));

    // Match all test keys
    let results: Vec<_> = storage.get("test.*").unwrap().collect();
    assert_eq!(results.len(), 2);

    // Match specific key
    let results: Vec<_> = storage.get("test1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "test1");
}

#[test]
fn test_storage_get_no_match() {
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));

    let results: Vec<_> = storage.get("nonexistent").unwrap().collect();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_storage_search() {
    let mut storage = SecretStore::new();
    storage.put("user_alice".to_string(), enc("value1"));
    storage.put("user_bob".to_string(), enc("value2"));
    storage.put("admin_charlie".to_string(), enc("value3"));

    let keys: Vec<_> = storage.search("user_").unwrap().collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"user_alice"));
    assert!(keys.contains(&"user_bob"));

    let all_keys: Vec<_> = storage.search("").unwrap().collect();
    assert_eq!(all_keys.len(), 3);
}

#[test]
fn test_storage_delete() {
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));
    storage.put("key2".to_string(), enc("value2"));

    assert!(storage.delete("key1"));
    assert_eq!(storage.len(), 1);

    assert!(!storage.delete("key1")); // Already deleted
    assert!(!storage.delete("nonexistent"));
}

#[test]
fn test_storage_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("v1"));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    storage.put_ts("key1".to_string(), enc("v2"), timestamp.add(1));
    storage.put_ts("key1".to_string(), enc("v3"), timestamp.add(2));

    let history = storage.history("key1").unwrap();
    assert_eq!(history.len(), 3);

    // Timestamps should be in ascending order
    assert!(history[0].timestamp + 1 == history[1].timestamp);
    assert!(history[1].timestamp + 1 == history[2].timestamp);

    // Values should be in order
    assert_eq!(history[0].value.as_bytes(), "v1".as_bytes());
    assert_eq!(history[1].value.as_bytes(), "v2".as_bytes());
    assert_eq!(history[2].value.as_bytes(), "v3".as_bytes());
}

#[test]
fn test_serialize_deserialize_empty() {
    let storage = SecretStore::new();
    let serialized = storage.safe_serialize().unwrap();
    let deserialized = SecretStore::safe_deserialize(&serialized).unwrap();

    assert_eq!(deserialized.len(), 0);
}

#[test]
fn test_serialize_deserialize_single_entry() {
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));

    let serialized = storage.safe_serialize().unwrap();
    let deserialized = SecretStore::safe_deserialize(&serialized).unwrap();

    assert_eq!(deserialized.len(), 1);
    let entry = &deserialized.history("key1").unwrap()[0];
    assert_eq!(entry.value.as_bytes(), "value1".as_bytes());
}

#[test]
fn test_serialize_deserialize_multiple_entries() {
    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));
    storage.put("key2".to_string(), enc("value2"));
    storage.put("key1".to_string(), enc("value1_updated"));

    let serialized = storage.safe_serialize().unwrap();
    let deserialized = SecretStore::safe_deserialize(&serialized).unwrap();

    assert_eq!(deserialized.len(), 2);
    assert_eq!(deserialized.history("key1").unwrap().len(), 2);
    assert_eq!(deserialized.history("key2").unwrap().len(), 1);
}

#[test]
fn test_serialize_deserialize_unicode() {
    let mut storage = SecretStore::new();
    storage.put("ключ".to_string(), enc("значение"));
    storage.put("🔑".to_string(), enc("🎁"));

    let serialized = storage.safe_serialize().unwrap();
    let deserialized = SecretStore::safe_deserialize(&serialized).unwrap();

    assert_eq!(deserialized.len(), 2);
    assert_eq!(
        deserialized.history("ключ").unwrap()[0].value.as_bytes(),
        "значение".as_bytes()
    );
    assert_eq!(
        deserialized.history("🔑").unwrap()[0].value.as_bytes(),
        "🎁".as_bytes()
    );
}

#[test]
fn test_deserialize_corrupted_data() {
    // Too short
    let result = SecretStore::safe_deserialize(&[0, 1, 2]);
    assert!(result.is_err());

    // Invalid version
    let mut data = vec![0, 99]; // version 99
    data.extend_from_slice(&[0, 0, 0, 1]); // count = 1
    let result = SecretStore::safe_deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_save_load_roundtrip() {
    let (_dir, path) = temp_test_file();

    let cypher = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );

    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));
    storage.put("key2".to_string(), enc("value2"));

    storage.save(&cypher, &path).unwrap();
    assert!(path.exists());

    let loaded = SecretStore::load(&cypher, &path).unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(
        loaded.history("key1").unwrap()[0].value.as_bytes(),
        "value1".as_bytes()
    );
    assert_eq!(
        loaded.history("key2").unwrap()[0].value.as_bytes(),
        "value2".as_bytes()
    );
}

#[test]
fn test_load_nonexistent_file() {
    let (_dir, path) = temp_test_file();

    let cypher = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );

    let storage = SecretStore::load(&cypher, &path).unwrap();
    assert_eq!(storage.len(), 0);
}

#[test]
fn test_load_with_wrong_password() {
    let (_dir, path) = temp_test_file();
    let cypher1 = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );
    let cypher2 = Cypher::new(
        EncryptionKey::for_file_with_params("test_password2", &path, &Argon2Params::insecure())
            .unwrap(),
    );

    let mut storage = SecretStore::new();
    storage.put("key1".to_string(), enc("value1"));

    storage.save(&cypher1, &path).unwrap();

    // Should fail or return garbage
    let result = SecretStore::load(&cypher2, &path);
    assert!(result.is_err() || result.unwrap().is_empty());
}

#[test]
fn test_reencrypt_rekeys_all_values_and_history() {
    let make = |pw: &str| {
        Cypher::new(
            EncryptionKey::from_password_with_params(
                CypherVersion::default(),
                pw,
                &Argon2Params::insecure(),
            )
            .unwrap(),
        )
    };
    let old = make("old_password");
    let new = make("new_password");

    let mut storage = SecretStore::new();
    // A key with two historical versions, plus a second key.
    storage.put_ts(
        "k".to_string(),
        EncryptedValue::encrypt(&old, "v1").unwrap(),
        100,
    );
    storage.put_ts(
        "k".to_string(),
        EncryptedValue::encrypt(&old, "v2").unwrap(),
        200,
    );
    storage.put(
        "other".to_string(),
        EncryptedValue::encrypt(&old, "secret").unwrap(),
    );

    storage.reencrypt(&old, &new).unwrap();

    // The full history of every key now decrypts under the new cypher...
    let history: Vec<String> = storage
        .history("k")
        .unwrap()
        .iter()
        .map(|e| e.value.decrypt(&new).unwrap().to_string())
        .collect();
    assert_eq!(history, vec!["v1".to_string(), "v2".to_string()]);

    let (_, latest_other) = storage.get("other").unwrap().next().unwrap();
    assert_eq!(*latest_other.decrypt(&new).unwrap(), *"secret");

    // ...and the old cypher can no longer read the re-encrypted values.
    let (_, latest_k) = storage.get("k").unwrap().next().unwrap();
    assert!(latest_k.decrypt(&old).is_err());
}

#[test]
fn test_policy_change_rekeys_stored_values_and_history() {
    let mut container = UnlockedContainer::create_with_password(
        "primary",
        "alpha-vault-pass",
        SecretStore::new(),
        &Argon2Params::insecure(),
    )
    .unwrap();
    let old_cypher = container.cypher();
    container.data_mut().put_ts(
        "key".to_string(),
        EncryptedValue::encrypt(&old_cypher, "old value").unwrap(),
        100,
    );
    container.data_mut().put_ts(
        "key".to_string(),
        EncryptedValue::encrypt(&old_cypher, "new value").unwrap(),
        200,
    );

    container
        .enroll_password("second", "bravo-vault-pass", &Argon2Params::insecure())
        .unwrap();
    container.set_policy("primary and second").unwrap();

    let new_cypher = container.cypher();
    let history = container.data().history("key").unwrap();
    assert_eq!(
        history
            .iter()
            .map(|entry| entry.value.decrypt(&new_cypher).unwrap().to_string())
            .collect::<Vec<_>>(),
        ["old value", "new value"]
    );
    assert!(
        history
            .iter()
            .all(|entry| entry.value.decrypt(&old_cypher).is_err())
    );
}

#[test]
fn test_storage_ordering() {
    let mut storage = SecretStore::new();

    // Add keys in random order
    storage.put("zebra".to_string(), enc("z"));
    storage.put("alpha".to_string(), enc("a"));
    storage.put("beta".to_string(), enc("b"));

    // Search should return sorted
    let keys: Vec<_> = storage.search("").unwrap().collect();
    assert_eq!(keys[0], "alpha");
    assert_eq!(keys[1], "beta");
    assert_eq!(keys[2], "zebra");
}

#[test]
fn test_special_characters_in_keys() {
    let mut storage = SecretStore::new();
    storage.put("key-with-dash".to_string(), enc("value1"));
    storage.put("key_with_underscore".to_string(), enc("value2"));
    storage.put("key.with.dots".to_string(), enc("value3"));
    storage.put("key@with@at".to_string(), enc("value4"));

    assert_eq!(storage.len(), 4);

    let result: Vec<_> = storage.get("key-with-dash").unwrap().collect();
    assert_eq!(result[0].1.as_bytes(), "value1".as_bytes());
    let result: Vec<_> = storage.get("key_with_underscore").unwrap().collect();
    assert_eq!(result[0].1.as_bytes(), "value2".as_bytes());
    let result: Vec<_> = storage.get("key.with.dots").unwrap().collect();
    assert_eq!(result[0].1.as_bytes(), "value3".as_bytes());
    let result: Vec<_> = storage.get("key@with@at").unwrap().collect();
    assert_eq!(result[0].1.as_bytes(), "value4".as_bytes());

    // Dot in regex matches any character
    let results: Vec<_> = storage.get("key.*").unwrap().collect();
    assert_eq!(results.len(), 4);
}

#[test]
fn test_concurrent_operations() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(SecretStore::new()));
    let mut handles = vec![];

    for i in 0..10 {
        let storage_clone = Arc::clone(&storage);
        let handle = thread::spawn(move || {
            let mut s = storage_clone.lock().unwrap();
            s.put(format!("key{}", i), enc(format!("value{}", i)));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_storage = storage.lock().unwrap();
    assert_eq!(final_storage.len(), 10);
}

#[test]
fn test_storage_persistence_across_sessions() {
    let (_dir, path) = temp_test_file();
    let cypher = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );

    // Session 1: Create and save
    {
        let mut storage = SecretStore::new();
        storage.put("session1_key".to_string(), enc("session1_value"));
        storage.save(&cypher, &path).unwrap();
    }

    // Session 2: Load and add
    {
        let mut storage = SecretStore::load(&cypher, &path).unwrap();
        assert_eq!(storage.len(), 1);
        storage.put("session2_key".to_string(), enc("session2_value"));
        storage.save(&cypher, &path).unwrap();
    }

    // Session 3: Verify both keys exist
    {
        let storage = SecretStore::load(&cypher, &path).unwrap();
        assert_eq!(storage.len(), 2);
        assert!(storage.contains_key("session1_key"));
        assert!(storage.contains_key("session2_key"));
    }
}

#[test]
fn test_empty_key_value() {
    let mut storage = SecretStore::new();
    storage.put("".to_string(), enc("value"));
    storage.put("key".to_string(), enc(""));

    assert_eq!(storage.len(), 2);

    let serialized = storage.safe_serialize().unwrap();
    let deserialized = SecretStore::safe_deserialize(&serialized).unwrap();

    assert_eq!(deserialized.len(), 2);
    assert_eq!(
        deserialized.history("").unwrap()[0].value.as_bytes(),
        "value".as_bytes()
    );
    assert_eq!(
        deserialized.history("key").unwrap()[0].value.as_bytes(),
        "".as_bytes()
    );
}

#[test]
fn test_very_long_key_value() {
    let mut storage = SecretStore::new();
    let long_key = "k".repeat(10000);
    let long_value = "v".repeat(50000);

    storage.put(long_key.clone(), enc(long_value.clone()));

    let serialized = storage.safe_serialize().unwrap();
    let deserialized = SecretStore::safe_deserialize(&serialized).unwrap();

    assert_eq!(
        deserialized.history(&long_key).unwrap()[0].value.as_bytes(),
        long_value.as_bytes()
    );
}

// --- safe_deserialize (v4 parsing) error path tests ---

#[test]
fn test_deserialize_too_short_for_version() {
    // Fewer than 2 bytes — SecretStoreVersion::probe_data fails
    let result = SecretStore::safe_deserialize(&[0x00]);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_truncated_no_key_len() {
    // version=4, count=1, but nothing after the 6-byte header
    let mut data = vec![0x00u8, 0x04]; // version 4
    data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    // no key_len bytes follow
    let result = SecretStore::safe_deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_truncated_key_overflow() {
    // version=4, count=1, key_len=50 but only 3 key bytes present
    let mut data = vec![0x00u8, 0x04]; // version 4
    data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    data.extend_from_slice(&50u16.to_be_bytes()); // key_len = 50
    data.extend_from_slice(b"abc"); // only 3 bytes of key
    let result = SecretStore::safe_deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_truncated_value_len_missing() {
    // version=4, count=1, full key, but only 2 bytes available for the 4-byte val_len
    let mut data = vec![0x00u8, 0x04]; // version 4
    data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    data.extend_from_slice(&3u16.to_be_bytes()); // key_len = 3
    data.extend_from_slice(b"key"); // key
    data.extend_from_slice(&[0x00, 0x00]); // only 2 of 4 val_len bytes
    let result = SecretStore::safe_deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_truncated_value_overflow() {
    // version=4, count=1, key="k", val_len=100 but no value bytes
    let mut data = vec![0x00u8, 0x04]; // version 4
    data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    data.extend_from_slice(&1u16.to_be_bytes()); // key_len = 1
    data.push(b'k'); // key
    data.extend_from_slice(&100u32.to_be_bytes()); // val_len = 100
    // no value bytes
    let result = SecretStore::safe_deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_truncated_timestamp_missing() {
    // version=4, count=1, key="k", val="v", only 2 of 4 timestamp bytes
    let mut data = vec![0x00u8, 0x04]; // version 4
    data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    data.extend_from_slice(&1u16.to_be_bytes()); // key_len = 1
    data.push(b'k'); // key
    data.extend_from_slice(&1u32.to_be_bytes()); // val_len = 1
    data.push(b'v'); // value
    data.extend_from_slice(&[0x00, 0x00]); // only 2 of 4 timestamp bytes
    let result = SecretStore::safe_deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_round_trip_via_builder() {
    // Verify the build_v4_entry helper produces parseable data
    let data = build_v4_entry(b"hello", b"world");
    let storage = SecretStore::safe_deserialize(&data).unwrap();
    assert_eq!(storage.len(), 1);
    assert_eq!(
        storage.history("hello").unwrap()[0].value.as_bytes(),
        b"world"
    );
}

#[test]
fn test_encrypted_value_display() {
    // Uses the debug_assertions From<&str> impl
    let val: EncryptedValue = enc("hello");
    let s = format!("{val}");
    assert!(s.contains("encrypted"));
    assert!(s.contains("5")); // 5 bytes
}

#[test]
fn test_storage_history_nonexistent() {
    let storage = SecretStore::new();
    assert!(storage.history("does_not_exist").is_none());
}
