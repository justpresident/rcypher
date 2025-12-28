use rcypher::*;
use std::ops::Add;
use std::path::PathBuf;
use tempfile::TempDir;

// Helper to create a temporary test file
fn temp_test_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rcypher_test");
    (dir, path)
}

#[test]
fn test_storage_new() {
    let storage = StorageV5::new();
    assert_eq!(storage.root.secrets.len(), 0);
}

#[test]
fn test_storage_put_get() {
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());
    storage.put("key2".to_string(), "value2".into());

    let results: Vec<_> = storage.get("key1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0.as_bytes(), "key1".as_bytes());
    assert_eq!(results[0].1.as_bytes(), "value1".as_bytes());
}

#[test]
fn test_storage_put_multiple_values() {
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());
    storage.put("key1".to_string(), "value2".into());
    storage.put("key1".to_string(), "value3".into());

    // get should return the latest value
    let results: Vec<_> = storage.get("key1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1.as_bytes(), "value3".as_bytes());

    // history should return all values
    let history: Vec<_> = storage.history("key1").unwrap().collect();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].encrypted_value().as_bytes(), "value1".as_bytes());
    assert_eq!(history[1].encrypted_value().as_bytes(), "value2".as_bytes());
    assert_eq!(history[2].encrypted_value().as_bytes(), "value3".as_bytes());
}

#[test]
fn test_storage_get_with_regex() {
    let mut storage = StorageV5::new();
    storage.put("test1".to_string(), "value1".into());
    storage.put("test2".to_string(), "value2".into());
    storage.put("prod1".to_string(), "value3".into());

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
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());

    let results: Vec<_> = storage.get("nonexistent").unwrap().collect();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_storage_search() {
    let mut storage = StorageV5::new();
    storage.put("user_alice".to_string(), "value1".into());
    storage.put("user_bob".to_string(), "value2".into());
    storage.put("admin_charlie".to_string(), "value3".into());

    let keys: Vec<_> = storage.search("user_").unwrap().collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"user_alice"));
    assert!(keys.contains(&"user_bob"));

    let all_keys: Vec<_> = storage.search("").unwrap().collect();
    assert_eq!(all_keys.len(), 3);
}

#[test]
fn test_storage_delete() {
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());
    storage.put("key2".to_string(), "value2".into());

    assert!(storage.delete("key1"));
    assert_eq!(storage.root.secrets.len(), 1);

    assert!(!storage.delete("key1")); // Already deleted
    assert!(!storage.delete("nonexistent"));
}

#[test]
fn test_storage_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "v1".into());
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    storage.put_ts("key1".to_string(), "v2".into(), timestamp.add(1));
    storage.put_ts("key1".to_string(), "v3".into(), timestamp.add(2));

    let history: Vec<_> = storage.history("key1").unwrap().collect();
    assert_eq!(history.len(), 3);

    // Timestamps should be in ascending order
    assert!(history[0].timestamp + 1 == history[1].timestamp);
    assert!(history[1].timestamp + 1 == history[2].timestamp);

    // Values should be in order
    assert_eq!(history[0].encrypted_value().as_bytes(), "v1".as_bytes());
    assert_eq!(history[1].encrypted_value().as_bytes(), "v2".as_bytes());
    assert_eq!(history[2].encrypted_value().as_bytes(), "v3".as_bytes());
}

#[test]
fn test_serialize_deserialize_empty() {
    let storage = StorageV5::new();
    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 0);
}

#[test]
fn test_serialize_deserialize_single_entry() {
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 1);
    let entry = &deserialized.root.secrets["key1"][0];
    assert_eq!(entry.encrypted_value().as_bytes(), "value1".as_bytes());
}

#[test]
fn test_serialize_deserialize_multiple_entries() {
    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());
    storage.put("key2".to_string(), "value2".into());
    storage.put("key1".to_string(), "value1_updated".into());

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 2);
    assert_eq!(deserialized.root.secrets["key1"].len(), 2);
    assert_eq!(deserialized.root.secrets["key2"].len(), 1);
}

#[test]
fn test_serialize_deserialize_unicode() {
    let mut storage = StorageV5::new();
    storage.put("ключ".to_string(), "значение".into());
    storage.put("🔑".to_string(), "🎁".into());

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 2);
    assert_eq!(
        deserialized.root.secrets["ключ"][0]
            .encrypted_value()
            .as_bytes(),
        "значение".as_bytes()
    );
    assert_eq!(
        deserialized.root.secrets["🔑"][0]
            .encrypted_value()
            .as_bytes(),
        "🎁".as_bytes()
    );
}

#[test]
fn test_deserialize_corrupted_data() {
    // Too short
    let result = deserialize_storage_v5_from_slice(&[0, 1, 2]);
    assert!(result.is_err());

    // Invalid version
    let mut data = vec![0, 99]; // version 99
    data.extend_from_slice(&[0, 0, 0, 1]); // count = 1
    let result = deserialize_storage_v5_from_slice(&data);
    assert!(result.is_err());
}

#[test]
fn test_load_save_storage_v5() {
    let (_dir, path) = temp_test_file();

    let cypher = Cypher::new(EncryptionKey::for_file("test_password", &path).unwrap());

    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());
    storage.put("key2".to_string(), "value2".into());

    save_storage_v5(&cypher, &storage, &path).unwrap();
    assert!(path.exists());

    let loaded = load_storage_v5(&cypher, &path).unwrap();
    assert_eq!(loaded.root.secrets.len(), 2);
    assert_eq!(
        loaded.root.secrets["key1"][0].encrypted_value().as_bytes(),
        "value1".as_bytes()
    );
    assert_eq!(
        loaded.root.secrets["key2"][0].encrypted_value().as_bytes(),
        "value2".as_bytes()
    );
}

#[test]
fn test_load_nonexistent_file() {
    let (_dir, path) = temp_test_file();

    let cypher = Cypher::new(EncryptionKey::for_file("test_password", &path).unwrap());

    let storage = load_storage_v5(&cypher, &path).unwrap();
    assert_eq!(storage.root.secrets.len(), 0);
}

#[test]
fn test_load_with_wrong_password() {
    let (_dir, path) = temp_test_file();
    let cypher1 = Cypher::new(EncryptionKey::for_file("test_password", &path).unwrap());
    let cypher2 = Cypher::new(EncryptionKey::for_file("test_password2", &path).unwrap());

    let mut storage = StorageV5::new();
    storage.put("key1".to_string(), "value1".into());

    save_storage_v5(&cypher1, &storage, &path).unwrap();

    // Should fail or return garbage
    let result = load_storage_v5(&cypher2, &path);
    assert!(result.is_err() || result.unwrap().root.secrets.is_empty());
}

#[test]
fn test_storage_ordering() {
    let mut storage = StorageV5::new();

    // Add keys in random order
    storage.put("zebra".to_string(), "z".into());
    storage.put("alpha".to_string(), "a".into());
    storage.put("beta".to_string(), "b".into());

    // Search should return sorted
    let keys: Vec<_> = storage.search("").unwrap().collect();
    assert_eq!(keys[0], "alpha");
    assert_eq!(keys[1], "beta");
    assert_eq!(keys[2], "zebra");
}

#[test]
fn test_special_characters_in_keys() {
    let mut storage = StorageV5::new();
    storage.put("key-with-dash".to_string(), "value1".into());
    storage.put("key_with_underscore".to_string(), "value2".into());
    storage.put("key.with.dots".to_string(), "value3".into());
    storage.put("key@with@at".to_string(), "value4".into());

    assert_eq!(storage.root.secrets.len(), 4);

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

    let storage = Arc::new(Mutex::new(StorageV5::new()));
    let mut handles = vec![];

    for i in 0..10 {
        let storage_clone = Arc::clone(&storage);
        let handle = thread::spawn(move || {
            let mut s = storage_clone.lock().unwrap();
            s.put(format!("key{}", i), format!("value{}", i).into());
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_storage = storage.lock().unwrap();
    assert_eq!(final_storage.root.secrets.len(), 10);
}

#[test]
fn test_storage_persistence_across_sessions() {
    let (_dir, path) = temp_test_file();
    let cypher = Cypher::new(EncryptionKey::for_file("test_password", &path).unwrap());

    // Session 1: Create and save
    {
        let mut storage = StorageV5::new();
        storage.put("session1_key".to_string(), "session1_value".into());
        save_storage_v5(&cypher, &storage, &path).unwrap();
    }

    // Session 2: Load and add
    {
        let mut storage = load_storage_v5(&cypher, &path).unwrap();
        assert_eq!(storage.root.secrets.len(), 1);
        storage.put("session2_key".to_string(), "session2_value".into());
        save_storage_v5(&cypher, &storage, &path).unwrap();
    }

    // Session 3: Verify both keys exist
    {
        let storage = load_storage_v5(&cypher, &path).unwrap();
        assert_eq!(storage.root.secrets.len(), 2);
        assert!(storage.root.secrets.contains_key("session1_key"));
        assert!(storage.root.secrets.contains_key("session2_key"));
    }
}

#[test]
fn test_empty_key_value() {
    let mut storage = StorageV5::new();
    storage.put("".to_string(), "value".into());
    storage.put("key".to_string(), "".into());

    assert_eq!(storage.root.secrets.len(), 2);

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 2);
    assert_eq!(
        deserialized.root.secrets[""][0]
            .encrypted_value()
            .as_bytes(),
        "value".as_bytes()
    );
    assert_eq!(
        deserialized.root.secrets["key"][0]
            .encrypted_value()
            .as_bytes(),
        "".as_bytes()
    );
}

#[test]
fn test_very_long_key_value() {
    let mut storage = StorageV5::new();
    let long_key = "k".repeat(10000);
    let long_value = "v".repeat(50000);

    storage.put(long_key.clone(), long_value.clone().into());

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(
        deserialized.root.secrets[&long_key][0]
            .encrypted_value()
            .as_bytes(),
        long_value.as_bytes()
    );
}
