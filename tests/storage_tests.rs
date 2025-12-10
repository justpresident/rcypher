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
    let storage = Storage::new();
    assert_eq!(storage.data.len(), 0);
}

#[test]
fn test_storage_put_get() {
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());
    storage.put("key2".to_string(), "value2".to_string());

    let results = storage.get("key1").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "key1");
    assert_eq!(results[0].1, "value1");
}

#[test]
fn test_storage_put_multiple_values() {
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());
    storage.put("key1".to_string(), "value2".to_string());
    storage.put("key1".to_string(), "value3".to_string());

    // get should return the latest value
    let results = storage.get("key1").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, "value3");

    // history should return all values
    let history = storage.history("key1").unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].value, "value1");
    assert_eq!(history[1].value, "value2");
    assert_eq!(history[2].value, "value3");
}

#[test]
fn test_storage_get_with_regex() {
    let mut storage = Storage::new();
    storage.put("test1".to_string(), "value1".to_string());
    storage.put("test2".to_string(), "value2".to_string());
    storage.put("prod1".to_string(), "value3".to_string());

    // Match all test keys
    let results = storage.get("test.*").unwrap();
    assert_eq!(results.len(), 2);

    // Match specific key
    let results = storage.get("test1").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "test1");
}

#[test]
fn test_storage_get_no_match() {
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());

    let results = storage.get("nonexistent").unwrap();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_storage_search() {
    let mut storage = Storage::new();
    storage.put("user_alice".to_string(), "value1".to_string());
    storage.put("user_bob".to_string(), "value2".to_string());
    storage.put("admin_charlie".to_string(), "value3".to_string());

    let keys = storage.search("user_").unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"user_alice".to_string()));
    assert!(keys.contains(&"user_bob".to_string()));

    let all_keys = storage.search("").unwrap();
    assert_eq!(all_keys.len(), 3);
}

#[test]
fn test_storage_delete() {
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());
    storage.put("key2".to_string(), "value2".to_string());

    assert!(storage.delete("key1"));
    assert_eq!(storage.data.len(), 1);

    assert!(!storage.delete("key1")); // Already deleted
    assert!(!storage.delete("nonexistent"));
}

#[test]
fn test_storage_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "v1".to_string());
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    storage.put_ts("key1".to_string(), "v2".to_string(), timestamp.add(1));
    storage.put_ts("key1".to_string(), "v3".to_string(), timestamp.add(2));

    let history = storage.history("key1").unwrap();
    assert_eq!(history.len(), 3);

    // Timestamps should be in ascending order
    assert!(history[0].timestamp + 1 == history[1].timestamp);
    assert!(history[1].timestamp + 1 == history[2].timestamp);

    // Values should be in order
    assert_eq!(history[0].value, "v1");
    assert_eq!(history[1].value, "v2");
    assert_eq!(history[2].value, "v3");
}

#[test]
fn test_serialize_deserialize_empty() {
    let storage = Storage::new();
    let serialized = serialize_storage(&storage);
    let deserialized = deserialize_storage(&serialized).unwrap();

    assert_eq!(deserialized.data.len(), 0);
}

#[test]
fn test_serialize_deserialize_single_entry() {
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());

    let serialized = serialize_storage(&storage);
    let deserialized = deserialize_storage(&serialized).unwrap();

    assert_eq!(deserialized.data.len(), 1);
    let entry = &deserialized.data["key1"][0];
    assert_eq!(entry.value, "value1");
}

#[test]
fn test_serialize_deserialize_multiple_entries() {
    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());
    storage.put("key2".to_string(), "value2".to_string());
    storage.put("key1".to_string(), "value1_updated".to_string());

    let serialized = serialize_storage(&storage);
    let deserialized = deserialize_storage(&serialized).unwrap();

    assert_eq!(deserialized.data.len(), 2);
    assert_eq!(deserialized.data["key1"].len(), 2);
    assert_eq!(deserialized.data["key2"].len(), 1);
}

#[test]
fn test_serialize_deserialize_unicode() {
    let mut storage = Storage::new();
    storage.put("ключ".to_string(), "значение".to_string());
    storage.put("🔑".to_string(), "🎁".to_string());

    let serialized = serialize_storage(&storage);
    let deserialized = deserialize_storage(&serialized).unwrap();

    assert_eq!(deserialized.data.len(), 2);
    assert_eq!(deserialized.data["ключ"][0].value, "значение");
    assert_eq!(deserialized.data["🔑"][0].value, "🎁");
}

#[test]
fn test_deserialize_corrupted_data() {
    // Too short
    let result = deserialize_storage(&[0, 1, 2]);
    assert!(result.is_err());

    // Invalid version
    let mut data = vec![0, 99]; // version 99
    data.extend_from_slice(&[0, 0, 0, 1]); // count = 1
    let result = deserialize_storage(&data);
    assert!(result.is_err());
}

#[test]
fn test_load_save_storage() {
    let (_dir, path) = temp_test_file();
    let cypher = Cypher::new("test_password");

    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());
    storage.put("key2".to_string(), "value2".to_string());

    save_storage(&cypher, &storage, &path).unwrap();
    assert!(path.exists());

    let loaded = load_storage(&cypher, &path).unwrap();
    assert_eq!(loaded.data.len(), 2);
    assert_eq!(loaded.data["key1"][0].value, "value1");
    assert_eq!(loaded.data["key2"][0].value, "value2");
}

#[test]
fn test_load_nonexistent_file() {
    let (_dir, path) = temp_test_file();
    let cypher = Cypher::new("test_password");

    let storage = load_storage(&cypher, &path).unwrap();
    assert_eq!(storage.data.len(), 0);
}

#[test]
fn test_load_with_wrong_password() {
    let (_dir, path) = temp_test_file();
    let cypher1 = Cypher::new("password1");
    let cypher2 = Cypher::new("password2");

    let mut storage = Storage::new();
    storage.put("key1".to_string(), "value1".to_string());

    save_storage(&cypher1, &storage, &path).unwrap();

    // Should fail or return garbage
    let result = load_storage(&cypher2, &path);
    assert!(result.is_err() || result.unwrap().data.is_empty());
}

#[test]
fn test_storage_ordering() {
    let mut storage = Storage::new();

    // Add keys in random order
    storage.put("zebra".to_string(), "z".to_string());
    storage.put("alpha".to_string(), "a".to_string());
    storage.put("beta".to_string(), "b".to_string());

    // Search should return sorted
    let keys = storage.search("").unwrap();
    assert_eq!(keys[0], "alpha");
    assert_eq!(keys[1], "beta");
    assert_eq!(keys[2], "zebra");
}

#[test]
fn test_special_characters_in_keys() {
    let mut storage = Storage::new();
    storage.put("key-with-dash".to_string(), "value1".to_string());
    storage.put("key_with_underscore".to_string(), "value2".to_string());
    storage.put("key.with.dots".to_string(), "value3".to_string());
    storage.put("key@with@at".to_string(), "value4".to_string());

    assert_eq!(storage.data.len(), 4);

    let mut result = storage.get("key-with-dash").unwrap();
    assert_eq!(result[0].1, "value1");
    result = storage.get("key_with_underscore").unwrap();
    assert_eq!(result[0].1, "value2");
    result = storage.get("key.with.dots").unwrap();
    assert_eq!(result[0].1, "value3");
    result = storage.get("key@with@at").unwrap();
    assert_eq!(result[0].1, "value4");

    // Dot in regex matches any character
    let results = storage.get("key.*").unwrap();
    assert_eq!(results.len(), 4);
}

#[test]
fn test_concurrent_operations() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(Storage::new()));
    let mut handles = vec![];

    for i in 0..10 {
        let storage_clone = Arc::clone(&storage);
        let handle = thread::spawn(move || {
            let mut s = storage_clone.lock().unwrap();
            s.put(format!("key{}", i), format!("value{}", i));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_storage = storage.lock().unwrap();
    assert_eq!(final_storage.data.len(), 10);
}

#[test]
fn test_storage_persistence_across_sessions() {
    let (_dir, path) = temp_test_file();
    let cypher = Cypher::new("test_password");

    // Session 1: Create and save
    {
        let mut storage = Storage::new();
        storage.put("session1_key".to_string(), "session1_value".to_string());
        save_storage(&cypher, &storage, &path).unwrap();
    }

    // Session 2: Load and add
    {
        let mut storage = load_storage(&cypher, &path).unwrap();
        assert_eq!(storage.data.len(), 1);
        storage.put("session2_key".to_string(), "session2_value".to_string());
        save_storage(&cypher, &storage, &path).unwrap();
    }

    // Session 3: Verify both keys exist
    {
        let storage = load_storage(&cypher, &path).unwrap();
        assert_eq!(storage.data.len(), 2);
        assert!(storage.data.contains_key("session1_key"));
        assert!(storage.data.contains_key("session2_key"));
    }
}

#[test]
fn test_empty_key_value() {
    let mut storage = Storage::new();
    storage.put("".to_string(), "value".to_string());
    storage.put("key".to_string(), "".to_string());

    assert_eq!(storage.data.len(), 2);

    let serialized = serialize_storage(&storage);
    let deserialized = deserialize_storage(&serialized).unwrap();

    assert_eq!(deserialized.data.len(), 2);
    assert_eq!(deserialized.data[""][0].value, "value");
    assert_eq!(deserialized.data["key"][0].value, "");
}

#[test]
fn test_very_long_key_value() {
    let mut storage = Storage::new();
    let long_key = "k".repeat(10000);
    let long_value = "v".repeat(50000);

    storage.put(long_key.clone(), long_value.clone());

    let serialized = serialize_storage(&storage);
    let deserialized = deserialize_storage(&serialized).unwrap();

    assert_eq!(deserialized.data[&long_key][0].value, long_value);
}
