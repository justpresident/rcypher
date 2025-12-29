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
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "key2".to_string(), "value2".into(), 0);

    let results: Vec<_> = storage.get("key1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "key1");
    assert_eq!(results[0].2.as_bytes(), "value1".as_bytes());
}

#[test]
fn test_storage_put_multiple_values() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "key1".to_string(), "value2".into(), 0);
    storage.put_at_path("/", "key1".to_string(), "value3".into(), 0);

    // get should return the latest value
    let results: Vec<_> = storage.get("key1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "key1");
    assert_eq!(results[0].2.as_bytes(), "value3".as_bytes());

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
    storage.put_at_path("/", "test1".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "test2".to_string(), "value2".into(), 0);
    storage.put_at_path("/", "prod1".to_string(), "value3".into(), 0);

    // Match all test keys
    let results: Vec<_> = storage.get("test.*").unwrap().collect();
    assert_eq!(results.len(), 2);

    // Match specific key
    let results: Vec<_> = storage.get("test1").unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "test1");
}

#[test]
fn test_storage_get_no_match() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);

    let results: Vec<_> = storage.get("nonexistent").unwrap().collect();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_storage_search() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "user_alice".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "user_bob".to_string(), "value2".into(), 0);
    storage.put_at_path("/", "admin_charlie".to_string(), "value3".into(), 0);

    let keys: Vec<_> = storage.search("user_").unwrap().collect();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .any(|(path, k)| path == "/" && *k == "user_alice")
    );
    assert!(keys.iter().any(|(path, k)| path == "/" && *k == "user_bob"));

    let all_keys: Vec<_> = storage.search("").unwrap().collect();
    assert_eq!(all_keys.len(), 3);
}

#[test]
fn test_storage_delete() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "key2".to_string(), "value2".into(), 0);

    assert!(storage.delete("key1"));
    assert_eq!(storage.root.secrets.len(), 1);

    assert!(!storage.delete("key1")); // Already deleted
    assert!(!storage.delete("nonexistent"));
}

#[test]
fn test_storage_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = StorageV5::new();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    storage.put_at_path("/", "key1".to_string(), "v1".into(), timestamp);
    storage.put_at_path("/", "key1".to_string(), "v2".into(), timestamp.add(1));
    storage.put_at_path("/", "key1".to_string(), "v3".into(), timestamp.add(2));

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
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 1);
    let entry = &deserialized.root.secrets["key1"][0];
    assert_eq!(entry.encrypted_value().as_bytes(), "value1".as_bytes());
}

#[test]
fn test_serialize_deserialize_multiple_entries() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "key2".to_string(), "value2".into(), 0);
    storage.put_at_path("/", "key1".to_string(), "value1_updated".into(), 0);

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.secrets.len(), 2);
    assert_eq!(deserialized.root.secrets["key1"].len(), 2);
    assert_eq!(deserialized.root.secrets["key2"].len(), 1);
}

#[test]
fn test_serialize_deserialize_unicode() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "ключ".to_string(), "значение".into(), 0);
    storage.put_at_path("/", "🔑".to_string(), "🎁".into(), 0);

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
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "key2".to_string(), "value2".into(), 0);

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
    storage.put_at_path("/", "key1".to_string(), "value1".into(), 0);

    save_storage_v5(&cypher1, &storage, &path).unwrap();

    // Should fail or return garbage
    let result = load_storage_v5(&cypher2, &path);
    assert!(result.is_err() || result.unwrap().root.secrets.is_empty());
}

#[test]
fn test_storage_ordering() {
    let mut storage = StorageV5::new();

    // Add keys in random order
    storage.put_at_path("/", "zebra".to_string(), "z".into(), 0);
    storage.put_at_path("/", "alpha".to_string(), "a".into(), 0);
    storage.put_at_path("/", "beta".to_string(), "b".into(), 0);

    // Search should return sorted
    let keys: Vec<_> = storage.search("").unwrap().collect();
    assert_eq!(keys[0], ("/".to_string(), "alpha"));
    assert_eq!(keys[1], ("/".to_string(), "beta"));
    assert_eq!(keys[2], ("/".to_string(), "zebra"));
}

#[test]
fn test_special_characters_in_keys() {
    let mut storage = StorageV5::new();
    storage.put_at_path("/", "key-with-dash".to_string(), "value1".into(), 0);
    storage.put_at_path("/", "key_with_underscore".to_string(), "value2".into(), 0);
    storage.put_at_path("/", "key.with.dots".to_string(), "value3".into(), 0);
    storage.put_at_path("/", "key@with@at".to_string(), "value4".into(), 0);

    assert_eq!(storage.root.secrets.len(), 4);

    let result: Vec<_> = storage.get("key-with-dash").unwrap().collect();
    assert_eq!(result[0].2.as_bytes(), "value1".as_bytes());
    let result: Vec<_> = storage.get("key_with_underscore").unwrap().collect();
    assert_eq!(result[0].2.as_bytes(), "value2".as_bytes());
    let result: Vec<_> = storage.get("key.with.dots").unwrap().collect();
    assert_eq!(result[0].2.as_bytes(), "value3".as_bytes());
    let result: Vec<_> = storage.get("key@with@at").unwrap().collect();
    assert_eq!(result[0].2.as_bytes(), "value4".as_bytes());

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
            s.put_at_path("/", format!("key{}", i), format!("value{}", i).into(), 0);
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
        storage.put_at_path("/", "session1_key".to_string(), "session1_value".into(), 0);
        save_storage_v5(&cypher, &storage, &path).unwrap();
    }

    // Session 2: Load and add
    {
        let mut storage = load_storage_v5(&cypher, &path).unwrap();
        assert_eq!(storage.root.secrets.len(), 1);
        storage.put_at_path("/", "session2_key".to_string(), "session2_value".into(), 0);
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
    storage.put_at_path("/", "".to_string(), "value".into(), 0);
    storage.put_at_path("/", "key".to_string(), "".into(), 0);

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

    storage.put_at_path("/", long_key.clone(), long_value.clone().into(), 0);

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(
        deserialized.root.secrets[&long_key][0]
            .encrypted_value()
            .as_bytes(),
        long_value.as_bytes()
    );
}

#[test]
fn test_regex_matches_full_path() {
    let mut storage = StorageV5::new();

    // Create folder structure and add keys
    storage.mkdir("/", "work").unwrap();
    storage.mkdir("/", "personal").unwrap();
    storage.put_at_path("/", "x_key".to_string(), "root_value".into(), 0);
    storage.put_at_path("/work", "api_key".to_string(), "work_api".into(), 0);
    storage.put_at_path("/work", "secret".to_string(), "work_secret".into(), 0);
    storage.put_at_path("/personal", "password".to_string(), "personal_pw".into(), 0);

    // Pattern "x.*" should match:
    // - "x_key" in root (path is "x_key")
    // But NOT "api_key" in /work (path is "work/api_key", doesn't match "x.*")
    let results: Vec<_> = storage.get_at_path("/", "x.*", true).unwrap().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "x_key");

    // Pattern "work.*" should match:
    // - "work/api_key" (matches "work.*")
    // - "work/secret" (matches "work.*")
    let results: Vec<_> = storage.get_at_path("/", "work.*", true).unwrap().collect();
    assert_eq!(results.len(), 2);
    assert!(
        results
            .iter()
            .any(|(p, k, _)| p == "/work" && *k == "api_key")
    );
    assert!(
        results
            .iter()
            .any(|(p, k, _)| p == "/work" && *k == "secret")
    );

    // Pattern "work/api.*" should match only "work/api_key"
    let results: Vec<_> = storage
        .get_at_path("/", "work/api.*", true)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/work");
    assert_eq!(results[0].1, "api_key");

    // Search should work the same way
    let keys: Vec<_> = storage
        .search_at_path("/", "work.*", true)
        .unwrap()
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|(p, k)| p == "/work" && *k == "api_key"));
    assert!(keys.iter().any(|(p, k)| p == "/work" && *k == "secret"));
}

#[test]
fn test_deep_nesting_operations() {
    let mut storage = StorageV5::new();

    // Create deeply nested folder structure (5 levels)
    storage.mkdir("/", "level1").unwrap();
    storage.mkdir("/level1", "level2").unwrap();
    storage.mkdir("/level1/level2", "level3").unwrap();
    storage.mkdir("/level1/level2/level3", "level4").unwrap();
    storage
        .mkdir("/level1/level2/level3/level4", "level5")
        .unwrap();

    // Add keys at different levels
    storage.put_at_path("/", "root_key".to_string(), "root_val".into(), 0);
    storage.put_at_path("/level1", "l1_key".to_string(), "l1_val".into(), 0);
    storage.put_at_path("/level1/level2", "l2_key".to_string(), "l2_val".into(), 0);
    storage.put_at_path(
        "/level1/level2/level3",
        "l3_key".to_string(),
        "l3_val".into(),
        0,
    );
    storage.put_at_path(
        "/level1/level2/level3/level4",
        "l4_key".to_string(),
        "l4_val".into(),
        0,
    );
    storage.put_at_path(
        "/level1/level2/level3/level4/level5",
        "l5_key".to_string(),
        "l5_val".into(),
        0,
    );

    // Test get from different levels
    let results: Vec<_> = storage
        .get_at_path("/", "root_key", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "root_key");

    let results: Vec<_> = storage
        .get_at_path("/level1/level2/level3", "l3_key", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/level1/level2/level3");
    assert_eq!(results[0].1, "l3_key");

    let results: Vec<_> = storage
        .get_at_path("/level1/level2/level3/level4/level5", "l5_key", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/level1/level2/level3/level4/level5");
    assert_eq!(results[0].1, "l5_key");

    // Test recursive search from root
    let all_keys: Vec<_> = storage.search_at_path("/", ".*", true).unwrap().collect();
    assert_eq!(all_keys.len(), 6);

    // Test recursive search from nested folder
    let nested_keys: Vec<_> = storage
        .search_at_path("/level1/level2", ".*", true)
        .unwrap()
        .collect();
    assert_eq!(nested_keys.len(), 4); // l2_key, l3_key, l4_key, l5_key
}

#[test]
fn test_nested_folder_regex_matching() {
    let mut storage = StorageV5::new();

    // Create nested structure with multiple branches
    storage.mkdir("/", "work").unwrap();
    storage.mkdir("/work", "projects").unwrap();
    storage.mkdir("/work", "configs").unwrap();
    storage.mkdir("/work/projects", "client_a").unwrap();
    storage.mkdir("/work/projects", "client_b").unwrap();

    // Add keys with patterns
    storage.put_at_path(
        "/work/projects/client_a",
        "api_key".to_string(),
        "key_a".into(),
        0,
    );
    storage.put_at_path(
        "/work/projects/client_a",
        "api_secret".to_string(),
        "secret_a".into(),
        0,
    );
    storage.put_at_path(
        "/work/projects/client_b",
        "api_key".to_string(),
        "key_b".into(),
        0,
    );
    storage.put_at_path(
        "/work/configs",
        "database".to_string(),
        "db_config".into(),
        0,
    );

    // Pattern "work/projects/client_a/.*" should match only client_a keys
    let results: Vec<_> = storage
        .get_at_path("/", "work/projects/client_a/.*", true)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 2);
    assert!(
        results
            .iter()
            .all(|(p, _, _)| p == "/work/projects/client_a")
    );

    // Pattern "work/projects/.*/api_key" should match both clients' api_key
    let results: Vec<_> = storage
        .get_at_path("/", "work/projects/.*/api_key", true)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 2);
    assert!(
        results
            .iter()
            .any(|(p, k, _)| p == "/work/projects/client_a" && *k == "api_key")
    );
    assert!(
        results
            .iter()
            .any(|(p, k, _)| p == "/work/projects/client_b" && *k == "api_key")
    );

    // Pattern "work/.*/database" should match only database in configs
    let results: Vec<_> = storage
        .get_at_path("/", "work/.*/database", true)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/work/configs");
    assert_eq!(results[0].1, "database");
}

#[test]
fn test_nested_folder_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = StorageV5::new();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create nested folder
    storage.mkdir("/", "work").unwrap();
    storage.mkdir("/work", "projects").unwrap();

    // Add multiple versions of a nested key
    storage.put_at_path(
        "/work/projects",
        "secret".to_string(),
        "v1".into(),
        timestamp,
    );
    storage.put_at_path(
        "/work/projects",
        "secret".to_string(),
        "v2".into(),
        timestamp.add(1),
    );
    storage.put_at_path(
        "/work/projects",
        "secret".to_string(),
        "v3".into(),
        timestamp.add(2),
    );

    // Get history from nested folder
    let history: Vec<_> = storage
        .history_at_path("/work/projects", "secret")
        .unwrap()
        .collect();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].encrypted_value().as_bytes(), "v1".as_bytes());
    assert_eq!(history[1].encrypted_value().as_bytes(), "v2".as_bytes());
    assert_eq!(history[2].encrypted_value().as_bytes(), "v3".as_bytes());

    // Verify timestamps are in order
    assert!(history[0].timestamp + 1 == history[1].timestamp);
    assert!(history[1].timestamp + 1 == history[2].timestamp);
}

#[test]
fn test_nested_folder_delete() {
    let mut storage = StorageV5::new();

    // Create nested structure with keys
    storage.mkdir("/", "work").unwrap();
    storage.mkdir("/work", "projects").unwrap();
    storage.put_at_path("/work/projects", "secret1".to_string(), "val1".into(), 0);
    storage.put_at_path("/work/projects", "secret2".to_string(), "val2".into(), 0);

    // Delete key from nested folder
    assert!(storage.delete_at_path("/work/projects", "secret1"));

    // Verify only secret1 is deleted
    let results: Vec<_> = storage
        .get_at_path("/work/projects", "secret1", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 0);

    let results: Vec<_> = storage
        .get_at_path("/work/projects", "secret2", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);

    // Try to delete non-existent key
    assert!(!storage.delete_at_path("/work/projects", "secret1"));
    assert!(!storage.delete_at_path("/work/projects", "nonexistent"));
}

#[test]
fn test_nested_folder_serialization() {
    let mut storage = StorageV5::new();

    // Create complex nested structure
    storage.mkdir("/", "org").unwrap();
    storage.mkdir("/org", "dept").unwrap();
    storage.mkdir("/org/dept", "team").unwrap();
    storage.put_at_path("/org", "org_key".to_string(), "org_val".into(), 0);
    storage.put_at_path("/org/dept", "dept_key".to_string(), "dept_val".into(), 0);
    storage.put_at_path(
        "/org/dept/team",
        "team_key".to_string(),
        "team_val".into(),
        0,
    );

    // Serialize and deserialize
    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    // Verify structure is preserved
    assert!(deserialized.get_folder("/org").is_some());
    assert!(deserialized.get_folder("/org/dept").is_some());
    assert!(deserialized.get_folder("/org/dept/team").is_some());

    // Verify keys are preserved
    let results: Vec<_> = deserialized
        .get_at_path("/org", "org_key", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].2.as_bytes(), "org_val".as_bytes());

    let results: Vec<_> = deserialized
        .get_at_path("/org/dept/team", "team_key", false)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].2.as_bytes(), "team_val".as_bytes());
}

#[test]
fn test_multiple_nested_branches() {
    let mut storage = StorageV5::new();

    // Create multiple independent nested branches
    storage.mkdir("/", "work").unwrap();
    storage.mkdir("/work", "project_a").unwrap();
    storage.mkdir("/work", "project_b").unwrap();
    storage.mkdir("/", "personal").unwrap();
    storage.mkdir("/personal", "finance").unwrap();
    storage.mkdir("/personal", "health").unwrap();

    // Add keys to different branches
    storage.put_at_path("/work/project_a", "api".to_string(), "api_a".into(), 0);
    storage.put_at_path("/work/project_b", "api".to_string(), "api_b".into(), 0);
    storage.put_at_path(
        "/personal/finance",
        "account".to_string(),
        "acc123".into(),
        0,
    );
    storage.put_at_path(
        "/personal/health",
        "insurance".to_string(),
        "ins456".into(),
        0,
    );

    // Search all work keys
    let work_keys: Vec<_> = storage
        .search_at_path("/work", ".*", true)
        .unwrap()
        .collect();
    assert_eq!(work_keys.len(), 2);

    // Search all personal keys
    let personal_keys: Vec<_> = storage
        .search_at_path("/personal", ".*", true)
        .unwrap()
        .collect();
    assert_eq!(personal_keys.len(), 2);

    // Search for specific pattern across all branches
    let api_keys: Vec<_> = storage
        .search_at_path("/", "work/.*/api", true)
        .unwrap()
        .collect();
    assert_eq!(api_keys.len(), 2);
    assert!(
        api_keys
            .iter()
            .any(|(p, k)| p == "/work/project_a" && *k == "api")
    );
    assert!(
        api_keys
            .iter()
            .any(|(p, k)| p == "/work/project_b" && *k == "api")
    );
}
