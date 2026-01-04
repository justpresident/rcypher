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

// Helper to create a test domain manager with master key
fn test_domain_manager() -> EncryptionDomainManager {
    let key = EncryptionKey::from_password_with_params(
        CypherVersion::default(),
        "test_password",
        &Argon2Params::insecure(),
    )
    .expect("Failed to create key");
    let cypher = Cypher::new(key);
    EncryptionDomainManager::new(cypher)
}

#[test]
fn test_storage_new() {
    let storage = StorageV5::new();
    assert_eq!(storage.root.items.len(), 0);
}

#[test]
fn test_storage_put_get() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key2".to_string(), "value2", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    let results: Vec<_> = storage
        .get_at_path("/", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "key1");
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
}

#[test]
fn test_storage_put_multiple_values() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key1".to_string(), "value2", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key1".to_string(), "value3", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    // get should return the latest value
    let results: Vec<_> = storage
        .get_at_path("/", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "key1");
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value3"
    );

    // history should return all values
    let history: Vec<_> = storage.history_at_path("/", "key1", &dm).unwrap().collect();
    assert_eq!(history.len(), 3);
    assert_eq!(
        history[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
    assert_eq!(
        history[1]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value2"
    );
    assert_eq!(
        history[2]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value3"
    );
}

#[test]
fn test_storage_get_with_regex() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "test1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "test2".to_string(), "value2", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "prod1".to_string(), "value3", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    // Match all test keys
    let results: Vec<_> = storage
        .get_at_path("/", "test.*", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 2);

    // Match specific key
    let results: Vec<_> = storage
        .get_at_path("/", "test1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "test1");
}

#[test]
fn test_storage_get_no_match() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    let results: Vec<_> = storage
        .get_at_path("/", "nonexistent", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_storage_search() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path(
            "/",
            "user_alice".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "user_bob".to_string(),
            "value2",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "admin_charlie".to_string(),
            "value3",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    let keys: Vec<_> = storage
        .search_at_path("/", "user_", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .any(|(path, k)| path == "/" && *k == "user_alice")
    );
    assert!(keys.iter().any(|(path, k)| path == "/" && *k == "user_bob"));

    let all_keys: Vec<_> = storage
        .search_at_path("/", "", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(all_keys.len(), 3);
}

#[test]
fn test_storage_delete() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key2".to_string(), "value2", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    assert!(storage.delete_at_path("/", "key1", &dm));
    assert_eq!(storage.root.items.len(), 1);

    assert!(!storage.delete_at_path("/", "key1", &dm)); // Already deleted
    assert!(!storage.delete_at_path("/", "nonexistent", &dm));
}

#[test]
fn test_storage_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    storage
        .put_at_path(
            "/",
            "key1".to_string(),
            "v1",
            timestamp,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "key1".to_string(),
            "v2",
            timestamp.add(1),
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "key1".to_string(),
            "v3",
            timestamp.add(2),
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    let history: Vec<_> = storage.history_at_path("/", "key1", &dm).unwrap().collect();
    assert_eq!(history.len(), 3);

    // Timestamps should be in ascending order
    assert!(history[0].timestamp + 1 == history[1].timestamp);
    assert!(history[1].timestamp + 1 == history[2].timestamp);

    // Values should be in order
    assert_eq!(
        history[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v1"
    );
    assert_eq!(
        history[1]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v2"
    );
    assert_eq!(
        history[2]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v3"
    );
}

#[test]
fn test_serialize_deserialize_empty() {
    let storage = StorageV5::new();
    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.items.len(), 0);
}

#[test]
fn test_serialize_deserialize_single_entry() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.items.len(), 1);
    let entry = &deserialized.root.items["key1"].get_entries().unwrap()[0];
    assert_eq!(
        entry
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
}

#[test]
fn test_serialize_deserialize_multiple_entries() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key2".to_string(), "value2", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path(
            "/",
            "key1".to_string(),
            "value1_updated",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.items.len(), 2);
    assert_eq!(
        deserialized.root.items["key1"].get_entries().unwrap().len(),
        2
    );
    assert_eq!(
        deserialized.root.items["key2"].get_entries().unwrap().len(),
        1
    );
}

#[test]
fn test_serialize_deserialize_unicode() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path(
            "/",
            "ключ".to_string(),
            "значение",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path("/", "🔑".to_string(), "🎁", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.items.len(), 2);
    assert_eq!(
        deserialized.root.items["ключ"].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "значение"
    );
    assert_eq!(
        deserialized.root.items["🔑"].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "🎁"
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

    let cypher = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );

    let mut storage = StorageV5::new();
    let dm = EncryptionDomainManager::new(cypher);
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key2".to_string(), "value2", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    save_storage_v5(&dm, &mut storage, &path).unwrap();
    assert!(path.exists());

    let loaded = load_storage_v5(dm.get_master_cypher(), &path).unwrap();
    assert_eq!(loaded.root.items.len(), 2);
    assert_eq!(
        loaded.root.items["key1"].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
    assert_eq!(
        loaded.root.items["key2"].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value2"
    );
}

#[test]
fn test_load_nonexistent_file() {
    let (_dir, path) = temp_test_file();

    let cypher = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );

    let storage = load_storage_v5(&cypher, &path).unwrap();
    assert_eq!(storage.root.items.len(), 0);
}

#[test]
fn test_load_with_wrong_password() {
    let (_dir, path) = temp_test_file();
    let cypher1 = Cypher::new(
        EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
            .unwrap(),
    );
    let dm1 = EncryptionDomainManager::new(cypher1);
    let cypher2 = Cypher::new(
        EncryptionKey::for_file_with_params("test_password2", &path, &Argon2Params::insecure())
            .unwrap(),
    );
    let dm2 = EncryptionDomainManager::new(cypher2);

    let mut storage = StorageV5::new();
    storage
        .put_at_path("/", "key1".to_string(), "value1", 0, MASTER_DOMAIN_ID, &dm1)
        .unwrap();

    save_storage_v5(&dm1, &mut storage, &path).unwrap();

    // Should fail or return garbage
    let result = load_storage_v5(dm2.get_master_cypher(), &path);
    assert!(result.is_err() || result.unwrap().root.items.is_empty());
}

#[test]
fn test_storage_ordering() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Add keys in random order
    storage
        .put_at_path("/", "zebra".to_string(), "z", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "alpha".to_string(), "a", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "beta".to_string(), "b", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    // Search should return sorted
    let keys: Vec<_> = storage
        .search_at_path("/", "", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(keys[0], ("/".to_string(), "alpha"));
    assert_eq!(keys[1], ("/".to_string(), "beta"));
    assert_eq!(keys[2], ("/".to_string(), "zebra"));
}

#[test]
fn test_special_characters_in_keys() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path(
            "/",
            "key-with-dash".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "key_with_underscore".to_string(),
            "value2",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "key.with.dots".to_string(),
            "value3",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/",
            "key@with@at".to_string(),
            "value4",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    assert_eq!(storage.root.items.len(), 4);

    let result: Vec<_> = storage
        .get_at_path("/", "key-with-dash", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(
        result[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
    let result: Vec<_> = storage
        .get_at_path("/", "key_with_underscore", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(
        result[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value2"
    );
    let result: Vec<_> = storage
        .get_at_path("/", "key.with.dots", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(
        result[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value3"
    );
    let result: Vec<_> = storage
        .get_at_path("/", "key@with@at", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(
        result[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value4"
    );

    // Dot in regex matches any character
    let results: Vec<_> = storage
        .get_at_path("/", "key.*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 4);
}

#[test]
fn test_concurrent_operations() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(StorageV5::new()));
    let dm = Arc::new(test_domain_manager());
    let mut handles = vec![];

    for i in 0..10 {
        let storage_clone = Arc::clone(&storage);
        let dm_clone = Arc::clone(&dm);
        let handle = thread::spawn(move || {
            let mut s = storage_clone.lock().unwrap();
            s.put_at_path(
                "/",
                format!("key{}", i),
                &format!("value{}", i),
                0,
                MASTER_DOMAIN_ID,
                &dm_clone,
            )
            .unwrap();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let final_storage = storage.lock().unwrap();
    assert_eq!(final_storage.root.items.len(), 10);
}

#[test]
fn test_storage_persistence_across_sessions() {
    use rcypher::*;

    let (_dir, path) = temp_test_file();

    // Helper to create domain manager with the same key for existing file
    let make_dm = || {
        let key =
            EncryptionKey::for_file_with_params("test_password", &path, &Argon2Params::insecure())
                .unwrap();
        EncryptionDomainManager::new(Cypher::new(key))
    };

    // Session 1: Create and save
    {
        let mut storage = StorageV5::new();
        let dm = make_dm();
        storage
            .put_at_path(
                "/",
                "session1_key".to_string(),
                "session1_value",
                0,
                MASTER_DOMAIN_ID,
                &dm,
            )
            .unwrap();
        save_storage_v5(&dm, &mut storage, &path).unwrap();
    }

    // Session 2: Load and add
    {
        let dm = make_dm();
        let mut storage = load_storage_v5(dm.get_master_cypher(), &path).unwrap();
        assert_eq!(storage.root.items.len(), 1);
        storage
            .put_at_path(
                "/",
                "session2_key".to_string(),
                "session2_value",
                0,
                MASTER_DOMAIN_ID,
                &dm,
            )
            .unwrap();
        save_storage_v5(&dm, &mut storage, &path).unwrap();
    }

    // Session 3: Verify both keys exist
    {
        let dm = make_dm();
        let storage = load_storage_v5(dm.get_master_cypher(), &path).unwrap();
        assert_eq!(storage.root.items.len(), 2);
        assert!(storage.root.items.contains_key("session1_key"));
        assert!(storage.root.items.contains_key("session2_key"));
    }
}

#[test]
fn test_empty_key_value() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "".to_string(), "value", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();
    storage
        .put_at_path("/", "key".to_string(), "", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    assert_eq!(storage.root.items.len(), 2);

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.root.items.len(), 2);
    assert_eq!(
        deserialized.root.items[""].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value"
    );
    assert_eq!(
        deserialized.root.items["key"].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        ""
    );
}

#[test]
fn test_very_long_key_value() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    let long_key = "k".repeat(10000);
    let long_value = "v".repeat(50000);

    storage
        .put_at_path("/", long_key.clone(), &long_value, 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    assert_eq!(
        deserialized.root.items[&long_key].get_entries().unwrap()[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        long_value.as_str()
    );
}

#[test]
fn test_regex_matches_full_path() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Create folder structure and add keys
    storage.mkdir("/", "work", &dm).unwrap();
    storage.mkdir("/", "personal", &dm).unwrap();
    storage
        .put_at_path(
            "/",
            "x_key".to_string(),
            "root_value",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work",
            "api_key".to_string(),
            "work_api",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work",
            "secret".to_string(),
            "work_secret",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/personal",
            "password".to_string(),
            "personal_pw",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Pattern "x.*" should match:
    // - "x_key" in root (path is "x_key")
    // But NOT "api_key" in /work (path is "work/api_key", doesn't match "x.*")
    let results: Vec<_> = storage
        .get_at_path("/", "x.*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "x_key");

    // Pattern "work.*" should match:
    // - "work/api_key" (matches "work.*")
    // - "work/secret" (matches "work.*")
    let results: Vec<_> = storage
        .get_at_path("/", "work.*", true, &dm)
        .unwrap()
        .collect();
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
        .get_at_path("/", "work/api.*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/work");
    assert_eq!(results[0].1, "api_key");

    // Search should work the same way
    let keys: Vec<_> = storage
        .search_at_path("/", "work.*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|(p, k)| p == "/work" && *k == "api_key"));
    assert!(keys.iter().any(|(p, k)| p == "/work" && *k == "secret"));
}

#[test]
fn test_deep_nesting_operations() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Create deeply nested folder structure (5 levels)
    storage.mkdir("/", "level1", &dm).unwrap();
    storage.mkdir("/level1", "level2", &dm).unwrap();
    storage.mkdir("/level1/level2", "level3", &dm).unwrap();
    storage
        .mkdir("/level1/level2/level3", "level4", &dm)
        .unwrap();
    storage
        .mkdir("/level1/level2/level3/level4", "level5", &dm)
        .unwrap();

    // Add keys at different levels
    storage
        .put_at_path(
            "/",
            "root_key".to_string(),
            "root_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/level1",
            "l1_key".to_string(),
            "l1_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/level1/level2",
            "l2_key".to_string(),
            "l2_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/level1/level2/level3",
            "l3_key".to_string(),
            "l3_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/level1/level2/level3/level4",
            "l4_key".to_string(),
            "l4_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/level1/level2/level3/level4/level5",
            "l5_key".to_string(),
            "l5_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Test get from different levels
    let results: Vec<_> = storage
        .get_at_path("/", "root_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/");
    assert_eq!(results[0].1, "root_key");

    let results: Vec<_> = storage
        .get_at_path("/level1/level2/level3", "l3_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/level1/level2/level3");
    assert_eq!(results[0].1, "l3_key");

    let results: Vec<_> = storage
        .get_at_path("/level1/level2/level3/level4/level5", "l5_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "/level1/level2/level3/level4/level5");
    assert_eq!(results[0].1, "l5_key");

    // Test recursive search from root
    let all_keys: Vec<_> = storage
        .search_at_path("/", ".*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(all_keys.len(), 6);

    // Test recursive search from nested folder
    let nested_keys: Vec<_> = storage
        .search_at_path("/level1/level2", ".*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(nested_keys.len(), 4); // l2_key, l3_key, l4_key, l5_key
}

#[test]
fn test_nested_folder_regex_matching() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Create nested structure with multiple branches
    storage.mkdir("/", "work", &dm).unwrap();
    storage.mkdir("/work", "projects", &dm).unwrap();
    storage.mkdir("/work", "configs", &dm).unwrap();
    storage.mkdir("/work/projects", "client_a", &dm).unwrap();
    storage.mkdir("/work/projects", "client_b", &dm).unwrap();

    // Add keys with patterns
    storage
        .put_at_path(
            "/work/projects/client_a",
            "api_key".to_string(),
            "key_a",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/projects/client_a",
            "api_secret".to_string(),
            "secret_a",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/projects/client_b",
            "api_key".to_string(),
            "key_b",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/configs",
            "database".to_string(),
            "db_config",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Pattern "work/projects/client_a/.*" should match only client_a keys
    let results: Vec<_> = storage
        .get_at_path("/", "work/projects/client_a/.*", true, &dm)
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
        .get_at_path("/", "work/projects/.*/api_key", true, &dm)
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
        .get_at_path("/", "work/.*/database", true, &dm)
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
    let dm = test_domain_manager();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create nested folder
    storage.mkdir("/", "work", &dm).unwrap();
    storage.mkdir("/work", "projects", &dm).unwrap();

    // Add multiple versions of a nested key
    storage
        .put_at_path(
            "/work/projects",
            "secret".to_string(),
            "v1",
            timestamp,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/projects",
            "secret".to_string(),
            "v2",
            timestamp.add(1),
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/projects",
            "secret".to_string(),
            "v3",
            timestamp.add(2),
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Get history from nested folder
    let history: Vec<_> = storage
        .history_at_path("/work/projects", "secret", &dm)
        .unwrap()
        .collect();
    assert_eq!(history.len(), 3);
    assert_eq!(
        history[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v1"
    );
    assert_eq!(
        history[1]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v2"
    );
    assert_eq!(
        history[2]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v3"
    );

    // Verify timestamps are in order
    assert!(history[0].timestamp + 1 == history[1].timestamp);
    assert!(history[1].timestamp + 1 == history[2].timestamp);
}

#[test]
fn test_nested_folder_delete() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Create nested structure with keys
    storage.mkdir("/", "work", &dm).unwrap();
    storage.mkdir("/work", "projects", &dm).unwrap();
    storage
        .put_at_path(
            "/work/projects",
            "secret1".to_string(),
            "val1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/projects",
            "secret2".to_string(),
            "val2",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Delete key from nested folder
    assert!(storage.delete_at_path("/work/projects", "secret1", &dm));

    // Verify only secret1 is deleted
    let results: Vec<_> = storage
        .get_at_path("/work/projects", "secret1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 0);

    let results: Vec<_> = storage
        .get_at_path("/work/projects", "secret2", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);

    // Try to delete non-existent key
    assert!(!storage.delete_at_path("/work/projects", "secret1", &dm));
    assert!(!storage.delete_at_path("/work/projects", "nonexistent", &dm));
}

#[test]
fn test_nested_folder_serialization() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Create complex nested structure
    storage.mkdir("/", "org", &dm).unwrap();
    storage.mkdir("/org", "dept", &dm).unwrap();
    storage.mkdir("/org/dept", "team", &dm).unwrap();
    storage
        .put_at_path(
            "/org",
            "org_key".to_string(),
            "org_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/org/dept",
            "dept_key".to_string(),
            "dept_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/org/dept/team",
            "team_key".to_string(),
            "team_val",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Serialize and deserialize
    let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
    let mut deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

    // Verify structure is preserved
    assert!(deserialized.get_folder("/org").is_some());
    assert!(deserialized.get_folder("/org/dept").is_some());
    assert!(deserialized.get_folder("/org/dept/team").is_some());

    // Verify keys are preserved
    let results: Vec<_> = deserialized
        .get_at_path("/org", "org_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "org_val"
    );

    let results: Vec<_> = deserialized
        .get_at_path("/org/dept/team", "team_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "team_val"
    );
}

#[test]
fn test_multiple_nested_branches() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();

    // Create multiple independent nested branches
    storage.mkdir("/", "work", &dm).unwrap();
    storage.mkdir("/work", "project_a", &dm).unwrap();
    storage.mkdir("/work", "project_b", &dm).unwrap();
    storage.mkdir("/", "personal", &dm).unwrap();
    storage.mkdir("/personal", "finance", &dm).unwrap();
    storage.mkdir("/personal", "health", &dm).unwrap();

    // Add keys to different branches
    storage
        .put_at_path(
            "/work/project_a",
            "api".to_string(),
            "api_a",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/work/project_b",
            "api".to_string(),
            "api_b",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/personal/finance",
            "account".to_string(),
            "acc123",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/personal/health",
            "insurance".to_string(),
            "ins456",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Search all work keys
    let work_keys: Vec<_> = storage
        .search_at_path("/work", ".*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(work_keys.len(), 2);

    // Search all personal keys
    let personal_keys: Vec<_> = storage
        .search_at_path("/personal", ".*", true, &dm)
        .unwrap()
        .collect();
    assert_eq!(personal_keys.len(), 2);

    // Search for specific pattern across all branches
    let api_keys: Vec<_> = storage
        .search_at_path("/", "work/.*/api", true, &dm)
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

#[test]
fn test_move_key_same_folder() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path(
            "/",
            "old_name".to_string(),
            "value",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Move with rename in same folder
    storage
        .move_item("/", "old_name", "/", Some("new_name"), None, &dm)
        .unwrap();

    // Old key should be gone
    let results: Vec<_> = storage
        .get_at_path("/", "old_name", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 0);

    // New key should exist
    let results: Vec<_> = storage
        .get_at_path("/", "new_name", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value"
    );
}

#[test]
fn test_move_key_between_folders() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();
    storage
        .put_at_path(
            "/source",
            "key1".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Move to different folder keeping same name
    storage
        .move_item("/source", "key1", "/dest", None, None, &dm)
        .unwrap();

    // Should be gone from source
    let results: Vec<_> = storage
        .get_at_path("/source", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 0);

    // Should exist in dest
    let results: Vec<_> = storage
        .get_at_path("/dest", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
}

#[test]
fn test_move_key_with_rename_between_folders() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();
    storage
        .put_at_path(
            "/source",
            "old_key".to_string(),
            "value",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Move and rename
    storage
        .move_item("/source", "old_key", "/dest", Some("new_key"), None, &dm)
        .unwrap();

    // Should be gone from source
    let results: Vec<_> = storage
        .get_at_path("/source", "old_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 0);

    // Should exist in dest with new name
    let results: Vec<_> = storage
        .get_at_path("/dest", "new_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value"
    );
}

#[test]
fn test_move_key_preserves_history() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();

    // Add multiple versions
    storage
        .put_at_path(
            "/source",
            "key1".to_string(),
            "v1",
            timestamp,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/source",
            "key1".to_string(),
            "v2",
            timestamp.add(1),
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/source",
            "key1".to_string(),
            "v3",
            timestamp.add(2),
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Move the key
    storage
        .move_item("/source", "key1", "/dest", None, None, &dm)
        .unwrap();

    // Check history is preserved
    let history: Vec<_> = storage
        .history_at_path("/dest", "key1", &dm)
        .unwrap()
        .collect();
    assert_eq!(history.len(), 3);
    assert_eq!(
        history[0]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v1"
    );
    assert_eq!(
        history[1]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v2"
    );
    assert_eq!(
        history[2]
            .encrypted_value()
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "v3"
    );
}

#[test]
fn test_move_key_collision_error() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();
    storage
        .put_at_path(
            "/source",
            "key1".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage
        .put_at_path(
            "/dest",
            "key1".to_string(),
            "existing",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Should fail due to collision
    let result = storage.move_item("/source", "key1", "/dest", None, None, &dm);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already exists"));

    // Source should still have the key (move was not performed)
    let results: Vec<_> = storage
        .get_at_path("/source", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
}

#[test]
fn test_move_key_nonexistent_source() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "dest", &dm).unwrap();

    let result = storage.move_item("/", "nonexistent", "/dest", None, None, &dm);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_move_key_nonexistent_dest_folder() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage
        .put_at_path("/", "key1".to_string(), "value", 0, MASTER_DOMAIN_ID, &dm)
        .unwrap();

    let result = storage.move_item("/", "key1", "/nonexistent", None, None, &dm);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_move_folder_between_parents() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/source", "folder1", &dm).unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();
    storage
        .put_at_path(
            "/source/folder1",
            "key1".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Move folder1 from /source to /dest
    storage
        .move_item("/source", "folder1", "/dest", None, None, &dm)
        .unwrap();

    // Should be gone from source
    assert!(storage.get_folder("/source/folder1").is_none());

    // Should exist in dest with contents
    assert!(storage.get_folder("/dest/folder1").is_some());
    let results: Vec<_> = storage
        .get_at_path("/dest/folder1", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "value1"
    );
}

#[test]
fn test_move_folder_with_rename() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "old_name", &dm).unwrap();
    storage
        .put_at_path(
            "/old_name",
            "key1".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Rename folder
    storage
        .move_item("/", "old_name", "/", Some("new_name"), None, &dm)
        .unwrap();

    // Old should be gone
    assert!(storage.get_folder("/old_name").is_none());

    // New should exist with contents
    assert!(storage.get_folder("/new_name").is_some());
    let results: Vec<_> = storage
        .get_at_path("/new_name", "key1", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
}

#[test]
fn test_move_folder_preserves_nested_structure() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/source", "folder1", &dm).unwrap();
    storage.mkdir("/source/folder1", "subfolder", &dm).unwrap();
    storage
        .put_at_path(
            "/source/folder1/subfolder",
            "deep_key".to_string(),
            "deep_value",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();

    // Move entire folder tree
    storage
        .move_item("/source", "folder1", "/dest", None, None, &dm)
        .unwrap();

    // Verify nested structure preserved
    assert!(storage.get_folder("/dest/folder1").is_some());
    assert!(storage.get_folder("/dest/folder1/subfolder").is_some());
    let results: Vec<_> = storage
        .get_at_path("/dest/folder1/subfolder", "deep_key", false, &dm)
        .unwrap()
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .2
            .decrypt(dm.get_master_cypher())
            .unwrap()
            .as_str(),
        "deep_value"
    );
}

#[test]
fn test_move_folder_collision_error() {
    let mut storage = StorageV5::new();
    let dm = test_domain_manager();
    storage.mkdir("/", "source", &dm).unwrap();
    storage.mkdir("/source", "folder1", &dm).unwrap();
    storage.mkdir("/", "dest", &dm).unwrap();
    storage.mkdir("/dest", "folder1", &dm).unwrap(); // Collision

    // Should fail
    let result = storage.move_item("/source", "folder1", "/dest", None, None, &dm);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already exists"));

    // Source should still have it
    assert!(storage.get_folder("/source/folder1").is_some());
}

#[test]
fn test_encrypted_folder_decrypted_state_not_serialized() {
    // This test verifies that decrypted_folder (in-memory state) is NOT serialized
    // Thanks to #[serde(skip)], unlocked folders return to locked state on load

    use rcypher::*;

    let (_dir, path) = temp_test_file();
    let cypher = Cypher::new(
        EncryptionKey::from_password_with_params(
            CypherVersion::V7WithKdf,
            "test_password",
            &Argon2Params::insecure(),
        )
        .unwrap(),
    );
    let mut dm = EncryptionDomainManager::new(cypher);

    // Create and unlock domain 1 (needed for re-encryption during save)
    dm.unlock_domain(
        1,
        "domain1".to_string(),
        "domain1_password",
        &Argon2Params::insecure(),
    )
    .unwrap();

    // Create storage with an encrypted folder
    let mut storage = StorageV5::new();

    // Create a regular folder with some content
    storage.mkdir("/", "subfolder", &dm).unwrap();
    storage
        .put_at_path(
            "/subfolder",
            "secret1".to_string(),
            "value1",
            0,
            MASTER_DOMAIN_ID,
            &dm,
        )
        .unwrap();

    // Create an encrypted folder with some encrypted_data
    use std::collections::BTreeMap;
    let mut encrypted_folder = FolderItem::new_encrypted_folder(
        "locked_folder".to_string(),
        vec![1, 2, 3, 4, 5], // dummy encrypted bytes
        1,                   // custom domain
    );

    // Create a decrypted folder with content
    let mut decrypted = Folder {
        name: "decrypted_content".to_string(),
        items: BTreeMap::new(),
    };
    decrypted.items.insert(
        "inner_secret".to_string(),
        FolderItem::new_secret(
            "inner_secret".to_string(),
            vec![SecretEntry::new(
                EncryptedValue::encrypt(dm.get_cypher(1).unwrap(), "sensitive_data").unwrap(),
                12345,
            )],
            1,
        ),
    );

    // Simulate unlocking: populate decrypted_folder (test helper only available in test/debug)
    encrypted_folder
        .test_set_decrypted_folder(decrypted)
        .unwrap();

    // Verify folder is unlocked before save
    assert!(
        encrypted_folder.test_has_decrypted_folder(),
        "Folder should be unlocked before serialization"
    );

    // Add to storage
    storage
        .root
        .items
        .insert("locked_folder".to_string(), encrypted_folder);

    // Save storage
    save_storage_v5(&dm, &mut storage, &path).unwrap();

    // Load storage back
    let loaded_storage = load_storage_v5(dm.get_master_cypher(), &path).unwrap();

    // CRITICAL TEST: decrypted_folder should be None after deserialization
    // This verifies #[serde(skip)] works correctly
    let loaded_item = loaded_storage.root.items.get("locked_folder").unwrap();
    assert!(
        !loaded_item.test_has_decrypted_folder(),
        "Folder MUST be locked after deserialization - decrypted_folder should be None"
    );

    // Verify encrypted_data exists (will be different from dummy bytes due to re-encryption)
    assert!(
        loaded_item.test_get_encrypted_data().is_some(),
        "encrypted_data should exist"
    );
    assert!(
        !loaded_item.test_get_encrypted_data().unwrap().is_empty(),
        "encrypted_data should not be empty"
    );

    // Verify encryption_domain is preserved
    assert_eq!(
        loaded_item.encryption_domain(),
        Some(1),
        "encryption_domain should be preserved"
    );

    // Verify the folder can be properly unlocked and contains the expected content
    // (transparent decryption happens when accessing the path with unlocked domain)
    let mut loaded_storage_mut = loaded_storage;
    let unlocked_folder = loaded_storage_mut
        .get_folder_mut("/locked_folder", &dm)
        .unwrap();
    assert!(
        unlocked_folder.items.contains_key("inner_secret"),
        "Decrypted folder should contain the inner secret"
    );
    let inner_secret = unlocked_folder.items.get("inner_secret").unwrap();
    let decrypted_value = inner_secret.get_entries().unwrap()[0]
        .encrypted_value()
        .decrypt(dm.get_cypher(1).unwrap())
        .unwrap();
    assert_eq!(
        decrypted_value.as_str(),
        "sensitive_data",
        "Inner secret value should match"
    );

    // Verify other content is still there
    assert_eq!(
        loaded_storage_mut.root.items.len(),
        2,
        "Should have 2 items"
    );
    assert!(
        loaded_storage_mut.get_folder("/subfolder").is_some(),
        "Regular folder should still exist"
    );
}
