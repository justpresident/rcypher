use crate::cli::utils::{format_full_path, format_timestamp, secure_print};
use crate::{Cypher, EncryptedValue, EncryptionKey, StorageV5, load_storage_v5, save_storage_v5};
use anyhow::Result;
use std::io;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

#[derive(Debug)]
struct UpdateEntry {
    folder_path: String,
    key: String,
    new_value: EncryptedValue,
    new_timestamp: u64,
    old_value: Option<EncryptedValue>,
    old_timestamp: Option<u64>,
}

impl UpdateEntry {
    const fn is_new_key(&self) -> bool {
        self.old_value.is_none()
    }
}

/// Recursively find updates in a folder and its subfolders
fn find_updates_in_folder(
    folder_path: &str,
    main_storage: &StorageV5,
    update_storage: &StorageV5,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    updates: &mut Vec<UpdateEntry>,
) {
    let Some(update_folder) = update_storage.get_folder(folder_path) else {
        return;
    };

    // Check secrets in this folder
    for (key, item) in update_folder.secrets() {
        if let Some(update_entries) = item.get_entries() {
            let update_latest = update_entries.last().expect("entries should not be empty");
            let main_latest = main_storage
                .get_folder(folder_path)
                .and_then(|f| f.get_item(key))
                .and_then(|item| item.get_entries())
                .and_then(|entries| entries.last());

            let should_update = main_latest.is_none_or(|main_entry| {
                // Key exists - decrypt and compare values
                let main_decrypted = main_entry
                    .encrypted_value()
                    .decrypt(main_cypher)
                    .expect("Failed to decrypt main file");
                let update_decrypted = update_latest
                    .encrypted_value()
                    .decrypt(update_cypher)
                    .expect("Failed to decrypt update file");

                // Update if values differ and update is newer or same timestamp
                *main_decrypted != *update_decrypted
                    && update_latest.timestamp >= main_entry.timestamp
            });

            if should_update {
                updates.push(UpdateEntry {
                    folder_path: folder_path.to_string(),
                    key: key.clone(),
                    new_value: update_latest.encrypted_value().clone(),
                    new_timestamp: update_latest.timestamp,
                    old_value: main_latest.map(|e| e.encrypted_value().clone()),
                    old_timestamp: main_latest.map(|e| e.timestamp),
                });
            }
        }
    }

    // Recursively check subfolders
    for (subfolder_name, _) in update_folder.navigable_folders() {
        let subfolder_path = format_full_path(folder_path, subfolder_name, true);
        find_updates_in_folder(
            &subfolder_path,
            main_storage,
            update_storage,
            main_cypher,
            update_cypher,
            updates,
        );
    }
}

/// Find entries that need updating by comparing latest values from both storages
fn find_updates(
    main_storage: &StorageV5,
    update_storage: &StorageV5,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
) -> Vec<UpdateEntry> {
    let mut updates = Vec::new();

    // Start recursive search from root
    find_updates_in_folder(
        "/",
        main_storage,
        update_storage,
        main_cypher,
        update_cypher,
        &mut updates,
    );

    // Sort by folder path then key name for consistent presentation
    updates.sort_by(|a, b| {
        a.folder_path
            .cmp(&b.folder_path)
            .then_with(|| a.key.cmp(&b.key))
    });
    updates
}

/// Format and display a single update entry
fn display_update_entry(
    update: &UpdateEntry,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    insecure_stdout: bool,
) -> Result<()> {
    use crate::cli::utils::format_full_path;
    let full_path = format_full_path(&update.folder_path, &update.key, false);

    // Compact format for summary view
    if update.is_new_key() {
        let new_decrypted = update.new_value.decrypt(update_cypher)?;
        secure_print(
            format!(
                "  [NEW] {}\n    New: {} ({})",
                full_path,
                &*new_decrypted,
                format_timestamp(update.new_timestamp)
            ),
            insecure_stdout,
        )?;
    } else {
        let old_decrypted = update
            .old_value
            .as_ref()
            .expect("old value exists")
            .decrypt(main_cypher)?;
        let new_decrypted = update.new_value.decrypt(update_cypher)?;
        secure_print(
            format!(
                "  [CONFLICT] {}\n    Current: {} ({})\n    Update:  {} ({})",
                full_path,
                &*old_decrypted,
                format_timestamp(update.old_timestamp.expect("old timestamp exists")),
                &*new_decrypted,
                format_timestamp(update.new_timestamp)
            ),
            insecure_stdout,
        )?;
    }

    Ok(())
}

/// Display summary of updates to the user
fn display_update_summary(
    updates: &[UpdateEntry],
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    insecure_stdout: bool,
) -> Result<(usize, usize)> {
    println!(
        "\nFound {} key{} with different values:",
        updates.len(),
        if updates.len() == 1 { "" } else { "s" }
    );

    let mut new_keys = 0;
    let mut conflicts = 0;

    for update in updates {
        display_update_entry(update, main_cypher, update_cypher, insecure_stdout)?;

        if update.is_new_key() {
            new_keys += 1;
        } else {
            conflicts += 1;
        }
    }

    println!(
        "\nSummary: {} new key{}, {} conflict{}",
        new_keys,
        if new_keys == 1 { "" } else { "s" },
        conflicts,
        if conflicts == 1 { "" } else { "s" }
    );

    Ok((new_keys, conflicts))
}

/// Ensure all parent folders exist for a given path, creating them if needed
fn ensure_folder_path(storage: &mut StorageV5, path: &str) -> Result<()> {
    if path == "/" || path.is_empty() {
        return Ok(());
    }

    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let mut current_path = String::from("/");

    for part in parts {
        // Check if folder exists
        let folder_path = format_full_path(&current_path, part, true);

        if storage.get_folder(&folder_path).is_none() {
            // Create the folder
            storage.mkdir(&current_path, part)?;
        }

        current_path = folder_path;
    }

    Ok(())
}

/// Apply all updates at once
fn apply_all_updates(
    updates: Vec<UpdateEntry>,
    main_storage: &mut StorageV5,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    filename: &Path,
) -> Result<()> {
    for update in updates {
        let mut decrypted = update.new_value.decrypt(update_cypher)?;
        let re_encrypted = EncryptedValue::encrypt(main_cypher, &decrypted)?;
        decrypted.zeroize();

        // Ensure folder path exists before putting the key
        ensure_folder_path(main_storage, &update.folder_path)?;

        main_storage.put_at_path(
            &update.folder_path,
            update.key,
            re_encrypted,
            update.new_timestamp,
        );
    }

    save_storage_v5(main_cypher, main_storage, filename)?;
    println!("✓ All updates applied successfully.");
    Ok(())
}

/// Apply updates interactively, prompting for each one
fn apply_updates_interactive(
    updates: Vec<UpdateEntry>,
    main_storage: &mut StorageV5,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    filename: &Path,
    insecure_stdout: bool,
) -> Result<()> {
    let mut applied = 0;
    let mut skipped = 0;

    for update in updates {
        display_update_entry(&update, main_cypher, update_cypher, insecure_stdout)?;

        print!("Apply this update? (y/n/q): ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;

        match response.trim().to_lowercase().as_str() {
            "y" | "yes" => {
                let mut decrypted = update.new_value.decrypt(update_cypher)?;
                let re_encrypted = EncryptedValue::encrypt(main_cypher, &decrypted)?;
                decrypted.zeroize();

                // Ensure folder path exists before putting the key
                ensure_folder_path(main_storage, &update.folder_path)?;

                main_storage.put_at_path(
                    &update.folder_path,
                    update.key,
                    re_encrypted,
                    update.new_timestamp,
                );
                applied += 1;
                println!("✓ Applied");
            }
            "q" | "quit" => {
                println!("Quitting interactive mode.");
                break;
            }
            _ => {
                skipped += 1;
                println!("✗ Skipped");
            }
        }
    }

    if applied > 0 {
        save_storage_v5(main_cypher, main_storage, filename)?;
        println!(
            "\n✓ Applied {} update{}, skipped {}.",
            applied,
            if applied == 1 { "" } else { "s" },
            skipped
        );
    } else {
        println!("\nNo updates applied.");
    }

    Ok(())
}

/// Prompt user for merge mode choice
fn prompt_merge_mode() -> Result<String> {
    print!("\nApply updates? (a)ll at once, (i)nteractive, (c)ancel [a/i/c]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase())
}

/// Main entry point for updating storage with another file
pub fn run_update_with(
    filename: &Path,
    update_file: &Path,
    main_key: EncryptionKey,
    update_key: EncryptionKey,
    insecure_stdout: bool,
) -> Result<()> {
    let main_cypher = Cypher::new(main_key);
    let mut main_storage = load_storage_v5(&main_cypher, filename)?;

    let update_cypher = Cypher::new(update_key);
    let update_storage = load_storage_v5(&update_cypher, update_file)?;

    // Find what needs updating
    let updates = find_updates(&main_storage, &update_storage, &main_cypher, &update_cypher);

    if updates.is_empty() {
        println!("No updates found. Storage files are in sync.");
        return Ok(());
    }

    // Display summary
    display_update_summary(&updates, &main_cypher, &update_cypher, insecure_stdout)?;

    // Prompt for action
    let choice = prompt_merge_mode()?;

    // Execute chosen action
    match choice.as_str() {
        "a" | "all" => {
            apply_all_updates(
                updates,
                &mut main_storage,
                &main_cypher,
                &update_cypher,
                filename,
            )?;
        }
        "i" | "interactive" => {
            apply_updates_interactive(
                updates,
                &mut main_storage,
                &main_cypher,
                &update_cypher,
                filename,
                insecure_stdout,
            )?;
        }
        _ => {
            println!("Cancelled. No changes made.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Argon2Params, CypherVersion, StorageV5};

    fn create_test_cypher() -> Cypher {
        let key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            "test_password",
            &Argon2Params::insecure(),
        )
        .expect("Failed to create key");
        Cypher::new(key)
    }

    #[test]
    fn test_update_entry_is_new_key() {
        let cypher = create_test_cypher();
        let value = EncryptedValue::encrypt(&cypher, "test").unwrap();

        let new_entry = UpdateEntry {
            folder_path: "/".to_string(),
            key: "key1".to_string(),
            new_value: value.clone(),
            new_timestamp: 100,
            old_value: None,
            old_timestamp: None,
        };

        assert!(new_entry.is_new_key());

        let existing_entry = UpdateEntry {
            folder_path: "/".to_string(),
            key: "key2".to_string(),
            new_value: value.clone(),
            new_timestamp: 100,
            old_value: Some(value),
            old_timestamp: Some(50),
        };

        assert!(!existing_entry.is_new_key());
    }

    #[test]
    fn test_find_updates_new_keys() {
        let cypher = create_test_cypher();
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Main has key1, update has key1 and key2
        main_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "value1").unwrap(),
            0,
        );
        update_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "value1").unwrap(),
            0,
        );
        update_storage.put_at_path(
            "/",
            "key2".to_string(),
            EncryptedValue::encrypt(&cypher, "value2").unwrap(),
            0,
        );

        let updates = find_updates(&main_storage, &update_storage, &cypher, &cypher);

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].key, "key2");
        assert!(updates[0].is_new_key());
    }

    #[test]
    fn test_find_updates_conflicts() {
        let cypher = create_test_cypher();
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Both have key1 but with different values
        main_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "old_value").unwrap(),
            100,
        );
        update_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "new_value").unwrap(),
            200,
        );

        let updates = find_updates(&main_storage, &update_storage, &cypher, &cypher);

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].key, "key1");
        assert!(!updates[0].is_new_key());
    }

    #[test]
    fn test_find_updates_no_changes() {
        let cypher = create_test_cypher();
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Both have same key with same value
        main_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "value1").unwrap(),
            0,
        );
        update_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "value1").unwrap(),
            0,
        );

        let updates = find_updates(&main_storage, &update_storage, &cypher, &cypher);

        assert_eq!(updates.len(), 0);
    }

    #[test]
    fn test_find_updates_ignores_older_timestamp() {
        let cypher = create_test_cypher();
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Update has older value
        update_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "old_value").unwrap(),
            100,
        );

        main_storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::encrypt(&cypher, "new_value").unwrap(),
            200,
        );

        let updates = find_updates(&main_storage, &update_storage, &cypher, &cypher);

        // Should not include update since main is newer
        assert_eq!(updates.len(), 0);
    }
}
