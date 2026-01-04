use crate::cli::utils::{format_full_path, format_timestamp, secure_print};
use crate::{
    Cypher, EncryptedValue, EncryptionDomainManager, EncryptionKey, StorageV5, load_storage_v5,
    save_storage_v5,
};
use anyhow::Result;
use std::io;
use std::io::Write;
use std::path::Path;

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
    main_domain_manager: &EncryptionDomainManager,
    update_domain_manager: &EncryptionDomainManager,
    updates: &mut Vec<UpdateEntry>,
    skipped_count: &mut usize,
) {
    let Some(update_folder) = update_storage.get_folder(folder_path) else {
        return;
    };

    let main_cypher = main_domain_manager.get_master_cypher();
    let update_cypher = update_domain_manager.get_master_cypher();

    // Check secrets in this folder
    for (key, item) in update_folder.secrets() {
        // Skip items in non-default encryption domains
        if let Some(domain) = item.encryption_domain()
            && domain != crate::MASTER_DOMAIN_ID
        {
            *skipped_count += 1;
            continue;
        }

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

    // Recursively check subfolders (only navigable = unlocked or regular folders)
    for (subfolder_name, item) in update_folder.navigable_folders() {
        // Skip encrypted folders in non-default domains
        if let Some(domain) = item.encryption_domain()
            && domain != crate::MASTER_DOMAIN_ID
        {
            *skipped_count += 1;
            continue;
        }

        let subfolder_path = format_full_path(folder_path, subfolder_name, true);
        find_updates_in_folder(
            &subfolder_path,
            main_storage,
            update_storage,
            main_domain_manager,
            update_domain_manager,
            updates,
            skipped_count,
        );
    }
}

/// Find entries that need updating by comparing latest values from both storages
fn find_updates(
    main_storage: &StorageV5,
    update_storage: &StorageV5,
    main_domain_manager: &EncryptionDomainManager,
    update_domain_manager: &EncryptionDomainManager,
) -> (Vec<UpdateEntry>, usize) {
    let mut updates = Vec::new();
    let mut skipped_count = 0;

    // Start recursive search from root
    find_updates_in_folder(
        "/",
        main_storage,
        update_storage,
        main_domain_manager,
        update_domain_manager,
        &mut updates,
        &mut skipped_count,
    );

    // Sort by folder path then key name for consistent presentation
    updates.sort_by(|a, b| {
        a.folder_path
            .cmp(&b.folder_path)
            .then_with(|| a.key.cmp(&b.key))
    });
    (updates, skipped_count)
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
    main_domain_manager: &EncryptionDomainManager,
    update_domain_manager: &EncryptionDomainManager,
    insecure_stdout: bool,
) -> Result<(usize, usize)> {
    let main_cypher = main_domain_manager.get_master_cypher();
    let update_cypher = update_domain_manager.get_master_cypher();

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
fn ensure_folder_path(
    storage: &mut StorageV5,
    path: &str,
    domain_manager: &EncryptionDomainManager,
) -> Result<()> {
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
            storage.mkdir(&current_path, part, domain_manager)?;
        }

        current_path = folder_path;
    }

    Ok(())
}

/// Apply all updates at once
fn apply_all_updates(
    updates: Vec<UpdateEntry>,
    main_storage: &mut StorageV5,
    main_domain_manager: &EncryptionDomainManager,
    update_domain_manager: &EncryptionDomainManager,
    filename: &Path,
) -> Result<()> {
    let update_cypher = update_domain_manager.get_master_cypher();

    for update in updates {
        let decrypted = update.new_value.decrypt(update_cypher)?;

        // Ensure folder path exists before putting the key
        ensure_folder_path(main_storage, &update.folder_path, main_domain_manager)?;

        main_storage.put_at_path(
            &update.folder_path,
            update.key,
            &decrypted,
            update.new_timestamp,
            crate::MASTER_DOMAIN_ID,
            main_domain_manager,
        )?;
    }

    save_storage_v5(main_domain_manager, main_storage, filename)?;
    println!("✓ All updates applied successfully.");
    Ok(())
}

/// Apply updates interactively, prompting for each one
fn apply_updates_interactive(
    updates: Vec<UpdateEntry>,
    main_storage: &mut StorageV5,
    main_domain_manager: &EncryptionDomainManager,
    update_domain_manager: &EncryptionDomainManager,
    filename: &Path,
    insecure_stdout: bool,
) -> Result<()> {
    let main_cypher = main_domain_manager.get_master_cypher();
    let update_cypher = update_domain_manager.get_master_cypher();

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
                // Ensure folder path exists before putting the key
                ensure_folder_path(main_storage, &update.folder_path, main_domain_manager)?;

                let decrypted = update.new_value.decrypt(update_cypher)?;

                main_storage.put_at_path(
                    &update.folder_path,
                    update.key,
                    &decrypted,
                    update.new_timestamp,
                    crate::MASTER_DOMAIN_ID,
                    main_domain_manager,
                )?;
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
        save_storage_v5(main_domain_manager, main_storage, filename)?;
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

    // Create domain managers with only master domain unlocked
    // We only sync secrets in the default domain (0) for safety and simplicity
    let main_domain_manager = EncryptionDomainManager::new(main_cypher);
    let update_domain_manager = EncryptionDomainManager::new(update_cypher);

    // Find what needs updating (only master domain items)
    let (updates, skipped_count) = find_updates(
        &main_storage,
        &update_storage,
        &main_domain_manager,
        &update_domain_manager,
    );

    if skipped_count > 0 {
        println!("⚠️  Skipped {skipped_count} items in non-default encryption domains.");
        println!(
            "   These items are likely more sensitive and should be synced manually if needed."
        );
        println!();
    }

    if updates.is_empty() {
        println!("No updates found. Storage files are in sync.");
        return Ok(());
    }

    // Display summary
    display_update_summary(
        &updates,
        &main_domain_manager,
        &update_domain_manager,
        insecure_stdout,
    )?;

    // Prompt for action
    let choice = prompt_merge_mode()?;

    // Execute chosen action
    match choice.as_str() {
        "a" | "all" => {
            apply_all_updates(
                updates,
                &mut main_storage,
                &main_domain_manager,
                &update_domain_manager,
                filename,
            )?;
        }
        "i" | "interactive" => {
            apply_updates_interactive(
                updates,
                &mut main_storage,
                &main_domain_manager,
                &update_domain_manager,
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
        let domain_manager = EncryptionDomainManager::new(cypher);
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Main has key1, update has key1 and key2
        main_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "value1",
                0,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();
        update_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "value1",
                0,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();
        update_storage
            .put_at_path(
                "/",
                "key2".to_string(),
                "value2",
                0,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();

        let (updates, skipped_count) = find_updates(
            &main_storage,
            &update_storage,
            &domain_manager,
            &domain_manager,
        );

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].key, "key2");
        assert!(updates[0].is_new_key());
        assert_eq!(skipped_count, 0);
    }

    #[test]
    fn test_find_updates_conflicts() {
        let cypher = create_test_cypher();
        let domain_manager = EncryptionDomainManager::new(cypher);
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Both have key1 but with different values
        main_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "old_value",
                100,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();
        update_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "new_value",
                200,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();

        let (updates, skipped_count) = find_updates(
            &main_storage,
            &update_storage,
            &domain_manager,
            &domain_manager,
        );

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].key, "key1");
        assert!(!updates[0].is_new_key());
        assert_eq!(skipped_count, 0);
    }

    #[test]
    fn test_find_updates_no_changes() {
        let cypher = create_test_cypher();
        let domain_manager = EncryptionDomainManager::new(cypher);
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Both have same key with same value
        main_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "value1",
                0,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();
        update_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "value1",
                0,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();

        let (updates, skipped_count) = find_updates(
            &main_storage,
            &update_storage,
            &domain_manager,
            &domain_manager,
        );

        assert_eq!(updates.len(), 0);
        assert_eq!(skipped_count, 0);
    }

    #[test]
    fn test_find_updates_ignores_older_timestamp() {
        let cypher = create_test_cypher();
        let domain_manager = EncryptionDomainManager::new(cypher);
        let mut main_storage = StorageV5::new();
        let mut update_storage = StorageV5::new();

        // Update has older value
        update_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "old_value",
                100,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();

        main_storage
            .put_at_path(
                "/",
                "key1".to_string(),
                "new_value",
                200,
                crate::MASTER_DOMAIN_ID,
                &domain_manager,
            )
            .unwrap();

        let (updates, skipped_count) = find_updates(
            &main_storage,
            &update_storage,
            &domain_manager,
            &domain_manager,
        );

        // Should not include update since main is newer
        assert_eq!(updates.len(), 0);
        assert_eq!(skipped_count, 0);
    }
}
