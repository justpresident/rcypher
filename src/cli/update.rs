use crate::{
    Cypher, EncryptedValue, EncryptionKey, Storage, format_timestamp, load_storage, save_storage,
    secure_print,
};
use anyhow::Result;
use std::io;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

#[derive(Debug)]
struct UpdateEntry {
    key: String,
    new_value: EncryptedValue,
    new_timestamp: u64,
    old_value: Option<EncryptedValue>,
    old_timestamp: Option<u64>,
}

impl UpdateEntry {
    fn is_new_key(&self) -> bool {
        self.old_value.is_none()
    }
}

/// Find entries that need updating by comparing latest values from both storages
fn find_updates(
    main_storage: &Storage,
    update_storage: &Storage,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
) -> Vec<UpdateEntry> {
    let mut updates = Vec::new();

    for (key, update_entries) in &update_storage.data {
        let update_latest = update_entries.last().expect("entries should not be empty");
        let main_latest = main_storage
            .data
            .get(key)
            .and_then(|entries| entries.last());

        let should_update = if let Some(main_entry) = main_latest {
            // Key exists - decrypt and compare values
            let main_decrypted = main_entry
                .value
                .decrypt(main_cypher)
                .expect("Failed to decrypt main file");
            let update_decrypted = update_latest
                .value
                .decrypt(update_cypher)
                .expect("Failed to decrypt update file");

            // Update if values differ and update is newer or same timestamp
            *main_decrypted != *update_decrypted && update_latest.timestamp >= main_entry.timestamp
        } else {
            // New key - always include
            true
        };

        if should_update {
            updates.push(UpdateEntry {
                key: key.clone(),
                new_value: update_latest.value.clone(),
                new_timestamp: update_latest.timestamp,
                old_value: main_latest.map(|e| e.value.clone()),
                old_timestamp: main_latest.map(|e| e.timestamp),
            });
        }
    }

    // Sort by key name for consistent presentation
    updates.sort_by(|a, b| a.key.cmp(&b.key));
    updates
}

/// Format and display a single update entry
fn display_update_entry(
    update: &UpdateEntry,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    insecure_stdout: bool,
) -> Result<()> {
    // Compact format for summary view
    if update.is_new_key() {
        let new_decrypted = update.new_value.decrypt(update_cypher)?;
        secure_print(
            format!(
                "  [NEW] {}\n    New: {} ({})",
                update.key,
                &*new_decrypted,
                format_timestamp(update.new_timestamp)
            ),
            insecure_stdout,
        )?;
    } else {
        let old_decrypted = update.old_value.as_ref().unwrap().decrypt(main_cypher)?;
        let new_decrypted = update.new_value.decrypt(update_cypher)?;
        secure_print(
            format!(
                "  [CONFLICT] {}\n    Current: {} ({})\n    Update:  {} ({})",
                update.key,
                &*old_decrypted,
                format_timestamp(update.old_timestamp.unwrap()),
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

/// Apply all updates at once
fn apply_all_updates(
    updates: Vec<UpdateEntry>,
    main_storage: &mut Storage,
    main_cypher: &Cypher,
    update_cypher: &Cypher,
    filename: &Path,
) -> Result<()> {
    for update in updates {
        let mut decrypted = update.new_value.decrypt(update_cypher)?;
        let re_encrypted = EncryptedValue::encrypt(main_cypher, &decrypted)?;
        decrypted.zeroize();
        main_storage.put(update.key, re_encrypted);
    }

    save_storage(main_cypher, main_storage, filename)?;
    println!("✓ All updates applied successfully.");
    Ok(())
}

/// Apply updates interactively, prompting for each one
fn apply_updates_interactive(
    updates: Vec<UpdateEntry>,
    main_storage: &mut Storage,
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
                main_storage.put(update.key, re_encrypted);
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
        save_storage(main_cypher, main_storage, filename)?;
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
    let mut main_storage = load_storage(&main_cypher, filename)?;

    let update_cypher = Cypher::new(update_key);
    let update_storage = load_storage(&update_cypher, update_file)?;

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
