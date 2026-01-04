use anyhow::anyhow;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use zeroize::Zeroizing;

use anyhow::{Result, bail};
use bincode::{Decode, Encode, config};
use regex::Regex;

use super::value::EncryptedValue;
use crate::EncryptionDomainManager;
use crate::path_utils::{format_full_path, relative_path_from};
use crate::version::StoreVersion;
use crate::{MASTER_DOMAIN_ID, MASTER_DOMAIN_NAME};

// ============================================================================
// Storage V5 - Hierarchical folders with encryption domains
// ============================================================================

/// Root storage container for V5
#[derive(Debug, Clone, Encode, Decode)]
pub struct StorageV5 {
    /// Root folder containing all secrets and subfolders
    pub root: Folder,
    /// Encryption domain metadata (`domain_id` -> `domain_name`)
    /// Domain 0 is always "master" (uses storage password)
    pub encryption_domains: std::collections::HashMap<u32, String>,
}

impl StorageV5 {
    /// Create a new empty V5 storage
    pub fn new() -> Self {
        let mut encryption_domains = std::collections::HashMap::new();
        encryption_domains.insert(MASTER_DOMAIN_ID, MASTER_DOMAIN_NAME.to_string());

        Self {
            root: Folder::new_root(),
            encryption_domains,
        }
    }

    /// Get a folder by path (read-only, no decryption)
    ///
    /// Returns None if path doesn't exist or contains locked encrypted folders
    /// Use `get_folder_mut` if you need to decrypt folders during traversal
    pub fn get_folder(&self, path: &str) -> Option<&Folder> {
        if path == "/" || path.is_empty() {
            return Some(&self.root);
        }

        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current = &self.root;

        for part in parts {
            let item = current.items.get(part)?;
            current = item.get_folder()?; // Returns None if locked
        }

        Some(current)
    }

    /// Get a mutable folder by path with transparent decryption
    ///
    /// Automatically decrypts `EncryptedFolders` during traversal if domain is unlocked
    ///
    /// # Errors
    /// * If path doesn't exist
    /// * If an encrypted folder's domain is locked
    /// * If decryption fails
    pub fn get_folder_mut(
        &mut self,
        path: &str,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<&mut Folder> {
        if path == "/" || path.is_empty() {
            return Ok(&mut self.root);
        }

        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current = &mut self.root;

        for part in parts {
            // Get the item
            let item = current
                .items
                .get_mut(part)
                .ok_or_else(|| anyhow::anyhow!("Folder '{part}' not found in path '{path}'"))?;

            // Decrypt if it's an encrypted folder (transparent, idempotent)
            if item.is_encrypted_folder() {
                item.decrypt_folder(domain_manager)?;
            }

            // Navigate into the folder
            current = item
                .get_folder_mut()
                .ok_or_else(|| anyhow::anyhow!("'{part}' is not a folder"))?;
        }

        Ok(current)
    }

    /// Get the encryption domain for a given path by traversing from root
    /// Returns the encryption domain of the deepest encrypted folder in the path,
    /// or `MASTER_DOMAIN_ID` if no encrypted folders are found
    pub fn get_encryption_domain_for_path(&self, path: &str) -> u32 {
        if path == "/" || path.is_empty() {
            return crate::MASTER_DOMAIN_ID;
        }

        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current = &self.root;
        let mut domain = crate::MASTER_DOMAIN_ID;

        for part in parts {
            if let Some(item) = current.items.get(part) {
                // Update domain if this folder has an encryption domain
                if let Some(item_domain) = item.encryption_domain() {
                    domain = item_domain;
                }

                // Try to get the folder for next iteration
                if let Some(folder) = item.get_folder() {
                    current = folder;
                } else {
                    // Can't traverse further, return current domain
                    break;
                }
            } else {
                // Path doesn't exist, return current domain
                break;
            }
        }

        domain
    }

    /// Recursively re-encrypt all unlocked encrypted folders before saving
    /// This ensures that any modifications made to encrypted folders are persisted
    pub fn prepare_for_save(&mut self, domain_manager: &EncryptionDomainManager) -> Result<()> {
        Self::reencrypt_folders_recursive(&mut self.root, domain_manager)
    }

    /// Helper function to recursively re-encrypt encrypted folders
    fn reencrypt_folders_recursive(
        folder: &mut Folder,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        for item in folder.items.values_mut() {
            match item {
                FolderItem::EncryptedFolder {
                    decrypted_folder, ..
                } => {
                    // If the folder is unlocked, recursively process its contents first
                    if let Some(decrypted) = decrypted_folder {
                        Self::reencrypt_folders_recursive(decrypted, domain_manager)?;
                    }
                    // Then re-encrypt this folder
                    item.reencrypt_folder(domain_manager)?;
                }
                FolderItem::Folder {
                    folder: subfolder, ..
                } => {
                    // Recursively process regular subfolders
                    Self::reencrypt_folders_recursive(subfolder, domain_manager)?;
                }
                FolderItem::Secret { .. } => {
                    // Secrets don't need special handling
                }
            }
        }
        Ok(())
    }

    /// Create a new folder at the given path
    pub fn mkdir(
        &mut self,
        path: &str,
        folder_name: &str,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        let parent = self.get_folder_mut(path, domain_manager)?;

        if parent.items.contains_key(folder_name) {
            bail!("Item '{folder_name}' already exists");
        }

        let new_folder = Folder::new(folder_name.to_string());
        parent.items.insert(
            folder_name.to_string(),
            FolderItem::new_folder(folder_name.to_string(), new_folder),
        );

        Ok(())
    }

    /// Store a secret value at a specific path
    pub fn put_at_path(
        &mut self,
        path: &str,
        key: String,
        value: &str,
        timestamp: u64,
        encryption_domain: u32,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        let folder = self.get_folder_mut(path, domain_manager)?;
        let encrypted_value = EncryptedValue::from_ciphertext(
            domain_manager
                .get_cypher(encryption_domain)
                .ok_or_else(|| anyhow!("target domain is locked"))?
                .encrypt(value.as_bytes())?,
        );
        let entry = SecretEntry::new(encrypted_value, timestamp);

        folder
            .items
            .entry(key.clone())
            .and_modify(|item| {
                if let Some(entries) = item.get_entries_mut() {
                    entries.push(entry.clone());
                }
            })
            .or_insert_with(|| FolderItem::new_secret(key, vec![entry], encryption_domain));

        Ok(())
    }

    /// Returns an iterator over key-value pairs matching pattern at a specific path.
    /// If recursive is true, searches through all subfolders.
    /// Returns (`full_path`, key, value) tuples where `full_path` is like "/work/personal"
    pub fn get_at_path<'a>(
        &'a mut self,
        path: &str,
        pattern: &str,
        recursive: bool,
        domain_manager: &'a EncryptionDomainManager,
    ) -> Result<impl Iterator<Item = (String, &'a str, &'a EncryptedValue)> + 'a> {
        let re = Regex::new(&format!("^{pattern}$"))?;
        let folder = self.get_folder_mut(path, domain_manager)?;

        // Decrypt the entire tree upfront if recursive (avoids borrow checker issues during iteration)
        if recursive {
            Self::decrypt_tree_recursive(folder, domain_manager);
        }

        let normalized_path = if path == "/" || path.is_empty() {
            String::from("/")
        } else {
            path.to_string()
        };

        Ok(RecursiveSecretIterator::new(
            folder,
            re,
            recursive,
            normalized_path,
        ))
    }

    /// Returns an iterator over all historical values for a given key at a specific path.
    /// Returns None for folders (regular or encrypted).
    pub fn history_at_path(
        &mut self,
        path: &str,
        key: &str,
        domain_manager: &EncryptionDomainManager,
    ) -> Option<impl Iterator<Item = &SecretEntry> + '_> {
        self.get_folder_mut(path, domain_manager)
            .ok()
            .and_then(|folder| folder.get_item(key))
            .and_then(|item| item.get_entries())
            .map(|entries| entries.iter())
    }

    /// Delete an item (secret, folder, or encrypted folder) from a specific path
    pub fn delete_at_path(
        &mut self,
        path: &str,
        key: &str,
        domain_manager: &EncryptionDomainManager,
    ) -> bool {
        self.get_folder_mut(path, domain_manager)
            .ok()
            .and_then(|folder| folder.items.remove(key))
            .is_some()
    }

    /// Move an item (secret, folder, or encrypted folder) from one location to another
    /// Works like shell `mv` - handles both files and directories uniformly
    ///
    /// # Arguments
    /// * `source_folder` - Path to folder containing the item
    /// * `item_name` - Name of the item to move
    /// * `dest_folder` - Destination folder path
    /// * `dest_name` - Optional new name (if None, keeps same name)
    /// * `target_domain_id` - If Some, re-encrypt item to this domain
    /// * `domain_manager` - Domain manager for transparent decryption and re-encryption
    pub fn move_item(
        &mut self,
        source_folder: &str,
        item_name: &str,
        dest_folder: &str,
        dest_name: Option<&str>,
        target_domain_id: Option<u32>,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        let final_name = dest_name.unwrap_or(item_name);

        // Check destination folder exists and no collision (must do before removing from source)
        {
            let dest = self.get_folder_mut(dest_folder, domain_manager)?;

            if dest.items.contains_key(final_name) {
                bail!("Item '{final_name}' already exists at destination '{dest_folder}'");
            }
        }

        // Remove from source
        let mut item = {
            let source = self.get_folder_mut(source_folder, domain_manager)?;
            source.items.remove(item_name).ok_or_else(|| {
                anyhow::anyhow!("Item '{item_name}' not found in '{source_folder}'")
            })?
        };

        // Update the item's name if renaming
        if final_name != item_name {
            match &mut item {
                FolderItem::Secret { name, .. }
                | FolderItem::Folder { name, .. }
                | FolderItem::EncryptedFolder { name, .. } => {
                    *name = final_name.to_string();
                }
            }
        }

        // Re-encrypt to target domain if requested
        if let Some(domain_id) = target_domain_id {
            Self::reencrypt_item(&mut item, domain_id, domain_manager)?;
        }

        // Insert into dest
        let dest = self.get_folder_mut(dest_folder, domain_manager)?;
        dest.items.insert(final_name.to_string(), item);

        Ok(())
    }

    /// Re-encrypt an item from its current domain to a target domain
    ///
    /// # Arguments
    /// * `item` - The item to re-encrypt (Secret, Folder, or `EncryptedFolder`)
    /// * `target_domain_id` - The domain ID to re-encrypt to
    /// * `domain_manager` - Manager containing unlocked domain cyphers
    ///
    /// # Errors
    /// * If the source domain (current item's domain) is not unlocked
    /// * If the target domain is not unlocked
    /// * If encryption/decryption fails
    fn reencrypt_item(
        item: &mut FolderItem,
        target_domain_id: u32,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        use zeroize::Zeroize;

        match item {
            FolderItem::Secret {
                entries,
                encryption_domain: source_domain_id,
                ..
            } => {
                // Verify target domain is unlocked
                let target_cypher =
                    domain_manager.get_cypher(target_domain_id).ok_or_else(|| {
                        anyhow::anyhow!("Target domain {target_domain_id} is not unlocked")
                    })?;

                // Get source cypher for decryption
                let source_cypher =
                    domain_manager
                        .get_cypher(*source_domain_id)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Source domain {source_domain_id} is not unlocked")
                        })?;

                // Re-encrypt all entries
                for entry in entries {
                    let mut plaintext = source_cypher.decrypt(entry.value.as_bytes())?;
                    let ciphertext = target_cypher.encrypt(&plaintext)?;
                    plaintext.zeroize(); // Clear decrypted content from memory
                    entry.value = EncryptedValue::from_ciphertext(ciphertext);
                }

                // Update domain
                *source_domain_id = target_domain_id;
                Ok(())
            }
            FolderItem::Folder { .. } | FolderItem::EncryptedFolder { .. } => {
                // Delegate to encrypt_folder for both folder types
                item.encrypt_folder(target_domain_id, domain_manager)
            }
        }
    }

    /// Lock an item to a specific encryption domain (re-encrypts the item)
    ///
    /// # Arguments
    /// * `item_path` - Full path to the item (e.g., "/`work/api_key`" or "/personal/passwords")
    /// * `target_domain_id` - The domain ID to lock the item to
    /// * `domain_manager` - Manager containing unlocked domain cyphers
    ///
    /// # Errors
    /// * If the item doesn't exist
    /// * If the target domain is not unlocked
    /// * If the source domain (for re-encryption) is not unlocked
    /// * If encryption/decryption fails
    pub fn lock_item(
        &mut self,
        item_path: &str,
        target_domain_id: u32,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        // Parse the path using path_utils (from root)
        let (folder_path, item_name) = crate::parse_key_path("/", item_path);

        // Get the folder containing the item (with transparent decryption)
        let folder = self.get_folder_mut(&folder_path, domain_manager)?;

        // Get the item
        let item = folder
            .items
            .get_mut(item_name)
            .ok_or_else(|| anyhow::anyhow!("Item '{item_name}' not found in '{folder_path}'"))?;

        // Re-encrypt the item
        Self::reencrypt_item(item, target_domain_id, domain_manager)?;

        Ok(())
    }

    /// Returns an iterator over all keys matching pattern at a specific path.
    /// If recursive is true, searches through all subfolders.
    /// Returns (`folder_path`, key) tuples where `folder_path` is like "/work/personal"
    pub fn search_at_path<'a>(
        &'a mut self,
        path: &str,
        pattern: &str,
        recursive: bool,
        domain_manager: &'a EncryptionDomainManager,
    ) -> Result<impl Iterator<Item = (String, &'a str)> + 'a> {
        let re = Regex::new(pattern)?;
        let folder = self.get_folder_mut(path, domain_manager)?;

        // Decrypt the entire tree upfront if recursive (avoids borrow checker issues during iteration)
        if recursive {
            Self::decrypt_tree_recursive(folder, domain_manager);
        }

        let normalized_path = if path == "/" || path.is_empty() {
            String::from("/")
        } else {
            path.to_string()
        };

        Ok(RecursiveKeyIterator::new(
            folder,
            re,
            recursive,
            normalized_path,
        ))
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    /// Recursively decrypt all unlocked encrypted folders in the tree
    /// This is called before creating iterators to avoid borrow checker issues
    fn decrypt_tree_recursive(folder: &mut Folder, domain_manager: &EncryptionDomainManager) {
        for item in folder.items.values_mut() {
            match item {
                FolderItem::EncryptedFolder { .. } => {
                    // Try to decrypt (idempotent, fails silently if domain locked)
                    let _ = item.decrypt_folder(domain_manager);

                    // If successfully decrypted, recurse into it
                    if let Some(subfolder) = item.get_folder_mut() {
                        Self::decrypt_tree_recursive(subfolder, domain_manager);
                    }
                }
                FolderItem::Folder { folder, .. } => {
                    // Regular folder - just recurse
                    Self::decrypt_tree_recursive(folder, domain_manager);
                }
                FolderItem::Secret { .. } => {
                    // Secrets don't contain subfolders
                }
            }
        }
    }

    // ========================================================================
    // Encryption Domain Management
    // ========================================================================

    /// Creates a new encryption domain with the given name
    ///
    /// # Arguments
    /// * `name` - Name for the new encryption domain
    ///
    /// # Returns
    /// * The new domain ID
    ///
    /// # Errors
    /// * If a domain with this name already exists
    pub fn create_encryption_domain(&mut self, name: String) -> Result<u32> {
        // Check if domain name already exists
        if self
            .encryption_domains
            .values()
            .any(|existing_name| existing_name == &name)
        {
            bail!("Encryption domain '{name}' already exists");
        }

        // Find next available domain ID (start from 1, skip 0 which is master)
        let domain_id = (1..=u32::MAX)
            .find(|id| !self.encryption_domains.contains_key(id))
            .ok_or_else(|| anyhow::anyhow!("No available domain IDs"))?;

        self.encryption_domains.insert(domain_id, name);
        Ok(domain_id)
    }

    /// Gets the name of an encryption domain
    ///
    /// # Returns
    /// * `Some(&str)` if the domain exists
    /// * `None` if the domain ID is not registered
    pub fn get_domain_name(&self, domain_id: u32) -> Option<&str> {
        self.encryption_domains.get(&domain_id).map(String::as_str)
    }

    /// Gets all encryption domains
    ///
    /// # Returns
    /// * Iterator of (`domain_id`, `domain_name`) pairs
    pub fn encryption_domains_iter(&self) -> impl Iterator<Item = (&u32, &String)> {
        self.encryption_domains.iter()
    }
}

// ============================================================================
// Iterators through Folder structure (tree is pre-decrypted before iteration)
// ============================================================================

type ItemsIterator<'a> = std::collections::btree_map::Iter<'a, String, FolderItem>;

/// Iterator over secrets in a folder and optionally its subfolders
/// Note: Encrypted folders must be decrypted before iteration (done automatically in `get_at_path`)
pub struct RecursiveSecretIterator<'a> {
    // Single stack of (current_path, items_iter) for depth-first traversal
    stack: Vec<(String, ItemsIterator<'a>)>,
    regex: Regex,
    recursive: bool,
    // Search root for computing relative paths in regex matching
    search_root: String,
}

impl<'a> RecursiveSecretIterator<'a> {
    fn new(folder: &'a Folder, regex: Regex, recursive: bool, initial_path: String) -> Self {
        let items_iter = folder.items.iter();

        Self {
            stack: vec![(initial_path.clone(), items_iter)],
            regex,
            recursive,
            search_root: initial_path,
        }
    }
}

impl<'a> Iterator for RecursiveSecretIterator<'a> {
    type Item = (String, &'a str, &'a EncryptedValue);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next item from current folder
            let mut descended = false;
            if let Some((current_path, items_iter)) = self.stack.last_mut() {
                let path = current_path.clone();
                // Compute relative path from search root for regex matching
                let relative_folder = relative_path_from(&self.search_root, &path);

                for (key, item) in items_iter.by_ref() {
                    // Match regex against full relative path (folder + key)
                    let full_path = format_full_path(&relative_folder, key, false);

                    // Check if this is a secret with matching pattern
                    if self.regex.is_match(&full_path)
                        && let Some(value) = item.get_latest_value()
                    {
                        return Some((path, key.as_str(), value));
                    }

                    // If recursive and this is a navigable folder, descend into it
                    // (Tree is already decrypted, so we only traverse navigable folders)
                    if self.recursive
                        && let Some(subfolder) = item.get_folder()
                    {
                        // Use is_folder=false to avoid trailing slash in internal path tracking
                        let new_path = format_full_path(&path, key, false);
                        self.stack.push((new_path, subfolder.items.iter()));
                        descended = true;
                        // Break to process the new folder
                        break;
                    }
                }
            }

            // If we descended into a subfolder, continue to process it
            if descended {
                continue;
            }

            // Current folder exhausted, pop and continue with parent
            if self.stack.len() > 1 {
                self.stack.pop();
                continue;
            }

            // Nothing left to iterate
            if self.stack.is_empty() || self.stack.len() == 1 {
                // Check if the last stack has more items
                if let Some((_, items_iter)) = self.stack.last_mut() {
                    if items_iter.len() == 0 {
                        return None;
                    }
                    continue;
                }
                return None;
            }
        }
    }
}

/// Iterator over keys in a folder and optionally its subfolders
/// Note: Encrypted folders must be decrypted before iteration (done automatically in `search_at_path`)
pub struct RecursiveKeyIterator<'a> {
    // Single stack of (current_path, items_iter) for depth-first traversal
    stack: Vec<(String, ItemsIterator<'a>)>,
    regex: Regex,
    recursive: bool,
    // Search root for computing relative paths in regex matching
    search_root: String,
}

impl<'a> RecursiveKeyIterator<'a> {
    fn new(folder: &'a Folder, regex: Regex, recursive: bool, initial_path: String) -> Self {
        let items_iter = folder.items.iter();

        Self {
            stack: vec![(initial_path.clone(), items_iter)],
            regex,
            recursive,
            search_root: initial_path,
        }
    }
}

impl<'a> Iterator for RecursiveKeyIterator<'a> {
    type Item = (String, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut descended = false;
            // Try to get next key from current folder
            if let Some((current_path, items_iter)) = self.stack.last_mut() {
                let path = current_path.clone();
                // Compute relative path from search root for regex matching
                let relative_folder = relative_path_from(&self.search_root, &path);

                for (key, item) in items_iter.by_ref() {
                    // Match regex against full relative path (folder + key)
                    let full_path = format_full_path(&relative_folder, key, false);

                    // Check if this is a secret (not a folder) with matching pattern
                    if self.regex.is_match(&full_path) && item.is_secret() {
                        return Some((path, key.as_str()));
                    }

                    // If recursive and this is a navigable folder, descend into it
                    // (Tree is already decrypted, so we only traverse navigable folders)
                    if self.recursive
                        && let Some(subfolder) = item.get_folder()
                    {
                        // Use is_folder=false to avoid trailing slash in internal path tracking
                        let new_path = format_full_path(&path, key, false);
                        self.stack.push((new_path, subfolder.items.iter()));
                        descended = true;
                        // Break to process the new folder
                        break;
                    }
                }
            }

            // If we descended into a subfolder, continue to process it
            if descended {
                continue;
            }

            // Current folder exhausted, pop and continue with parent
            if self.stack.len() > 1 {
                self.stack.pop();
                continue;
            }

            // Nothing left to iterate
            if self.stack.is_empty() || self.stack.len() == 1 {
                // Check if the last stack has more items
                if let Some((_, items_iter)) = self.stack.last_mut() {
                    if items_iter.len() == 0 {
                        return None;
                    }
                    continue;
                }
                return None;
            }
        }
    }
}

impl Default for StorageV5 {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FolderItem - Unified enum for secrets and folders
// ============================================================================

/// An item in a folder - can be either a secret or a subfolder
#[derive(Debug, Clone)]
pub enum FolderItem {
    /// Regular secret with history
    Secret {
        name: String,
        entries: Vec<SecretEntry>,
        encryption_domain: u32,
    },

    /// Regular folder that can be navigated
    Folder { name: String, folder: Box<Folder> },

    /// Encrypted folder - visible as encrypted, shows "**LOCKED**" when locked
    EncryptedFolder {
        name: String,
        /// Serialized encrypted folder bytes
        encrypted_data: Vec<u8>,
        /// Which encryption domain key to use
        encryption_domain: u32,
        /// Decrypted folder when unlocked (always None when serialized, populated in memory only)
        decrypted_folder: Option<Box<Folder>>,
    },
}

impl FolderItem {
    // ========== Constructors ==========

    pub const fn new_secret(
        name: String,
        entries: Vec<SecretEntry>,
        encryption_domain: u32,
    ) -> Self {
        Self::Secret {
            name,
            entries,
            encryption_domain,
        }
    }

    pub fn new_folder(name: String, folder: Folder) -> Self {
        Self::Folder {
            name,
            folder: Box::new(folder),
        }
    }

    pub const fn new_encrypted_folder(
        name: String,
        encrypted_data: Vec<u8>,
        encryption_domain: u32,
    ) -> Self {
        Self::EncryptedFolder {
            name,
            encrypted_data,
            encryption_domain,
            decrypted_folder: None,
        }
    }

    // ========== Basic Getters ==========

    /// Get the name of this item
    pub fn name(&self) -> &str {
        match self {
            Self::Secret { name, .. }
            | Self::Folder { name, .. }
            | Self::EncryptedFolder { name, .. } => name,
        }
    }

    /// Get the encryption domain for this item
    /// Returns None for regular (unencrypted) folders
    pub const fn encryption_domain(&self) -> Option<u32> {
        match self {
            Self::Secret {
                encryption_domain, ..
            }
            | Self::EncryptedFolder {
                encryption_domain, ..
            } => Some(*encryption_domain),
            Self::Folder { .. } => None,
        }
    }

    // ========== Type Checking ==========

    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret { .. })
    }

    pub const fn is_folder(&self) -> bool {
        matches!(self, Self::Folder { .. })
    }

    pub const fn is_encrypted_folder(&self) -> bool {
        matches!(self, Self::EncryptedFolder { .. })
    }

    /// Check if this is any kind of folder (regular or encrypted)
    pub const fn is_any_folder(&self) -> bool {
        matches!(self, Self::Folder { .. } | Self::EncryptedFolder { .. })
    }

    /// Check if this is a locked encrypted folder
    pub const fn is_locked(&self) -> bool {
        matches!(
            self,
            Self::EncryptedFolder {
                decrypted_folder: None,
                ..
            }
        )
    }

    /// Check if this is an unlocked encrypted folder
    pub const fn is_unlocked(&self) -> bool {
        matches!(
            self,
            Self::EncryptedFolder {
                decrypted_folder: Some(_),
                ..
            }
        )
    }

    /// Check if this item can be navigated into (regular folder or unlocked encrypted folder)
    pub const fn is_navigable(&self) -> bool {
        matches!(
            self,
            Self::Folder { .. }
                | Self::EncryptedFolder {
                    decrypted_folder: Some(_),
                    ..
                }
        )
    }

    // ========== Accessing Folder Data ==========

    /// Get folder reference if this is a navigable folder
    /// Returns regular folder or unlocked encrypted folder
    pub fn get_folder(&self) -> Option<&Folder> {
        match self {
            Self::Folder { folder, .. }
            | Self::EncryptedFolder {
                decrypted_folder: Some(folder),
                ..
            } => Some(folder),
            _ => None,
        }
    }

    /// Get mutable folder reference if this is a navigable folder
    pub fn get_folder_mut(&mut self) -> Option<&mut Folder> {
        match self {
            Self::Folder { folder, .. }
            | Self::EncryptedFolder {
                decrypted_folder: Some(folder),
                ..
            } => Some(folder),
            _ => None,
        }
    }

    // ========== Accessing Secret Data ==========

    /// Get secret entries (only for secrets, not folders)
    pub const fn get_entries(&self) -> Option<&Vec<SecretEntry>> {
        match self {
            Self::Secret { entries, .. } => Some(entries),
            _ => None,
        }
    }

    /// Get mutable secret entries (only for secrets)
    pub const fn get_entries_mut(&mut self) -> Option<&mut Vec<SecretEntry>> {
        match self {
            Self::Secret { entries, .. } => Some(entries),
            _ => None,
        }
    }

    /// Get the latest secret entry (most recent value)
    pub fn get_latest_entry(&self) -> Option<&SecretEntry> {
        self.get_entries()?.last()
    }

    /// Get the latest encrypted value (for display/copy)
    pub fn get_latest_value(&self) -> Option<&EncryptedValue> {
        self.get_latest_entry().map(SecretEntry::encrypted_value)
    }

    // ========== Encrypted Folder Operations ==========

    /// Encrypt a folder to a specific domain (converts Folder → `EncryptedFolder` or syncs changes)
    ///
    /// # Use cases
    /// - CLI `lock <folder> <domain>` command - encrypts folder to target domain
    /// - Before save - syncs in-memory changes back to `encrypted_data`
    ///
    /// # Behavior
    /// - Regular Folder: serialize, encrypt to target domain, convert to `EncryptedFolder`
    /// - `EncryptedFolder` with `decrypted_folder` (unlocked): serialize from memory, re-encrypt, **keeps folder unlocked**
    /// - `EncryptedFolder` without `decrypted_folder` (locked): decrypt from current domain, re-encrypt to target domain
    ///
    /// # Errors
    /// * If source or target domain is not unlocked
    /// * If serialization or encryption fails
    pub fn encrypt_folder(
        &mut self,
        target_domain_id: u32,
        domain_manager: &EncryptionDomainManager,
    ) -> Result<()> {
        match self {
            Self::Folder { folder, name } => {
                // Convert regular folder to encrypted folder
                let cypher = domain_manager
                    .get_cypher(target_domain_id)
                    .ok_or_else(|| anyhow::anyhow!("Domain {target_domain_id} is not unlocked"))?;

                let folder_bytes = serialize_folder_to_vec(folder)?;
                let encrypted_data = cypher.encrypt(&folder_bytes)?;

                *self = Self::new_encrypted_folder(name.clone(), encrypted_data, target_domain_id);
                Ok(())
            }
            Self::EncryptedFolder {
                encrypted_data,
                encryption_domain: source_domain_id,
                decrypted_folder,
                ..
            } => {
                let target_cypher =
                    domain_manager.get_cypher(target_domain_id).ok_or_else(|| {
                        anyhow::anyhow!("Target domain {target_domain_id} is not unlocked")
                    })?;

                let folder_bytes = if let Some(folder) = decrypted_folder.as_ref() {
                    // Use in-memory version (has latest changes)
                    serialize_folder_to_vec(folder)?
                } else {
                    // Decrypt from current domain first
                    let source_cypher =
                        domain_manager
                            .get_cypher(*source_domain_id)
                            .ok_or_else(|| {
                                anyhow::anyhow!("Source domain {source_domain_id} is not unlocked")
                            })?;
                    source_cypher.decrypt(encrypted_data)?
                };

                // Re-encrypt to target domain
                let new_encrypted_data = target_cypher.encrypt(&folder_bytes)?;

                *encrypted_data = new_encrypted_data;
                *source_domain_id = target_domain_id;
                Ok(())
            }
            Self::Secret { .. } => {
                bail!("Bug! should only be called for folders")
            }
        }
    }

    /// Re-encrypt an encrypted folder with its own domain's cypher
    /// This is used before saving to persist any changes made to unlocked folders
    /// Only re-encrypts if the folder is unlocked (has `decrypted_folder` populated)
    pub fn reencrypt_folder(&mut self, domain_manager: &EncryptionDomainManager) -> Result<()> {
        match self {
            Self::EncryptedFolder {
                encryption_domain,
                decrypted_folder,
                ..
            } => {
                // Only re-encrypt if the folder is unlocked (has been decrypted/modified)
                if decrypted_folder.is_some() {
                    let domain_id = *encryption_domain;
                    self.encrypt_folder(domain_id, domain_manager)
                } else {
                    // Folder is locked - no changes to persist, skip re-encryption
                    Ok(())
                }
            }
            Self::Folder { .. } | Self::Secret { .. } => {
                // Regular folders and secrets don't need re-encryption
                Ok(())
            }
        }
    }

    /// Decrypt an encrypted folder for access (lazy, idempotent)
    /// Populates `decrypted_folder` if not already populated
    ///
    /// # Errors
    /// * If not an encrypted folder
    /// * If the domain is not unlocked
    /// * If decryption or deserialization fails
    pub fn decrypt_folder(&mut self, domain_manager: &EncryptionDomainManager) -> Result<()> {
        match self {
            Self::EncryptedFolder {
                encrypted_data,
                encryption_domain,
                decrypted_folder,
                ..
            } => {
                // Idempotent - if already decrypted, do nothing
                if decrypted_folder.is_some() {
                    return Ok(());
                }

                // Get the domain's cypher
                let cypher = domain_manager
                    .get_cypher(*encryption_domain)
                    .ok_or_else(|| anyhow::anyhow!("Domain {encryption_domain} is not unlocked"))?;

                // Decrypt the folder data
                let folder_bytes = cypher.decrypt(encrypted_data)?;
                let folder = deserialize_folder_from_slice(&folder_bytes)?;

                // Populate the decrypted_folder field
                *decrypted_folder = Some(Box::new(folder));

                Ok(())
            }
            _ => bail!("Not an encrypted folder"),
        }
    }

    /// Get the encrypted data bytes (for re-encryption or storage)
    pub fn get_encrypted_data(&self) -> Option<&[u8]> {
        match self {
            Self::EncryptedFolder { encrypted_data, .. } => Some(encrypted_data),
            _ => None,
        }
    }

    // ========================================================================
    // Test/Debug helpers
    // ========================================================================

    #[cfg(any(test, debug_assertions))]
    /// Test helper: Manually set `decrypted_folder` (to test serialization behavior)
    /// Only available in test/debug builds
    pub fn test_set_decrypted_folder(&mut self, folder: Folder) -> Result<()> {
        match self {
            Self::EncryptedFolder {
                decrypted_folder, ..
            } => {
                *decrypted_folder = Some(Box::new(folder));
                Ok(())
            }
            _ => bail!("Not an encrypted folder"),
        }
    }

    #[cfg(any(test, debug_assertions))]
    /// Test helper: Check if `decrypted_folder` is populated
    /// Only available in test/debug builds
    pub const fn test_has_decrypted_folder(&self) -> bool {
        matches!(
            self,
            Self::EncryptedFolder {
                decrypted_folder: Some(_),
                ..
            }
        )
    }

    #[cfg(any(test, debug_assertions))]
    /// Test helper: Get `encrypted_data` bytes
    /// Only available in test/debug builds
    pub fn test_get_encrypted_data(&self) -> Option<&[u8]> {
        match self {
            Self::EncryptedFolder { encrypted_data, .. } => Some(encrypted_data),
            _ => None,
        }
    }
}

// Custom Encode/Decode implementations to ensure decrypted_folder is never serialized
impl Encode for FolderItem {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        match self {
            Self::Secret {
                name,
                entries,
                encryption_domain,
            } => {
                // Variant 0
                Encode::encode(&0u32, encoder)?;
                Encode::encode(name, encoder)?;
                Encode::encode(entries, encoder)?;
                Encode::encode(encryption_domain, encoder)?;
            }
            Self::Folder { name, folder } => {
                // Variant 1
                Encode::encode(&1u32, encoder)?;
                Encode::encode(name, encoder)?;
                Encode::encode(folder, encoder)?;
            }
            Self::EncryptedFolder {
                name,
                encrypted_data,
                encryption_domain,
                decrypted_folder: _, // Always skip this field
            } => {
                // Variant 2
                Encode::encode(&2u32, encoder)?;
                Encode::encode(name, encoder)?;
                Encode::encode(encrypted_data, encoder)?;
                Encode::encode(encryption_domain, encoder)?;
                // CRITICAL: decrypted_folder is NEVER encoded (security requirement)
            }
        }
        Ok(())
    }
}

impl<Context> Decode<Context> for FolderItem {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let variant = <u32 as Decode<Context>>::decode(decoder)?;
        match variant {
            0 => {
                let name = <String as Decode<Context>>::decode(decoder)?;
                let entries = <Vec<SecretEntry> as Decode<Context>>::decode(decoder)?;
                let encryption_domain = <u32 as Decode<Context>>::decode(decoder)?;
                Ok(Self::Secret {
                    name,
                    entries,
                    encryption_domain,
                })
            }
            1 => {
                let name = <String as Decode<Context>>::decode(decoder)?;
                let folder = <Box<Folder> as Decode<Context>>::decode(decoder)?;
                Ok(Self::Folder { name, folder })
            }
            2 => {
                let name = <String as Decode<Context>>::decode(decoder)?;
                let encrypted_data = <Vec<u8> as Decode<Context>>::decode(decoder)?;
                let encryption_domain = <u32 as Decode<Context>>::decode(decoder)?;
                // CRITICAL: decrypted_folder is always None after deserialization
                Ok(Self::EncryptedFolder {
                    name,
                    encrypted_data,
                    encryption_domain,
                    decrypted_folder: None,
                })
            }
            _ => Err(bincode::error::DecodeError::UnexpectedVariant {
                found: variant,
                allowed: &bincode::error::AllowedEnumVariants::Range { min: 0, max: 2 },
                type_name: "FolderItem",
            }),
        }
    }
}
bincode::impl_borrow_decode!(FolderItem);

// ============================================================================
// Folder - Hierarchical container with unified items
// ============================================================================

/// A folder containing a unified collection of secrets and subfolders
#[derive(Debug, Clone, Encode, Decode)]
pub struct Folder {
    /// Folder name (empty string for root)
    pub name: String,

    /// All items in this folder (secrets AND subfolders)
    pub items: BTreeMap<String, FolderItem>,
}

impl Folder {
    /// Create a new root folder
    pub const fn new_root() -> Self {
        Self {
            name: String::new(),
            items: BTreeMap::new(),
        }
    }

    /// Create a new named folder
    pub const fn new(name: String) -> Self {
        Self {
            name,
            items: BTreeMap::new(),
        }
    }

    // ========== Helper Methods ==========

    /// Get all secrets (excluding folders)
    pub fn secrets(&self) -> impl Iterator<Item = (&String, &FolderItem)> {
        self.items.iter().filter(|(_, item)| item.is_secret())
    }

    /// Get all folders (regular, encrypted, locked or unlocked)
    pub fn all_folders(&self) -> impl Iterator<Item = (&String, &FolderItem)> {
        self.items.iter().filter(|(_, item)| item.is_any_folder())
    }

    /// Get all navigable folders (regular + unlocked encrypted)
    pub fn navigable_folders(&self) -> impl Iterator<Item = (&String, &FolderItem)> {
        self.items.iter().filter(|(_, item)| item.is_navigable())
    }

    /// Get an item by name
    pub fn get_item(&self, name: &str) -> Option<&FolderItem> {
        self.items.get(name)
    }

    /// Get a mutable item by name
    pub fn get_item_mut(&mut self, name: &str) -> Option<&mut FolderItem> {
        self.items.get_mut(name)
    }

    /// Get a subfolder by name (only if navigable)
    pub fn get_subfolder(&self, name: &str) -> Option<&Self> {
        self.items.get(name).and_then(|item| item.get_folder())
    }

    /// Get a mutable subfolder by name (only if navigable)
    pub fn get_subfolder_mut(&mut self, name: &str) -> Option<&mut Self> {
        self.items
            .get_mut(name)
            .and_then(|item| item.get_folder_mut())
    }
}

// ============================================================================
// Secret Entry - A versioned secret with metadata
// ============================================================================

/// A secret entry with timestamp and metadata
#[derive(Debug, Clone, Encode, Decode)]
pub struct SecretEntry {
    /// The encrypted secret value
    pub value: EncryptedValue,

    /// When this version was created (seconds since UNIX epoch)
    pub timestamp: u64,

    /// Type of secret
    pub secret_type: SecretType,

    /// Optional metadata (for future file storage, etc.)
    pub metadata: HashMap<String, String>,
}

impl SecretEntry {
    /// Create a new secret entry
    pub fn new(encrypted_value: EncryptedValue, timestamp: u64) -> Self {
        Self {
            value: encrypted_value,
            timestamp,
            secret_type: SecretType::Utf8String,
            metadata: HashMap::new(),
        }
    }

    /// Get the encrypted value from this entry
    pub const fn encrypted_value(&self) -> &EncryptedValue {
        &self.value
    }
}

// ============================================================================
// Secret Type - Extensible enum for different secret types
// ============================================================================

/// Type of secret content
#[derive(Debug, Clone, Copy, Encode, Decode, PartialEq, Eq)]
#[repr(u16)]
pub enum SecretType {
    Utf8String = 0,
}

// ============================================================================
// Serialization - Stream-based
// ============================================================================

/// Serialize V5 storage to a writer
/// Format: [version:u16 big-endian][bincode_payload]
/// Version is written separately to allow forward-only stream reading
pub fn serialize_storage_v5<W: Write>(writer: &mut W, storage: &StorageV5) -> Result<()> {
    // Write version (2 bytes, big-endian)
    let version = StoreVersion::Version5 as u16;
    writer.write_all(&version.to_be_bytes())?;

    // Serialize the storage with bincode
    let config = config::standard();
    bincode::encode_into_std_write(storage, writer, config)?;

    Ok(())
}

/// Deserialize V5 storage from a reader
/// Reads version first, then deserializes payload (forward-only stream)
pub fn deserialize_storage_v5<R: Read>(reader: &mut R) -> Result<StorageV5> {
    // Read version (2 bytes, big-endian)
    let mut version_bytes = [0u8; 2];
    reader.read_exact(&mut version_bytes)?;
    let version = u16::from_be_bytes(version_bytes);

    let expected_version = StoreVersion::Version5 as u16;
    if version != expected_version {
        bail!("Invalid version for V5 deserializer: expected {expected_version}, got {version}");
    }

    // Deserialize storage from stream
    let config = config::standard();
    let mut storage: StorageV5 = bincode::decode_from_std_read(reader, config)?;

    // Sort entries by timestamp for consistency
    sort_folder_entries(&mut storage.root);

    Ok(storage)
}

// Convenience functions for Vec<u8>

/// Serialize V5 storage to bytes (convenience wrapper)
pub fn serialize_storage_v5_to_vec(storage: &StorageV5) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Vec::new();
    serialize_storage_v5(&mut buffer, storage)?;
    Ok(Zeroizing::new(buffer))
}

/// Deserialize V5 storage from bytes (convenience wrapper)
pub fn deserialize_storage_v5_from_slice(data: &[u8]) -> Result<StorageV5> {
    let mut cursor = std::io::Cursor::new(data);
    deserialize_storage_v5(&mut cursor)
}

// ============================================================================
// Folder Serialization Helpers
// ============================================================================

/// Serialize a Folder to bytes using bincode
/// Used for encrypting folders into `EncryptedFolder` variant
pub fn serialize_folder_to_vec(folder: &Folder) -> Result<Zeroizing<Vec<u8>>> {
    let config = config::standard();
    let bytes = bincode::encode_to_vec(folder, config)?;
    Ok(Zeroizing::new(bytes))
}

/// Deserialize a Folder from bytes using bincode
/// Used for decrypting `EncryptedFolder` variant
pub fn deserialize_folder_from_slice(data: &[u8]) -> Result<Folder> {
    let config = config::standard();
    let (folder, _len) = bincode::decode_from_slice(data, config)?;
    Ok(folder)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Sort all secret entries by timestamp (recursive)
fn sort_folder_entries(folder: &mut Folder) {
    for item in folder.items.values_mut() {
        match item {
            FolderItem::Secret { entries, .. } => {
                entries.sort_by_key(|e| e.timestamp);
            }
            FolderItem::Folder { folder, .. } => {
                sort_folder_entries(folder);
            }
            FolderItem::EncryptedFolder {
                decrypted_folder, ..
            } => {
                if let Some(df) = decrypted_folder {
                    sort_folder_entries(df);
                }
            }
        }
    }
}

// ============================================================================
// Migration from V4 to V5
// ============================================================================

use super::v4::StorageV4;
use super::value::ValueEntry;

/// Migrate V4 storage to V5 format
/// All secrets go into root folder with default encryption domain (0)
pub fn migrate_v4_to_v5(v4: StorageV4) -> StorageV5 {
    let mut root = Folder::new_root();

    // Migrate flat structure to root folder
    for (key, entries) in v4.data {
        let secrets: Vec<SecretEntry> = entries.into_iter().map(value_entry_to_secret).collect();

        root.items.insert(
            key.clone(),
            FolderItem::new_secret(key, secrets, MASTER_DOMAIN_ID),
        );
    }

    // Initialize encryption domains with master domain
    let mut encryption_domains = std::collections::HashMap::new();
    encryption_domains.insert(MASTER_DOMAIN_ID, MASTER_DOMAIN_NAME.to_string());

    StorageV5 {
        root,
        encryption_domains,
    }
}

/// Convert V4 `ValueEntry` to V5 `SecretEntry`
fn value_entry_to_secret(entry: ValueEntry) -> SecretEntry {
    SecretEntry::new(entry.value, entry.timestamp)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Argon2Params, Cypher, CypherVersion, EncryptionKey};

    /// Test helper: Create a domain manager with master key
    fn test_domain_manager() -> EncryptionDomainManager {
        // Use insecure params for testing (faster)
        let key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            "test_password",
            &Argon2Params::insecure(),
        )
        .expect("Failed to create key");
        let master_cypher = Cypher::new(key);
        EncryptionDomainManager::new(master_cypher)
    }

    #[test]
    fn test_empty_storage_v5() {
        let storage = StorageV5::new();
        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        assert!(deserialized.root.items.is_empty());
    }

    #[test]
    fn test_simple_secret_v5() {
        let mut storage = StorageV5::new();
        let test_value = EncryptedValue::from_ciphertext(b"test_value".to_vec());
        storage.root.items.insert(
            "test_key".to_string(),
            FolderItem::new_secret(
                "test_key".to_string(),
                vec![SecretEntry::new(test_value, 12345)],
                0,
            ),
        );

        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        assert_eq!(deserialized.root.items.len(), 1);
        let item = &deserialized.root.items["test_key"];

        match item {
            FolderItem::Secret {
                entries,
                encryption_domain,
                ..
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].encrypted_value().as_bytes(), b"test_value");
                assert_eq!(*encryption_domain, 0);
            }
            _ => panic!("Expected Secret variant"),
        }
    }

    #[test]
    fn test_folder_structure() {
        let mut storage = StorageV5::new();

        // Add a subfolder
        let mut subfolder = Folder::new("work".to_string());
        let api_key_value = EncryptedValue::from_ciphertext(b"secret123".to_vec());
        subfolder.items.insert(
            "api_key".to_string(),
            FolderItem::new_secret(
                "api_key".to_string(),
                vec![SecretEntry::new(api_key_value, 12345)],
                0,
            ),
        );

        storage.root.items.insert(
            "work".to_string(),
            FolderItem::new_folder("work".to_string(), subfolder),
        );

        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        assert_eq!(deserialized.root.items.len(), 1);
        assert!(deserialized.root.items.contains_key("work"));
        let work_item = &deserialized.root.items["work"];
        assert!(work_item.is_folder());
        if let Some(work_folder) = work_item.get_folder() {
            assert_eq!(work_folder.items.len(), 1);
        } else {
            panic!("Expected folder");
        }
    }

    #[test]
    fn test_encrypted_folder_variant() {
        let mut storage = StorageV5::new();

        // Create an encrypted folder
        storage.root.items.insert(
            "secret_folder".to_string(),
            FolderItem::new_encrypted_folder(
                "secret_folder".to_string(),
                vec![1, 2, 3, 4], // Mock encrypted data
                1,
            ),
        );

        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        let item = &deserialized.root.items["secret_folder"];
        assert!(item.is_encrypted_folder());
        assert!(item.is_locked());
        assert_eq!(item.encryption_domain(), Some(1));
    }

    #[test]
    fn test_v4_migration() {
        let mut v4 = StorageV4::new();
        v4.put(
            "key1".to_string(),
            EncryptedValue::from_ciphertext("value1".into()),
        );
        v4.put(
            "key2".to_string(),
            EncryptedValue::from_ciphertext("value2".into()),
        );

        let v5 = migrate_v4_to_v5(v4);

        assert_eq!(v5.root.items.len(), 2);
        assert!(v5.root.items.contains_key("key1"));
        assert!(v5.root.items.contains_key("key2"));
        // All migrated secrets should use master domain (0)
        assert_eq!(v5.root.items["key1"].encryption_domain(), Some(0));
        assert_eq!(v5.root.items["key2"].encryption_domain(), Some(0));
    }

    #[test]
    fn test_put_and_get() {
        let mut storage = StorageV5::new();
        let dm = test_domain_manager();
        storage
            .put_at_path("/", "test_key".to_string(), "test_value", 0, 0, &dm)
            .unwrap();

        let results: Vec<_> = storage
            .get_at_path("/", "test_key", false, &dm)
            .unwrap()
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "/"); // full_path
        assert_eq!(results[0].1, "test_key"); // key name
        assert_eq!(results[0].2.as_bytes(), b"test_value"); // value
    }

    #[test]
    fn test_get_with_pattern() {
        let mut storage = StorageV5::new();
        let dm = test_domain_manager();
        storage
            .put_at_path("/", "key1".to_string(), "value1", 0, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "key2".to_string(), "value2", 0, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "other".to_string(), "value3", 0, 0, &dm)
            .unwrap();

        let results: Vec<_> = storage
            .get_at_path("/", "key.*", false, &dm)
            .unwrap()
            .collect();
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .any(|(path, k, _)| path == "/" && *k == "key1")
        );
        assert!(
            results
                .iter()
                .any(|(path, k, _)| path == "/" && *k == "key2")
        );
    }

    #[test]
    fn test_search() {
        let mut storage = StorageV5::new();
        let dm = test_domain_manager();
        storage
            .put_at_path("/", "alpha".to_string(), "value1", 0, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "beta".to_string(), "value2", 0, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "gamma".to_string(), "value3", 0, 0, &dm)
            .unwrap();

        let results: Vec<_> = storage
            .search_at_path("/", ".*a.*", true, &dm)
            .unwrap()
            .collect();
        assert_eq!(results.len(), 2); // alpha, gamma
        assert!(results.iter().any(|(path, k)| path == "/" && *k == "alpha"));
        assert!(results.iter().any(|(path, k)| path == "/" && *k == "gamma"));
    }

    #[test]
    fn test_history() {
        let mut storage = StorageV5::new();
        let dm = test_domain_manager();
        storage
            .put_at_path("/", "key".to_string(), "value1", 100, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "key".to_string(), "value2", 200, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "key".to_string(), "value3", 300, 0, &dm)
            .unwrap();

        let history: Vec<_> = storage.history_at_path("/", "key", &dm).unwrap().collect();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].timestamp, 100);
        assert_eq!(history[1].timestamp, 200);
        assert_eq!(history[2].timestamp, 300);
    }

    #[test]
    fn test_delete() {
        let mut storage = StorageV5::new();
        let dm = test_domain_manager();
        storage
            .put_at_path("/", "key1".to_string(), "value1", 0, 0, &dm)
            .unwrap();
        storage
            .put_at_path("/", "key2".to_string(), "value2", 0, 0, &dm)
            .unwrap();

        assert!(storage.delete_at_path("/", "key1", &dm));
        assert!(!storage.delete_at_path("/", "key1", &dm)); // Already deleted
        assert!(storage.delete_at_path("/", "key2", &dm));

        let results: Vec<_> = storage.get_at_path("/", ".*", true, &dm).unwrap().collect();
        assert_eq!(results.len(), 0);
    }
}
