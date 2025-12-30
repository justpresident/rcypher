use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};

use anyhow::{Result, bail};
use bincode::{Decode, Encode, config};
use regex::Regex;

use super::value::EncryptedValue;
use crate::path_utils::{format_full_path, relative_path_from};
use crate::version::StoreVersion;

// ============================================================================
// Storage V5 - Hierarchical folders with encryption domains
// ============================================================================

/// Root storage container for V5
#[derive(Debug, Clone, Encode, Decode)]
pub struct StorageV5 {
    /// Root folder containing all secrets and subfolders
    pub root: Folder,
}

impl StorageV5 {
    /// Create a new empty V5 storage
    pub const fn new() -> Self {
        Self {
            root: Folder::new_root(),
        }
    }

    /// Get a folder by path (e.g., "/" or "/work/personal")
    pub fn get_folder(&self, path: &str) -> Option<&Folder> {
        if path == "/" || path.is_empty() {
            return Some(&self.root);
        }

        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current = &self.root;

        for part in parts {
            current = current.get_subfolder(part)?;
        }

        Some(current)
    }

    /// Get a mutable folder by path
    pub fn get_folder_mut(&mut self, path: &str) -> Option<&mut Folder> {
        if path == "/" || path.is_empty() {
            return Some(&mut self.root);
        }

        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current = &mut self.root;

        for part in parts {
            current = current.get_subfolder_mut(part)?;
        }

        Some(current)
    }

    /// Create a new folder at the given path
    pub fn mkdir(&mut self, path: &str, folder_name: &str) -> Result<()> {
        let parent = self
            .get_folder_mut(path)
            .ok_or_else(|| anyhow::anyhow!("Parent folder '{path}' not found"))?;

        if parent.items.contains_key(folder_name) {
            bail!("Item '{folder_name}' already exists");
        }

        let new_folder = Folder::new(folder_name.to_string(), parent.encryption_domain);
        parent.items.insert(
            folder_name.to_string(),
            FolderItem::new_folder(folder_name.to_string(), new_folder),
        );

        Ok(())
    }

    /// Store a secret value at a specific path
    pub fn put_at_path(&mut self, path: &str, key: String, value: EncryptedValue, timestamp: u64) {
        if let Some(folder) = self.get_folder_mut(path) {
            let entry = SecretEntry::new(value, timestamp);

            folder
                .items
                .entry(key.clone())
                .and_modify(|item| {
                    if let Some(entries) = item.get_entries_mut() {
                        entries.push(entry.clone());
                    }
                })
                .or_insert_with(|| FolderItem::new_secret(key, vec![entry], 0));
        }
    }

    /// Returns an iterator over key-value pairs matching the given regex pattern in root folder.
    ///
    /// # Sorting
    /// - Keys are returned in sorted order (guaranteed by `BTreeMap`)
    /// - Returns the latest value for each key (entries sorted by timestamp)
    ///
    /// Returns (`full_path`, key, value) tuples where `full_path` is like "/work/personal"
    pub fn get(
        &self,
        pattern: &str,
    ) -> Result<impl Iterator<Item = (String, &str, &EncryptedValue)> + '_> {
        self.get_at_path("/", pattern, false)
    }

    /// Returns an iterator over key-value pairs matching pattern at a specific path.
    /// If recursive is true, searches through all subfolders.
    /// Returns (`full_path`, key, value) tuples where `full_path` is like "/work/personal"
    pub fn get_at_path(
        &self,
        path: &str,
        pattern: &str,
        recursive: bool,
    ) -> Result<impl Iterator<Item = (String, &str, &EncryptedValue)> + '_> {
        let re = Regex::new(&format!("^{pattern}$"))?;
        let folder = self
            .get_folder(path)
            .ok_or_else(|| anyhow::anyhow!("Folder '{path}' not found"))?;

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

    /// Returns an iterator over all historical values for a given key in root folder.
    ///
    /// # Sorting
    /// Entries are returned in chronological order (oldest to newest).
    pub fn history(&self, key: &str) -> Option<impl Iterator<Item = &SecretEntry> + '_> {
        self.history_at_path("/", key)
    }

    /// Returns an iterator over all historical values for a given key at a specific path.
    /// Returns None for folders (regular or encrypted).
    pub fn history_at_path(
        &self,
        path: &str,
        key: &str,
    ) -> Option<impl Iterator<Item = &SecretEntry> + '_> {
        self.get_folder(path)
            .and_then(|folder| folder.get_item(key))
            .and_then(|item| item.get_entries())
            .map(|entries| entries.iter())
    }

    /// Delete a key and all its history from root folder
    pub fn delete(&mut self, key: &str) -> bool {
        self.delete_at_path("/", key)
    }

    /// Delete an item (secret, folder, or encrypted folder) from a specific path
    pub fn delete_at_path(&mut self, path: &str, key: &str) -> bool {
        self.get_folder_mut(path)
            .and_then(|folder| folder.items.remove(key))
            .is_some()
    }

    /// Move an item (secret, folder, or encrypted folder) from one location to another
    /// Works like shell `mv` - handles both files and directories uniformly
    /// `source_folder`: folder containing the item
    /// `item_name`: name of the item to move
    /// `dest_folder`: destination folder
    /// `dest_name`: optional new name (if None, keeps same name)
    pub fn move_item(
        &mut self,
        source_folder: &str,
        item_name: &str,
        dest_folder: &str,
        dest_name: Option<&str>,
    ) -> Result<()> {
        let final_name = dest_name.unwrap_or(item_name);

        // Check destination folder exists and no collision (must do before removing from source)
        {
            let dest = self
                .get_folder(dest_folder)
                .ok_or_else(|| anyhow::anyhow!("Destination folder '{dest_folder}' not found"))?;

            if dest.items.contains_key(final_name) {
                bail!("Item '{final_name}' already exists at destination '{dest_folder}'");
            }
        }

        // Remove from source
        let mut item = self
            .get_folder_mut(source_folder)
            .ok_or_else(|| anyhow::anyhow!("Source folder '{source_folder}' not found"))?
            .items
            .remove(item_name)
            .ok_or_else(|| anyhow::anyhow!("Item '{item_name}' not found in '{source_folder}'"))?;

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

        // Insert into dest
        self.get_folder_mut(dest_folder)
            .expect("dest folder exists")
            .items
            .insert(final_name.to_string(), item);

        Ok(())
    }

    /// Returns an iterator over all keys matching the given regex pattern in root folder.
    ///
    /// # Sorting
    /// Keys are returned in sorted order (guaranteed by `BTreeMap`).
    /// Returns (`folder_path`, key) tuples where `folder_path` is like "/work/personal"
    pub fn search(&self, pattern: &str) -> Result<impl Iterator<Item = (String, &str)> + '_> {
        self.search_at_path("/", pattern, false)
    }

    /// Returns an iterator over all keys matching pattern at a specific path.
    /// If recursive is true, searches through all subfolders.
    /// Returns (`folder_path`, key) tuples where `folder_path` is like "/work/personal"
    pub fn search_at_path(
        &self,
        path: &str,
        pattern: &str,
        recursive: bool,
    ) -> Result<impl Iterator<Item = (String, &str)> + '_> {
        let re = Regex::new(pattern)?;
        let folder = self
            .get_folder(path)
            .ok_or_else(|| anyhow::anyhow!("Folder '{path}' not found"))?;

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
}

// ============================================================================
// Zero-copy iterators through Folder structure
// ============================================================================

type ItemsIterator<'a> = std::collections::btree_map::Iter<'a, String, FolderItem>;

/// Iterator over secrets in a folder and optionally its subfolders
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
#[derive(Debug, Clone, Encode, Decode)]
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
    /// Returns folder's default domain for regular folders
    pub fn encryption_domain(&self) -> u32 {
        match self {
            Self::Secret {
                encryption_domain, ..
            }
            | Self::EncryptedFolder {
                encryption_domain, ..
            } => *encryption_domain,
            Self::Folder { folder, .. } => folder.encryption_domain,
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

    /// Get the underlying Folder box (for moving folders around)
    pub fn take_folder(self) -> Option<Box<Folder>> {
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

    /// Unlock an encrypted folder with the decrypted data
    /// Returns error if not an encrypted folder or already unlocked
    pub fn unlock(&mut self, decrypted_folder: Folder) -> Result<()> {
        match self {
            Self::EncryptedFolder {
                decrypted_folder: df,
                ..
            } => {
                if df.is_some() {
                    bail!("Folder already unlocked");
                }
                *df = Some(Box::new(decrypted_folder));
                Ok(())
            }
            _ => bail!("Not an encrypted folder"),
        }
    }

    /// Lock an encrypted folder (clear the decrypted data)
    pub fn lock(&mut self) -> Result<()> {
        match self {
            Self::EncryptedFolder {
                decrypted_folder: df,
                ..
            } => {
                *df = None;
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
}

// ============================================================================
// Folder - Hierarchical container with unified items
// ============================================================================

/// A folder containing a unified collection of secrets and subfolders
#[derive(Debug, Clone, Encode, Decode)]
pub struct Folder {
    /// Folder name (empty string for root)
    pub name: String,

    /// Default encryption domain for new items created in this folder
    /// - 0 = default domain (master key)
    /// - N > 0 = custom domain (requires separate password)
    pub encryption_domain: u32,

    /// All items in this folder (secrets AND subfolders)
    pub items: BTreeMap<String, FolderItem>,
}

impl Folder {
    /// Create a new root folder (domain 0)
    pub const fn new_root() -> Self {
        Self {
            name: String::new(),
            encryption_domain: 0,
            items: BTreeMap::new(),
        }
    }

    /// Create a new named folder
    pub const fn new(name: String, encryption_domain: u32) -> Self {
        Self {
            name,
            encryption_domain,
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
pub fn serialize_storage_v5_to_vec(storage: &StorageV5) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    serialize_storage_v5(&mut buffer, storage)?;
    Ok(buffer)
}

/// Deserialize V5 storage from bytes (convenience wrapper)
pub fn deserialize_storage_v5_from_slice(data: &[u8]) -> Result<StorageV5> {
    let mut cursor = std::io::Cursor::new(data);
    deserialize_storage_v5(&mut cursor)
}

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

use super::store::StorageV4;
use super::value::ValueEntry;

/// Migrate V4 storage to V5 format
/// All secrets go into root folder with default encryption domain (0)
pub fn migrate_v4_to_v5(v4: StorageV4) -> StorageV5 {
    let mut root = Folder::new_root();

    // Migrate flat structure to root folder
    for (key, entries) in v4.data {
        let secrets: Vec<SecretEntry> = entries.into_iter().map(value_entry_to_secret).collect();

        root.items
            .insert(key.clone(), FolderItem::new_secret(key, secrets, 0));
    }

    StorageV5 { root }
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
        let mut subfolder = Folder::new("work".to_string(), 0);
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
        assert_eq!(item.encryption_domain(), 1);
    }

    #[test]
    fn test_v4_migration() {
        let mut v4 = StorageV4::new();
        v4.put("key1".to_string(), "value1".into());
        v4.put("key2".to_string(), "value2".into());

        let v5 = migrate_v4_to_v5(v4);

        assert_eq!(v5.root.items.len(), 2);
        assert!(v5.root.items.contains_key("key1"));
        assert!(v5.root.items.contains_key("key2"));
        assert_eq!(v5.root.encryption_domain, 0);
    }

    #[test]
    fn test_put_and_get() {
        let mut storage = StorageV5::new();
        let test_value = EncryptedValue::from_ciphertext(b"test_value".to_vec());
        storage.put_at_path("/", "test_key".to_string(), test_value, 0);

        let results: Vec<_> = storage.get("test_key").unwrap().collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "test_key");
        assert_eq!(results[0].1.as_bytes(), b"test_value");
    }

    #[test]
    fn test_get_with_pattern() {
        let mut storage = StorageV5::new();
        storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::from_ciphertext(b"value1".to_vec()),
            0,
        );
        storage.put_at_path(
            "/",
            "key2".to_string(),
            EncryptedValue::from_ciphertext(b"value2".to_vec()),
            0,
        );
        storage.put_at_path(
            "/",
            "other".to_string(),
            EncryptedValue::from_ciphertext(b"value3".to_vec()),
            0,
        );

        let results: Vec<_> = storage.get("key.*").unwrap().collect();
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
        storage.put_at_path(
            "/",
            "alpha".to_string(),
            EncryptedValue::from_ciphertext(b"value1".to_vec()),
            0,
        );
        storage.put_at_path(
            "/",
            "beta".to_string(),
            EncryptedValue::from_ciphertext(b"value2".to_vec()),
            0,
        );
        storage.put_at_path(
            "/",
            "gamma".to_string(),
            EncryptedValue::from_ciphertext(b"value3".to_vec()),
            0,
        );

        let results: Vec<_> = storage.search(".*a.*").unwrap().collect();
        assert_eq!(results.len(), 2); // alpha, gamma
        assert!(results.iter().any(|(path, k)| path == "/" && *k == "alpha"));
        assert!(results.iter().any(|(path, k)| path == "/" && *k == "gamma"));
    }

    #[test]
    fn test_history() {
        let mut storage = StorageV5::new();
        storage.put_at_path(
            "/",
            "key".to_string(),
            EncryptedValue::from_ciphertext(b"value1".to_vec()),
            100,
        );
        storage.put_at_path(
            "/",
            "key".to_string(),
            EncryptedValue::from_ciphertext(b"value2".to_vec()),
            200,
        );
        storage.put_at_path(
            "/",
            "key".to_string(),
            EncryptedValue::from_ciphertext(b"value3".to_vec()),
            300,
        );

        let history: Vec<_> = storage.history("key").unwrap().collect();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].timestamp, 100);
        assert_eq!(history[1].timestamp, 200);
        assert_eq!(history[2].timestamp, 300);
    }

    #[test]
    fn test_delete() {
        let mut storage = StorageV5::new();
        storage.put_at_path(
            "/",
            "key1".to_string(),
            EncryptedValue::from_ciphertext(b"value1".to_vec()),
            0,
        );
        storage.put_at_path(
            "/",
            "key2".to_string(),
            EncryptedValue::from_ciphertext(b"value2".to_vec()),
            0,
        );

        assert!(storage.delete("key1"));
        assert!(!storage.delete("key1")); // Already deleted
        assert!(storage.delete("key2"));

        let results: Vec<_> = storage.get(".*").unwrap().collect();
        assert_eq!(results.len(), 0);
    }
}
