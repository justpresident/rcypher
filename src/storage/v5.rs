use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};

use anyhow::{Result, bail};
use bincode::{Decode, Encode, config};
use regex::Regex;

use super::value::EncryptedValue;
use crate::cli::utils::{format_full_path, relative_path_from};
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
            current = current.subfolders.get(part)?;
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
            current = current.subfolders.get_mut(part)?;
        }

        Some(current)
    }

    /// Create a new folder at the given path
    pub fn mkdir(&mut self, path: &str, folder_name: &str) -> Result<()> {
        let parent = self
            .get_folder_mut(path)
            .ok_or_else(|| anyhow::anyhow!("Parent folder '{path}' not found"))?;

        if parent.subfolders.contains_key(folder_name) {
            bail!("Folder '{folder_name}' already exists");
        }

        parent.subfolders.insert(
            folder_name.to_string(),
            Folder::new(folder_name.to_string(), parent.encryption_domain),
        );

        Ok(())
    }

    /// Store a secret value at a specific path
    pub fn put_at_path(&mut self, path: &str, key: String, value: EncryptedValue, timestamp: u64) {
        if let Some(folder) = self.get_folder_mut(path) {
            folder
                .secrets
                .entry(key)
                .or_default()
                .push(SecretEntry::new_plain(value, timestamp, 0));
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
    pub fn history_at_path(
        &self,
        path: &str,
        key: &str,
    ) -> Option<impl Iterator<Item = &SecretEntry> + '_> {
        self.get_folder(path)
            .and_then(|folder| folder.secrets.get(key))
            .map(|entries| entries.iter())
    }

    /// Delete a key and all its history from root folder
    pub fn delete(&mut self, key: &str) -> bool {
        self.delete_at_path("/", key)
    }

    /// Delete a key and all its history from a specific path
    pub fn delete_at_path(&mut self, path: &str, key: &str) -> bool {
        self.get_folder_mut(path)
            .and_then(|folder| folder.secrets.remove(key))
            .is_some()
    }

    /// Move a key from one location to another (like shell mv)
    /// `source_folder`: folder containing the key
    /// key: the key to move
    /// `dest_folder`: destination folder
    /// `dest_key`: optional new key name (if None, keeps same name)
    pub fn move_key(
        &mut self,
        source_folder: &str,
        key: &str,
        dest_folder: &str,
        dest_key: Option<&str>,
    ) -> Result<()> {
        let final_key = dest_key.unwrap_or(key);

        // Check destination folder exists and no collision (must do before removing from source)
        {
            let dest = self
                .get_folder(dest_folder)
                .ok_or_else(|| anyhow::anyhow!("Destination folder '{dest_folder}' not found"))?;

            if dest.secrets.contains_key(final_key) {
                bail!("Key '{final_key}' already exists at destination '{dest_folder}'");
            }
        }

        // Remove from source
        let entries = self
            .get_folder_mut(source_folder)
            .ok_or_else(|| anyhow::anyhow!("Source folder '{source_folder}' not found"))?
            .secrets
            .remove(key)
            .ok_or_else(|| anyhow::anyhow!("Key '{key}' not found in '{source_folder}'"))?;

        // Insert into dest
        self.get_folder_mut(dest_folder)
            .expect("dest folder exists")
            .secrets
            .insert(final_key.to_string(), entries);

        Ok(())
    }

    /// Move a folder from one location to another (like shell mv for directories)
    /// `parent_path`: parent folder containing the folder to move
    /// `folder_name`: name of the folder to move
    /// `dest_parent`: destination parent folder
    /// `dest_name`: optional new folder name (if None, keeps same name)
    pub fn move_folder(
        &mut self,
        parent_path: &str,
        folder_name: &str,
        dest_parent: &str,
        dest_name: Option<&str>,
    ) -> Result<()> {
        let final_name = dest_name.unwrap_or(folder_name);

        // Check destination parent exists and no collision
        {
            let dest = self
                .get_folder(dest_parent)
                .ok_or_else(|| anyhow::anyhow!("Destination folder '{dest_parent}' not found"))?;

            if dest.subfolders.contains_key(final_name) {
                bail!("Folder '{final_name}' already exists at destination '{dest_parent}'");
            }
        }

        // Remove from source
        let folder = self
            .get_folder_mut(parent_path)
            .ok_or_else(|| anyhow::anyhow!("Source folder '{parent_path}' not found"))?
            .subfolders
            .remove(folder_name)
            .ok_or_else(|| {
                anyhow::anyhow!("Folder '{folder_name}' not found in '{parent_path}'")
            })?;

        // Insert into dest
        self.get_folder_mut(dest_parent)
            .expect("dest parent exists")
            .subfolders
            .insert(final_name.to_string(), folder);

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
// Recursive Iterators - Zero-copy iteration through folder hierarchies
// ============================================================================

type SecretsIterator<'a> = std::collections::btree_map::Iter<'a, String, Vec<SecretEntry>>;
type KeysIterator<'a> = std::collections::btree_map::Keys<'a, String, Vec<SecretEntry>>;
type FolderIterator<'a> = std::collections::btree_map::Iter<'a, String, Folder>;
/// Iterator over secrets in a folder and optionally its subfolders
pub struct RecursiveSecretIterator<'a> {
    // Stack of (current_path, folder, secrets_iter) for depth-first traversal
    stack: Vec<(String, &'a Folder, SecretsIterator<'a>)>,
    regex: Regex,
    recursive: bool,
    // For tracking subfolders to visit - stores (current_path, subfolders_iter)
    subfolders_stack: Vec<(String, FolderIterator<'a>)>,
    // Search root for computing relative paths in regex matching
    search_root: String,
}

impl<'a> RecursiveSecretIterator<'a> {
    fn new(folder: &'a Folder, regex: Regex, recursive: bool, initial_path: String) -> Self {
        let secrets_iter = folder.secrets.iter();
        let subfolders_iter = folder.subfolders.iter();

        Self {
            stack: vec![(initial_path.clone(), folder, secrets_iter)],
            regex,
            recursive,
            subfolders_stack: vec![(initial_path.clone(), subfolders_iter)],
            search_root: initial_path,
        }
    }
}

impl<'a> Iterator for RecursiveSecretIterator<'a> {
    type Item = (String, &'a str, &'a EncryptedValue);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next secret from current folder
            if let Some((current_path, _, secrets_iter)) = self.stack.last_mut() {
                let path = current_path.clone();
                // Compute relative path from search root for regex matching
                let relative_folder = relative_path_from(&self.search_root, &path);

                for (key, entries) in secrets_iter.by_ref() {
                    // Match regex against full relative path (folder + key)
                    let full_path = format_full_path(&relative_folder, key, false);
                    if self.regex.is_match(&full_path)
                        && !entries.is_empty()
                        && let Some(entry) = entries.last()
                    {
                        return Some((path, key.as_str(), entry.encrypted_value()));
                    }
                }
            }

            // Current folder exhausted, try to descend into subfolder
            if self.recursive
                && let Some((current_path, subfolders_iter)) = self.subfolders_stack.last_mut()
                && let Some((subfolder_name, subfolder)) = subfolders_iter.next()
            {
                // Build path for the subfolder
                let new_path = if current_path == "/" {
                    format!("/{subfolder_name}")
                } else {
                    format!("{current_path}/{subfolder_name}")
                };

                // Push new folder onto stack
                self.stack
                    .push((new_path.clone(), subfolder, subfolder.secrets.iter()));
                self.subfolders_stack
                    .push((new_path, subfolder.subfolders.iter()));
                continue;
            }

            // No more subfolders, pop the stack
            self.stack.pop();
            self.subfolders_stack.pop();

            if self.stack.is_empty() {
                return None;
            }
        }
    }
}

/// Iterator over keys in a folder and optionally its subfolders
pub struct RecursiveKeyIterator<'a> {
    // Stack of (current_path, keys_iter) for tracking keys in each folder
    stack: Vec<(String, KeysIterator<'a>)>,
    regex: Regex,
    recursive: bool,
    // Stack of (current_path, folder, subfolders_iter) for descending into subfolders
    folder_stack: Vec<(String, &'a Folder, FolderIterator<'a>)>,
    // Search root for computing relative paths in regex matching
    search_root: String,
}

impl<'a> RecursiveKeyIterator<'a> {
    fn new(folder: &'a Folder, regex: Regex, recursive: bool, initial_path: String) -> Self {
        let keys_iter = folder.secrets.keys();
        let subfolders_iter = folder.subfolders.iter();

        Self {
            stack: vec![(initial_path.clone(), keys_iter)],
            regex,
            recursive,
            folder_stack: vec![(initial_path.clone(), folder, subfolders_iter)],
            search_root: initial_path,
        }
    }
}

impl<'a> Iterator for RecursiveKeyIterator<'a> {
    type Item = (String, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next key from current folder
            if let Some((current_path, keys_iter)) = self.stack.last_mut() {
                let path = current_path.clone();
                // Compute relative path from search root for regex matching
                let relative_folder = relative_path_from(&self.search_root, &path);

                for key in keys_iter.by_ref() {
                    // Match regex against full relative path (folder + key)
                    let full_path = format_full_path(&relative_folder, key, false);
                    if self.regex.is_match(&full_path) {
                        return Some((path, key.as_str()));
                    }
                }
            }

            // Current folder exhausted, try to descend into subfolder
            if self.recursive
                && let Some((current_path, _, subfolders_iter)) = self.folder_stack.last_mut()
                && let Some((subfolder_name, subfolder)) = subfolders_iter.next()
            {
                // Build path for the subfolder
                let new_path = if current_path == "/" {
                    format!("/{subfolder_name}")
                } else {
                    format!("{current_path}/{subfolder_name}")
                };

                // Push new folder onto stack
                self.stack
                    .push((new_path.clone(), subfolder.secrets.keys()));
                self.folder_stack
                    .push((new_path, subfolder, subfolder.subfolders.iter()));
                continue;
            }

            // No more subfolders, pop the stack
            self.stack.pop();
            self.folder_stack.pop();

            if self.stack.is_empty() || self.folder_stack.is_empty() {
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
// Folder - Hierarchical container for secrets
// ============================================================================

/// A folder containing secrets and subfolders
#[derive(Debug, Clone, Encode, Decode)]
pub struct Folder {
    /// Folder name (empty string for root)
    pub name: String,

    /// Which encryption domain this folder belongs to
    /// - 0 = default domain (master key)
    /// - N > 0 = custom domain (requires separate password)
    pub encryption_domain: u32,

    /// Secrets in this folder (key -> history of values)
    pub secrets: BTreeMap<String, Vec<SecretEntry>>,

    /// Subfolders
    pub subfolders: BTreeMap<String, Folder>,
}

impl Folder {
    /// Create a new root folder (domain 0)
    pub const fn new_root() -> Self {
        Self {
            name: String::new(),
            encryption_domain: 0,
            secrets: BTreeMap::new(),
            subfolders: BTreeMap::new(),
        }
    }

    /// Create a new named folder
    pub const fn new(name: String, encryption_domain: u32) -> Self {
        Self {
            name,
            encryption_domain,
            secrets: BTreeMap::new(),
            subfolders: BTreeMap::new(),
        }
    }
}

// ============================================================================
// Secret Entry - A versioned secret with metadata
// ============================================================================

/// A secret entry with timestamp and metadata
#[derive(Debug, Clone, Encode, Decode)]
pub struct SecretEntry {
    /// The secret value (may be plain or encrypted folder)
    pub value: SecretValue,

    /// When this version was created (seconds since UNIX epoch)
    pub timestamp: u64,

    /// Type of secret
    pub secret_type: SecretType,

    /// Optional metadata (for future file storage, etc.)
    pub metadata: HashMap<String, String>,
}

impl SecretEntry {
    /// Create a new secret entry with plain value
    pub fn new_plain(
        encrypted_value: EncryptedValue,
        timestamp: u64,
        encryption_domain: u32,
    ) -> Self {
        Self {
            value: SecretValue::Plain {
                data: encrypted_value,
                encryption_domain,
            },
            timestamp,
            secret_type: SecretType::Utf8String,
            metadata: HashMap::new(),
        }
    }

    /// Get the encrypted value from this entry
    pub const fn encrypted_value(&self) -> &EncryptedValue {
        match &self.value {
            SecretValue::Plain { data, .. } => data,
            // For encrypted folders, we return the placeholder
            // (actual folder decryption will be handled separately)
            SecretValue::EncryptedFolder {
                placeholder_data, ..
            } => placeholder_data,
        }
    }
}

// ============================================================================
// Secret Value - Either plain data or encrypted folder
// ============================================================================

/// The actual secret value
#[derive(Debug, Clone, Encode, Decode)]
pub enum SecretValue {
    /// Regular secret encrypted with domain key
    /// - Domain 0: encrypted with master key (like V4)
    /// - Domain N: encrypted with custom domain key
    Plain {
        /// The encrypted data
        data: EncryptedValue,

        /// Which encryption domain encrypts this data
        encryption_domain: u32,
    },

    /// Locked folder disguised as a regular secret
    /// When locked, CLI shows `placeholder_data`
    /// When unlocked, `encrypted_folder` is decrypted and merged into parent
    EncryptedFolder {
        /// What to show when locked (appears as regular secret value)
        placeholder_data: EncryptedValue,

        /// The actual folder serialized and encrypted with domain key
        encrypted_folder: Vec<u8>,

        /// Which encryption domain encrypts this folder
        encryption_domain: u32,
    },
}

impl SecretValue {
    /// Check if this is an encrypted folder
    pub const fn is_encrypted_folder(&self) -> bool {
        matches!(self, Self::EncryptedFolder { .. })
    }

    /// Get the encryption domain for this value
    pub const fn encryption_domain(&self) -> u32 {
        match self {
            Self::Plain {
                encryption_domain, ..
            }
            | Self::EncryptedFolder {
                encryption_domain, ..
            } => *encryption_domain,
        }
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
    for entries in folder.secrets.values_mut() {
        entries.sort_by_key(|e| e.timestamp);
    }

    for subfolder in folder.subfolders.values_mut() {
        sort_folder_entries(subfolder);
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

        root.secrets.insert(key, secrets);
    }

    StorageV5 { root }
}

/// Convert V4 `ValueEntry` to V5 `SecretEntry`
fn value_entry_to_secret(entry: ValueEntry) -> SecretEntry {
    SecretEntry {
        value: SecretValue::Plain {
            data: entry.value,
            encryption_domain: 0, // Default domain
        },
        timestamp: entry.timestamp,
        secret_type: SecretType::Utf8String,
        metadata: HashMap::new(),
    }
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

        assert!(deserialized.root.secrets.is_empty());
        assert!(deserialized.root.subfolders.is_empty());
    }

    #[test]
    fn test_simple_secret_v5() {
        let mut storage = StorageV5::new();
        let test_value = EncryptedValue::from_ciphertext(b"test_value".to_vec());
        storage.root.secrets.insert(
            "test_key".to_string(),
            vec![SecretEntry::new_plain(test_value, 12345, 0)],
        );

        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        assert_eq!(deserialized.root.secrets.len(), 1);
        let entry = &deserialized.root.secrets["test_key"][0];

        match &entry.value {
            SecretValue::Plain {
                data,
                encryption_domain,
            } => {
                assert_eq!(data.as_bytes(), b"test_value");
                assert_eq!(*encryption_domain, 0);
            }
            _ => panic!("Expected Plain variant"),
        }
    }

    #[test]
    fn test_folder_structure() {
        let mut storage = StorageV5::new();

        // Add a subfolder
        let mut subfolder = Folder::new("work".to_string(), 0);
        let api_key_value = EncryptedValue::from_ciphertext(b"secret123".to_vec());
        subfolder.secrets.insert(
            "api_key".to_string(),
            vec![SecretEntry::new_plain(api_key_value, 12345, 0)],
        );

        storage
            .root
            .subfolders
            .insert("work".to_string(), subfolder);

        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        assert_eq!(deserialized.root.subfolders.len(), 1);
        assert!(deserialized.root.subfolders.contains_key("work"));
        assert_eq!(deserialized.root.subfolders["work"].secrets.len(), 1);
    }

    #[test]
    fn test_encrypted_folder_variant() {
        let mut storage = StorageV5::new();

        // Create an encrypted folder secret
        let placeholder = EncryptedValue::from_ciphertext(b"placeholder".to_vec());
        storage.root.secrets.insert(
            "secret_folder".to_string(),
            vec![SecretEntry {
                value: SecretValue::EncryptedFolder {
                    placeholder_data: placeholder,
                    encrypted_folder: vec![1, 2, 3, 4], // Mock encrypted data
                    encryption_domain: 1,
                },
                timestamp: 12345,
                secret_type: SecretType::Utf8String,
                metadata: HashMap::new(),
            }],
        );

        let serialized = serialize_storage_v5_to_vec(&storage).unwrap();
        let deserialized = deserialize_storage_v5_from_slice(&serialized).unwrap();

        let entry = &deserialized.root.secrets["secret_folder"][0];
        assert!(entry.value.is_encrypted_folder());
        assert_eq!(entry.value.encryption_domain(), 1);
    }

    #[test]
    fn test_v4_migration() {
        let mut v4 = StorageV4::new();
        v4.put("key1".to_string(), "value1".into());
        v4.put("key2".to_string(), "value2".into());

        let v5 = migrate_v4_to_v5(v4);

        assert_eq!(v5.root.secrets.len(), 2);
        assert!(v5.root.secrets.contains_key("key1"));
        assert!(v5.root.secrets.contains_key("key2"));
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
