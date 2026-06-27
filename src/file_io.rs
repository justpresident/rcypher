use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::crypto::Cypher;

/// Encrypts `bytes` with `cypher` and writes the resulting self-contained blob
/// to `path` atomically.
///
/// The plaintext is encrypted in memory, then written to a temporary file in the
/// same directory and `persist`ed over `path`, so a crash or concurrent reader
/// never observes a partially written file. This is format-agnostic: bring your
/// own serialization and store any bytes you like.
pub fn save_encrypted(cypher: &Cypher, bytes: &[u8], path: &Path) -> Result<()> {
    write_atomic(path, &cypher.encrypt(bytes)?)
}

/// Atomically writes `bytes` to `path`: a temp file in the same directory, then a
/// rename, so a crash or concurrent reader never observes a partial file.
///
/// `parent()` is `Some("")` for a bare filename and `None` only for the filesystem
/// root; in both cases the temp file should land in the current directory
/// (alongside the destination), so fall back to ".".
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut temp = NamedTempFile::new_in(dir)?;
    temp.write_all(bytes)?;
    temp.persist(path)?;
    Ok(())
}

/// Reads and decrypts a blob previously written by [`save_encrypted`] (or any
/// `Cypher::encrypt` output) from `path`.
///
/// The returned plaintext is wrapped in [`Zeroizing`] so it is wiped from memory
/// when dropped.
pub fn load_encrypted(cypher: &Cypher, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let encrypted = fs::read(path)?;
    cypher.decrypt(&encrypted)
}
