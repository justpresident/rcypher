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

/// Atomically writes `bytes` to `path` (see [`persist_atomically`]).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    persist_atomically(path, |file| {
        file.write_all(bytes)?;
        Ok(())
    })
}

/// Durably and atomically replaces `path` with whatever `fill` writes.
///
/// A fresh, private (owner-only) temporary file is created in the *same directory*
/// as `path`; `fill` streams the new contents into it; then the temp is flushed
/// and fsync'd, atomically renamed over `path`, and the directory entry itself
/// fsync'd. A crash therefore leaves either the previous file or the complete new
/// one — never a truncated, empty, or missing file. If `fill` errors, `path` is
/// left untouched and the temp is removed.
///
/// Because `fill` is handed the raw file, callers can stream output of any size
/// without buffering it all in memory; `write_atomic` is the in-memory case.
///
/// `parent()` is `Some("")` for a bare filename and `None` only for the filesystem
/// root; in both cases the temp file should land in the current directory
/// (alongside the destination), so fall back to ".".
pub fn persist_atomically<F>(path: &Path, fill: F) -> Result<()>
where
    F: FnOnce(&mut fs::File) -> Result<()>,
{
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut temp = NamedTempFile::new_in(dir)?;
    set_owner_only(temp.as_file())?;
    fill(temp.as_file_mut())?;
    // Durably persist the contents before the rename, then the rename itself, so
    // the new directory entry can never point at unflushed data after a crash.
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    sync_dir(dir)?;
    Ok(())
}

/// Restricts the temp file to its owner (`0600`) before any data is written, so a
/// decrypted or sensitive payload is never briefly world-readable. (`NamedTempFile`
/// already creates at `0600` on Unix; this makes the guarantee explicit and is a
/// no-op elsewhere.)
#[cfg(unix)]
fn set_owner_only(file: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_file: &fs::File) -> Result<()> {
    Ok(())
}

/// fsyncs `dir` so a rename into it is itself durable: without this the file
/// contents can reach disk while the directory entry naming them does not.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Non-Unix platforms cannot fsync a directory handle; the rename is relied upon
/// for atomicity and the contents are already fsync'd above.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<()> {
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
