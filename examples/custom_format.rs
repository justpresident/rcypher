//! Using `rcypher` as a library to encrypt an application's **own** data format —
//! at two levels:
//!
//! 1. **The raw AEAD envelope** ([`Cypher`] + [`EncryptionKey`]): you manage the
//!    key and the bytes, interoperating with the exact same envelope the `rcypher`
//!    CLI writes (Argon2id → AES-256-CBC → HMAC-SHA256, encrypt-then-MAC).
//! 2. **The high-level store facade** ([`DataContainer`] + [`UnlockedContainer`] /
//!    [`LockedContainer`]): implement one trait for your type and get a password-
//!    or **multi-factor**-protected, versioned, atomically-saved store — you never
//!    touch keys, salts, or the file format, and a future on-disk format is adopted
//!    without any change here.
//!
//! rcypher knows nothing about the shape of your data — you bring your own
//! serialization and hand it raw bytes. Run with:
//!
//! ```sh
//! cargo run -p rcypher --example custom_format
//! ```

use anyhow::Result;
use bincode::{Decode, Encode};
use rcypher::{
    Cypher, CypherVersion, DataContainer, EncryptionKey, LockedContainer, UnlockedContainer,
    Zeroizing, load_encrypted, save_encrypted,
};

// An application-defined record. Any serialization works — here we use bincode,
// but it could just as well be serde_json, protobuf, or a hand-rolled format.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct AppSecret {
    label: String,
    token: String,
    rotated_at: u64,
}

const CFG: bincode::config::Configuration = bincode::config::standard();

fn main() -> Result<()> {
    let password = "correct horse battery staple";

    let secret = AppSecret {
        label: "prod-api".to_string(),
        token: "sk-live-abc123".to_string(),
        rotated_at: 1_750_000_000,
    };
    let dir = tempfile::tempdir()?;

    raw_envelope(&secret, password, dir.path())?;
    multi_factor_store(&secret, password, dir.path())?;
    Ok(())
}

/// Level 1 — the raw envelope: you hold the key and the bytes yourself.
fn raw_envelope(secret: &AppSecret, password: &str, dir: &std::path::Path) -> Result<()> {
    println!("== raw AEAD envelope ==");

    // --- Encrypt the app's own bytes, entirely in memory ---
    // Deriving from a password generates a fresh random salt; it is written into
    // the blob's header so decryption can recover it later.
    let key = EncryptionKey::from_password(CypherVersion::default(), password)?;
    let cypher = Cypher::new(key);
    // For a host process that is legitimately traced (profiler, supervising
    // debugger), opt out of the anti-debug check with:
    //   Cypher::with_trace_detection(key, false)

    let plaintext = bincode::encode_to_vec(secret, CFG)?;
    let blob = cypher.encrypt(&plaintext)?; // [version|salt|iv|pad | ciphertext | hmac]
    println!(
        "  encrypted {} bytes of app data into a {}-byte self-contained blob",
        plaintext.len(),
        blob.len()
    );

    // --- Decrypt in memory, deriving the key from the blob's embedded salt ---
    // No file needed: `for_data` reads the salt back out of the header, so the
    // re-derived key matches the one used to encrypt.
    let reopen_key = EncryptionKey::for_data(password, &blob)?;
    let recovered = Cypher::new(reopen_key).decrypt(&blob)?;
    let (recovered, _): (AppSecret, _) = bincode::decode_from_slice(&recovered, CFG)?;
    assert_eq!(&recovered, secret);
    println!("  in-memory round-trip OK: {recovered:?}");

    // --- Or persist to disk with the same atomic encrypted write the CLI uses ---
    let path = dir.join("app.secret");
    save_encrypted(&cypher, &plaintext, &path)?;

    // Re-open later: derive the key from the file header, then load + decrypt.
    let file_key = EncryptionKey::for_file(password, &path)?;
    let loaded = load_encrypted(&Cypher::new(file_key), &path)?;
    let (from_disk, _): (AppSecret, _) = bincode::decode_from_slice(&loaded, CFG)?;
    assert_eq!(&from_disk, secret);
    println!("  file round-trip OK at {}", path.display());
    Ok(())
}

// Teach the container how to (de)serialize `AppSecret`, and the library handles
// the lock, the AEAD envelope, the file, and version upgrades for you. `AppSecret`
// does no inner encryption of its own, so `rekey`/`verify` are explicit no-ops.
impl DataContainer for AppSecret {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(bincode::encode_to_vec(self, CFG)?))
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::decode_from_slice(bytes, CFG)?.0)
    }
    fn rekey(&mut self, _from: &Cypher, _to: &Cypher) -> Result<()> {
        Ok(())
    }
    fn verify(&self, _cypher: &Cypher) -> Result<()> {
        Ok(())
    }
}

/// Level 2 — the store facade: a multi-factor-protected, atomically-saved store
/// over your own [`DataContainer`], with no key or format handling on your side.
fn multi_factor_store(secret: &AppSecret, password: &str, dir: &std::path::Path) -> Result<()> {
    println!("== multi-factor store facade ==");
    let path = dir.join("app.store");

    // Create a store holding the secret, locked by a `primary` password factor,
    // then add a `recovery` password and accept EITHER one — a backup way in that
    // doesn't lock you out if the primary password is lost. Adding a factor or
    // changing the policy never re-encrypts the payload (the data key is stable).
    let mut store = UnlockedContainer::create("primary", password, secret.clone())?;
    store.enroll_password("recovery", "another-strong-passphrase-42")?;
    store.set_policy("primary or recovery")?;
    store.save(&path)?;
    println!("  saved; unlock policy = {}", store.policy_expr());

    // Re-open: `load` is format-agnostic (a legacy file would be upgraded on
    // unlock). Satisfy the lock with EITHER password, then decrypt into `AppSecret`.
    let mut locked = LockedContainer::load(&path)?;
    assert!(locked.try_password("another-strong-passphrase-42")?); // the recovery branch
    assert!(locked.can_unlock());
    let opened = locked.unlock::<AppSecret>()?;
    assert_eq!(opened.data(), secret);
    println!("  unlocked via the recovery factor: {:?}", opened.data());
    Ok(())
}
