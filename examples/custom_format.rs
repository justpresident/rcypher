//! Using `rcypher` as a library to encrypt and sign an application's **own**
//! data format, interoperating with the exact same envelope the `rcypher` CLI
//! writes (Argon2id key derivation → AES-256-CBC → HMAC-SHA256, encrypt-then-MAC).
//!
//! rcypher knows nothing about the shape of your data — you bring your own
//! serialization and hand it raw bytes. Run with:
//!
//! ```sh
//! cargo run -p rcypher --example custom_format
//! ```

use anyhow::Result;
use bincode::{Decode, Encode};
use rcypher::{Cypher, CypherVersion, EncryptionKey, load_encrypted, save_encrypted};

// An application-defined record. Any serialization works — here we use bincode,
// but it could just as well be serde_json, protobuf, or a hand-rolled format.
#[derive(Debug, PartialEq, Eq, Encode, Decode)]
struct AppSecret {
    label: String,
    token: String,
    rotated_at: u64,
}

fn main() -> Result<()> {
    let password = "correct horse battery staple";
    let cfg = bincode::config::standard();

    let secret = AppSecret {
        label: "prod-api".to_string(),
        token: "sk-live-abc123".to_string(),
        rotated_at: 1_750_000_000,
    };

    // --- Encrypt the app's own bytes, entirely in memory ---
    // Deriving from a password generates a fresh random salt; it is written into
    // the blob's header so decryption can recover it later.
    let key = EncryptionKey::from_password(CypherVersion::default(), password)?;
    let cypher = Cypher::new(key);
    // For a host process that is legitimately traced (profiler, supervising
    // debugger), opt out of the anti-debug check with:
    //   Cypher::with_trace_detection(key, false)

    let plaintext = bincode::encode_to_vec(&secret, cfg)?;
    let blob = cypher.encrypt(&plaintext)?; // [version|salt|iv|pad | ciphertext | hmac]
    println!(
        "encrypted {} bytes of app data into a {}-byte self-contained blob",
        plaintext.len(),
        blob.len()
    );

    // --- Decrypt in memory, deriving the key from the blob's embedded salt ---
    // No file needed: `for_data` reads the salt back out of the header, so the
    // re-derived key matches the one used to encrypt.
    let reopen_key = EncryptionKey::for_data(password, &blob)?;
    let recovered = Cypher::new(reopen_key).decrypt(&blob)?;
    let (recovered, _): (AppSecret, _) = bincode::decode_from_slice(&recovered, cfg)?;
    assert_eq!(recovered, secret);
    println!("in-memory round-trip OK: {recovered:?}");

    // --- Or persist to disk with the same atomic encrypted write the CLI uses ---
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("app.secret");
    save_encrypted(&cypher, &plaintext, &path)?;

    // Re-open later: derive the key from the file header, then load + decrypt.
    let file_key = EncryptionKey::for_file(password, &path)?;
    let loaded = load_encrypted(&Cypher::new(file_key), &path)?;
    let (from_disk, _): (AppSecret, _) = bincode::decode_from_slice(&loaded, cfg)?;
    assert_eq!(from_disk, secret);
    println!("file round-trip OK at {}", path.display());

    Ok(())
}
