# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
pre-1.0 [Semantic Versioning](https://semver.org/) (breaking changes bump the
minor; features and fixes bump the patch).

## [Unreleased]

### Added
- **Multi-factor unlock (policy vaults).** A store can now require more than one
  secret, combined by a boolean access policy.
  - New stores are created as version-8 policy vaults with a single `password`
    factor. Legacy version-7 password stores still open with their password and
    are **upgraded automatically**: on open they are converted to a policy vault
    in memory (the unlock password becomes the `primary` factor and secrets are
    re-encrypted under a fresh random key). The on-disk file is rewritten in the
    new format lazily, on the next write — after copying the untouched original to
    `<file>.bak`; rcypher notifies you both on open and when the backup is made. A
    read-only session leaves the file unchanged.
  - In-store `auth` commands while unlocked: `auth factor {list, add password
    NAME, remove NAME}` and `auth policy {show, set EXPR}` (e.g. `p1 or (p2 and
    yk)`). Enrolling a password rejects one that duplicates an existing factor's.
  - On open, rcypher asks for a password in a loop (you don't pick a factor):
    each entry is matched against the factors and the loop continues until the
    policy is satisfied.
  - The payload is encrypted under a random data-encryption key (DEK) that is
    monotone-secret-shared across the policy tree; changing the policy or adding
    a factor never re-encrypts stored secrets (the DEK is stable; only the IV
    changes per save). See `docs/auth-protocol.md`.
- **Password strength check.** Creating a store or enrolling a password factor
  scores the password with zxcvbn (NIST-aligned: guess-resistance and pattern
  detection, no composition rules). A weak password shows a prominent warning
  with an estimated crack time and requires a double confirmation; a trivially
  guessable one — including the factor name itself — is refused outright.

### Security
- A factor's password may not be too similar to its (cleartext) name — it must be
  at least twice as long as any shared prefix — preventing a password from being
  exposed as a label, including the mix-up of typing a password where the factor
  name belongs.
- Transient secret-shares and recovered per-factor auth-keys are now held in
  zeroizing buffers throughout the unlock/secret-sharing path, so no share or
  auth-key lingers in memory un-wiped.
- Codebase-wide zeroization audit: every function returning sensitive data now
  returns it wrapped in `Zeroizing` (decrypted values and payloads, passwords,
  derived keys, secret-shares, serialized store payloads), and intermediate
  copies are eliminated — key material is split directly into zeroizing buffers
  (no Copy-array left behind), and `EncryptedValue::decrypt` validates UTF-8 by
  borrowing so plaintext is never moved into an un-zeroized buffer. `FactorSecret`
  and the CLI password prompts now hold their secrets zeroizing.

## [0.2.0] - 2026-06-20

### Added
- **Reusable library for bring-your-own-format encryption.** `rcypher` is now a
  library crate: another application can encrypt and sign its own serialized data
  with the same envelope the CLI uses (Argon2id → AES-256-CBC → HMAC-SHA256,
  encrypt-then-MAC). New public API:
  - `EncryptionKey::for_data` — derive a key from the salt embedded in an
    in-memory blob, enabling in-memory decryption without a temporary file.
  - `save_encrypted` / `load_encrypted` — format-agnostic atomic encrypted file
    I/O, available even without the bundled storage format.
  - `Cypher::with_trace_detection` — opt out of the anti-debug check for
    legitimately-traced host processes.
  - `examples/custom_format.rs`, crate-level docs, and a README "Use as a
    library" section.
- `storage` cargo feature (default-on) gating the bundled key-value format, so
  the crypto envelope can be depended on without `regex` (`default-features =
  false`).
- **macOS support.** The library and CLI now build and run on macOS (Intel and
  Apple Silicon) as well as Linux, preserving the security model with platform
  equivalents — a `setitimer(ITIMER_REAL)` kernel-signal watchdog and continuous
  `sysctl`/`P_TRACED` debugger detection (plus `PT_DENY_ATTACH`). Prebuilt
  binaries are published for Linux (x86_64 + ARM64) and macOS (Intel + Apple
  Silicon), and `scripts/install.sh` installs the right one (`curl … | bash`).
- Anti-debugging (ptrace) self-protection and a security watchdog timer that
  exits an idle or stalled interactive session.
- Core-dump disabling at startup, preventing plaintext secrets from reaching a
  crash dump.
- Master-password confirmation prompt with an irreversibility warning when
  creating a new store.
- `rcypher --version` reports the crate version.

### Changed
- Reorganized into a Cargo workspace: the `rcypher` library plus the
  `rcypher-cli` binary (the installed executable is still named `rcypher`).
  Install the CLI with `cargo install rcypher-cli`; depend on the library with
  `cargo add rcypher`.
- `serialize_storage` returns `Result` instead of panicking on oversized input.
- License is declared as `Apache-2.0`, matching the bundled `LICENSE`.

### Removed
- Support for the legacy pre-Argon2 encryption format.

### Security
- Removed an all-zero-key footgun (the unused `EncryptionKey: Default`) and the
  implicit `EncryptedValue: From<&str>` constructor that could silently store
  plaintext as ciphertext in debug builds; the latter is replaced by an explicit
  `#[doc(hidden)] from_plaintext_unchecked`.

[0.2.0]: https://github.com/justpresident/rcypher/compare/v0.1.1...v0.2.0
