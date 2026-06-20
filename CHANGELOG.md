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
    factor; existing version-7 password stores keep opening through the legacy
    path unchanged.
  - In-store commands while unlocked: `factors`, `enroll password NAME`,
    `policy show`, `policy set EXPR` (e.g. `p1 or (p2 and yk)`), and
    `remove factor NAME`.
  - On open, rcypher prints the policy and prompts only for as many factors as
    are needed to satisfy it.
  - The payload is encrypted under a random data-encryption key (DEK) that is
    monotone-secret-shared across the policy tree; changing the policy or adding
    a factor never re-encrypts stored secrets (the DEK is stable; only the IV
    changes per save). See `docs/auth-protocol.md`.
- **Weak-policy warning.** rcypher warns — at `policy set` time and on open —
  when a single password factor alone can unlock a multi-factor store, since an
  `or` branch is only as strong as its weakest satisfying set.

### Security
- Transient secret-shares and recovered per-factor auth-keys are now held in
  zeroizing buffers throughout the unlock/secret-sharing path, so no share or
  auth-key lingers in memory un-wiped.

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
