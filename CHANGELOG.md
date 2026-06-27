# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
pre-1.0 [Semantic Versioning](https://semver.org/) (breaking changes bump the
minor; features and fixes bump the patch).

## [0.3.0] - 2026-06-27

### Added
- **Multi-factor unlock.** A store can now require more than one secret, combined
  by a boolean access policy.
  - New stores use the version-8 format with a single `password` factor. Legacy
    version-7 password stores still open with their password and are **upgraded
    automatically**: on open they are converted in memory (the unlock password
    becomes the `primary` factor and secrets are re-encrypted under a fresh random
    key). The on-disk file is rewritten in the new format lazily, on the next
    write — after copying the untouched original to `<file>.bak`; rcypher notifies
    you both on open and when the backup is made. A read-only session leaves the
    file unchanged.
  - In-store `auth` commands while unlocked: `auth factor {list, add password
    NAME, add fido2 NAME, remove NAME}` and `auth policy {show, set EXPR}` (e.g.
    `p1 or (p2 and key)`). Enrolling a password rejects one that duplicates an
    existing factor's.
  - On open, rcypher asks for a password in a loop (you don't pick a factor):
    each entry is matched against the factors and the loop continues until the
    policy is satisfied.
  - The payload is encrypted under a random data-encryption key (DEK) that is
    monotone-secret-shared across the policy tree; changing the policy or adding
    a factor never re-encrypts stored secrets (the DEK is stable; only the IV
    changes per save). See `docs/auth-protocol.md`.
- **FIDO2 security-key factor.** A factor can be a hardware authenticator (any
  FIDO2 key with the `hmac-secret` extension) instead of a password —
  `auth factor add fido2 NAME`, and a new store offers to enrol one at creation.
  Touch-vs-PIN is auto-detected from the key (no PIN prompt when none is set), and
  the verification mode used at enrolment is bound into the factor and replayed at
  unlock. The factor's key is derived from the authenticator's per-credential
  `hmac-secret`, so nothing key-derived touches disk. Built into the CLI by
  default; the opt-in `fido2` feature in the library (a `--no-default-features` CLI
  build omits it, for hosts without the USB-HID build dependencies).
- **Reusable CLI plumbing (`cli` feature).** The interactive terminal helpers now
  live in the library behind a `cli` feature (`rcypher::cli`): password/PIN prompts
  and direct-to-tty secret output, the zxcvbn password-strength gate, and the
  policy-unlock prompt loop (`prompt_until_unlocked`, with a pluggable
  `UnlockProgress` for a spinner). Other apps can build an rcypher-like CLI on top;
  `rcypher-cli` is now a thin shell over it. Pulls `rpassword` + `zxcvbn` only when
  the feature is enabled.
- **Password strength check.** Creating a store or enrolling a password factor
  scores the password with zxcvbn (NIST-aligned: guess-resistance and pattern
  detection, no composition rules). A weak password shows a prominent warning
  with an estimated crack time and requires a double confirmation; a trivially
  guessable one — including the factor name itself — is refused outright.

### Changed
- **Store-file formats are handled by a new `container` module (library API).**
  Each on-disk format implements a `ContainerCodec` (its wire layout, unlock, and
  payload decryption); `FileContainer` is the registry that probes the leading tag
  and dispatches (`FileContainerV7` legacy, `FileContainerV8` policy vault). The
  AEAD envelope is shared across formats and only the keyslot scheme is per-format,
  so a future format is a new submodule plus a dispatch arm. `ContainerFormat` is
  renamed `FileContainerFormat`; the keyslot vault (`PolicyVault`) no longer does
  file I/O (reading/writing a vault file goes through the container layer).
  Removed `parse_policy_vault`, `serialize_policy_header`, and `ParsedVault`.

### Fixed
- The terminal is restored to normal (cooked) mode when the interactive session
  exits on the idle timeout or a security trip. Those exits go through the watchdog
  thread's `process::exit`, which skipped the line editor's terminal cleanup and
  could leave the shell without echo or working line editing.

### Security
- **The version-8 keyslot header is now authenticated.** The keyslot metadata
  (policy tree, factor table, KDF params, and wrapped shares) is bound to the
  encrypted payload as associated data, so its integrity tag also covers the
  policy. This prevents an attacker who can modify the at-rest file from
  downgrading the unlock policy — e.g. stripping `p1 OR (p2 AND yk)` down to `p1`
  alone (OR replicates the data key to each branch), which previously unlocked
  with a single factor and silently persisted the weakened policy on the next
  save. The on-disk layout is unchanged.
- **Factor names are encrypted at rest.** Each factor's id is its human name
  encrypted under the data key, so a version-8 file no longer leaks the labels
  (`recovery`, `work-bank`, …) to anyone who can read it; the names are recovered
  and shown only after the store is unlocked. The policy *shape* (AND/OR structure
  and factor count) and each factor's *kind* and KDF params remain visible, as the
  unlock flow needs them. Pre-unlock prompts are generic (no names or policy
  expression). The on-disk layout is unchanged.
- A factor's password may not be too similar to its name — it must be at least
  twice as long as any shared prefix — a weak password close to the factor name is
  a guessable choice, and this also catches the mix-up of typing a password where
  the factor name belongs.
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

[0.3.0]: https://github.com/justpresident/rcypher/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/justpresident/rcypher/compare/v0.1.1...v0.2.0
