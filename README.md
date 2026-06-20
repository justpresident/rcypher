![CI](https://github.com/justpresident/rcypher/actions/workflows/rust.yml/badge.svg)
![Coverage](https://raw.githubusercontent.com/justpresident/rcypher/main/.github/badges/coverage.svg)
# rcypher

rcypher is a minimal, offline, file-based password storage and encryption tool for technical users.
It is designed to protect secrets at rest using modern cryptography, while remaining simple and auditable.

> ⚠️ Not audited. Use at your own risk.

# Usage

`rcypher` operates in two main modes:

1. **Encrypted key-value storage** (default)
2. **Full file encryption / decryption**

## Encrypted storage (default)

When no `--encrypt` or `--decrypt` flags are provided, `rcypher` treats the given file as an encrypted key-value storage.

If the file does not exist, it will be created.

```sh
$ rcypher secrets.db
Enter Password for secrets.db:
cypher > help
USER COMMANDS:
  put KEY VAL     - Store a key-value pair
  get REGEXP      - Get values for keys matching regexp
  copy KEY        - Copy key value into system clipboard
  history KEY     - Show history of changes for a key
  search REGEXP   - Search for keys matching regexp
  del|rm KEY      - Delete a key
  help            - Show this help
```
![demo](demo.gif)
Secrets are:

* encrypted at rest

* never printed to stdout

* written directly to the terminal (TTY)

## Encrypting/Decrypting a file

To encrypt an arbitrary file:

```(sh)
# To encrypt:
$ rcypher --encrypt input.txt --output input.txt.enc
Enter Password for input.txt:
# To decrypt:
$ rcypher --decrypt input.txt.enc --output input.txt
Enter Password for input.txt.enc:
```

If --output is omitted, resulting file is written to stdout:
```(sh)
$ rcypher --encrypt input.txt > input.txt.enc
$ rcypher --decrypt input.txt.enc > input.txt
```

## Upgrading storage format

When opening an encrypted storage file with an outdated encryption format, `rcypher` automatically detects this and prompts you to upgrade:

```sh
$ rcypher secrets.db
Enter Password for secrets.db:
File is encrypted with deprecated algorithm.
Would you like to upgrade it now? (y/n): y
```

The file is upgraded in place using the latest encryption format (Argon2id + AES-256 + HMAC).

You can also upgrade manually without entering interactive mode:
```sh
$ rcypher --upgrade-storage secrets.db
Enter Password for secrets.db:
```

## Merging conflicting storage files

If you synchronize your storage file across devices (e.g., via Dropbox, Syncthing), conflicts may occur when changes are made on different devices. The `--update-with` option helps merge these conflicts:

```sh
$ rcypher secrets.db --update-with "secrets (conflicted copy).db"
Enter Password for secrets.db:

Found 3 keys with different values:
  [NEW] api_token
    New: sk-abc123def456 (2025-12-19 14:30:00)
  [CONFLICT] github_pat
    Current: ghp_old_token (2025-12-18 10:15:00)
    Update:  ghp_new_token (2025-12-19 14:25:00)
  [CONFLICT] db_password
    Current: old_pass (2025-12-17 08:00:00)
    Update:  new_pass (2025-12-19 14:28:00)

Summary: 1 new key, 2 conflicts

Apply updates? (a)ll at once, (i)nteractive, (c)ancel [a/i/c]:
```

**Merge modes:**
- **(a)ll at once**: Apply all updates from the conflicted file automatically
- **(i)nteractive**: Review each change individually, accepting or rejecting one by one
- **(c)ancel**: Exit without making any changes

**Security note**: Values are displayed during comparison to help you make informed decisions. Passwords and sensitive data are written directly to the terminal (TTY), not to stdout, preventing accidental logging. Use `--insecure-stdout` only in testing environments.

---

# Use as a library

This repository is a Cargo workspace:

* **`rcypher`** — the reusable encryption library (this is the published library crate).
* **`rcypher-cli`** — the command-line tool described above, built on top of it.

Another application can encrypt and sign **its own data format** with the exact
same envelope rcypher uses (Argon2id → AES-256-CBC → HMAC-SHA256, encrypt-then-MAC),
and read those files back. Add the dependency:

```toml
[dependencies]
rcypher = "0.1"

# crypto envelope only, without rcypher's bundled key-value storage format:
# rcypher = { version = "0.1", default-features = false }
```

Bring your own serialization and hand rcypher the bytes:

```rust
use rcypher::{Cypher, CypherVersion, EncryptionKey};

// Encrypt your own bytes (a fresh random salt is embedded in the blob header):
let cypher = Cypher::new(EncryptionKey::from_password(CypherVersion::default(), "pw")?);
let blob = cypher.encrypt(my_serialized_bytes)?;

// Decrypt in memory — the key is re-derived from the salt inside the blob:
let reopened = Cypher::new(EncryptionKey::for_data("pw", &blob)?);
let plaintext = reopened.decrypt(&blob)?;
```

The blob is self-contained (`[ header | ciphertext | hmac ]`), so it round-trips
from memory (`encrypt`/`decrypt` + `EncryptionKey::for_data`) or from disk
(`save_encrypted`/`load_encrypted` + `EncryptionKey::for_file`). See
[`examples/custom_format.rs`](examples/custom_format.rs) for a complete example,
and the **Cryptography Overview** below for the construction details.

`Cypher` refuses to operate while a debugger is attached by default; for a
legitimately-traced host process, opt out with `Cypher::with_trace_detection(key, false)`.

## Installing the CLI

The quickest way (Linux x86_64) — download the prebuilt binary, verify its
checksum, and put it on your `PATH`:

```sh
curl -fsSL https://raw.githubusercontent.com/justpresident/rcypher/main/scripts/install.sh | bash
```

It picks the binary from the
[latest release](https://github.com/justpresident/rcypher/releases/latest),
verifies its checksum, installs to `/usr/local/bin` (or `~/.local/bin` if that
isn't writable), and — if that directory isn't on your `PATH` — adds it to your
shell's rc file. Override the location with `RCYPHER_INSTALL_DIR=...`, pin a tag
with `RCYPHER_VERSION=v0.2.0`, or skip the rc edit with `RCYPHER_NO_MODIFY_PATH=1`.
Prefer to read before you pipe? It's [`scripts/install.sh`](scripts/install.sh).

Or via cargo (any platform with a Rust toolchain):

```sh
cargo install rcypher-cli   # installs the `rcypher` binary
```

Prebuilt binaries cover **Linux** (x86_64 and ARM64, static musl) and **macOS**
(Intel + Apple Silicon). Windows isn't supported — use WSL or the
[library](#use-as-a-library).

---

# Features

* Offline, single-file encrypted storage

* Encryption key derivation using Argon2id
 * Argon2id is a winner in a "password Hashing Competition 2015", see https://www.password-hashing.net/ for details
 * Random SALT is generated on every encryption operation

* Strong authenticated encryption with AES-256-CBC-HMAC-SHA256
 * **Quantum resistant**, widely used in TLS, IPsec, PGP and many other security tools and protocols
 * Random IV is generated on every encrypt operation
 * Secure constant time HMAC check to avoid timing attacks
 * With encrypt-then-hmac approach, see https://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html for details

* Secure password input (no terminal echo)

* Secure terminal output using raw TTY access (bypasses stdout)

* Automatic zeroing of sensitive memory

* Optional clipboard copy with warnings

* Minimal dependencies and attack surface

* Explicit file format versioning

* Automatic detection and upgrade of legacy storage formats

* Conflict resolution for synchronized files (e.g., Dropbox conflicts)

# Threat Model

rcypher is designed to protect secrets:

✔ against **offline attackers** who obtain the encrypted file

✔ against accidental disclosure via plaintext files

✔ against tampering and corruption of encrypted data

It **does not** protect against:

❌ a compromised operating system

❌ malware, keyloggers, or malicious clipboard managers

❌ privileged (root) attackers

❌ swap attacks or hibernation

❌ shoulder-surfing or screen recording

**Partial protection** (defense-in-depth, not security guarantees):

⚠️ **Debugger attachment**: ptrace-based protection prevents casual debugging but can be bypassed by privileged attackers or kernel-level tools

⚠️ **Core dumps**: disabled at startup to prevent crash dumps, but doesn't protect against forced dumps or swap

This tool focuses on **at-rest encryption**. Runtime protections are defense-in-depth measures that raise the bar for attackers but do not provide complete runtime secrecy.

# Cryptography Overview
## Key Derivation

* Argon2id

* Per-file random salt

* Tunable memory and time cost

* Password material is zeroized after use

## Encryption

* AES-256 in CBC mode

* Random per-file IV

* Explicit padding handling

## Authentication

* HMAC-SHA256

* Covers file header and ciphertext

* Verified in constant time

* Authentication is checked before any decryption

> If authentication fails, no data is decrypted or written.

## Runtime Safety Measures

In addition to encrypting data at rest, `rcypher` applies several defensive measures during runtime to reduce accidental exposure of secrets.

### Direct TTY Output

When displaying secrets to the user, `rcypher` writes directly to the controlling terminal (`/dev/tty`) instead of standard output.

This helps prevent secrets from being:
- accidentally redirected to files
- captured by shell pipelines
- logged by wrapper scripts

Note that terminal output may still be retained in:
- terminal scrollback
- terminal multiplexers (tmux, screen)
- screen recordings

This measure reduces accidental leakage but does not provide complete protection against runtime observation.

### Memory Zeroing

Sensitive values such as:
- encryption keys
- derived key material
- decrypted secret values

are stored in memory using zeroing containers and are explicitly cleared when they go out of scope.

This helps reduce the lifetime of sensitive data in memory and limits exposure in cases such as:
- accidental reuse of memory
- crashes
- partial memory inspection

Memory zeroing is a best-effort mitigation and does not protect against:
- a compromised operating system
- swap or hibernation
- debuggers or core dumps
- privileged attackers

### Secure Password Input

Passwords are read without terminal echo and are not printed, logged, or stored in plaintext on disk.

### Core Dump Protection (Linux/Unix)

On Unix-like systems, `rcypher` disables core dumps using `setrlimit(RLIMIT_CORE, 0)` at startup.

This prevents unencrypted secrets from being written to disk in the event of a crash, reducing the risk of:
- accidental exposure through crash dumps
- forensic recovery of plaintext secrets from core files

**Limitations:**
- Does not protect against swap files or hibernation
- Does not prevent privileged (root) attackers from forcing core dumps
- Does not protect against memory inspection by debuggers

### Anti-Debugging Protection

`rcypher` continuously detects debugger/tracer attachment and refuses to decrypt
secrets while one is present. The mechanism is platform-specific:

**On Linux** — the secure fork model described in `ptrace(2)`:
1. At startup, the process forks into parent and child
2. Child calls `PTRACE_TRACEME` to be traced by the parent
3. Child stores the parent PID and continues as the main application
4. Parent monitors the child for its entire lifetime
5. During runtime, the child continuously verifies that `TracerPid` (from `/proc/self/status`) matches the stored parent PID; if it becomes 0 or changes, the app refuses to decrypt.

**On macOS** — the same properties without Linux's `timer_create`/`PTRACE_TRACEME`:
- continuous detection by checking this process's `P_TRACED` flag via `sysctl` on every watchdog tick (the analog of the Linux `TracerPid` read);
- `PT_DENY_ATTACH` at startup to refuse *future* attaches, followed immediately by a `P_TRACED` re-check so an already-attached debugger aborts;
- the watchdog is driven by a kernel-signal interval timer (`setitimer(ITIMER_REAL)` → `SIGALRM`), not a sleep loop, so a frozen or single-stepped process is detectable.

**What this prevents:**
- External debuggers from attaching (e.g., `gdb`, `lldb`, `strace`)
- Runtime inspection via ptrace-based tools
- Dynamic analysis and memory inspection

**Limitations:**
- Does not protect against kernel-level debugging (e.g., kprobes, eBPF, DTrace)
- Does not protect against privileged (root) attackers who can modify kernel behavior
- Can be bypassed by tampering with the kernel's view of process state (e.g. `/proc/self/status` on Linux) in a compromised OS
- Does not prevent static analysis or reverse engineering

These runtime protections are **defense-in-depth measures** and do not replace the core threat model. They provide additional barriers against casual memory inspection and debugging but cannot stop a determined attacker with OS-level privileges.


# File Format (High-Level)
```(css)
[ header | ciphertext | hmac ]
```

Header includes:

* format version

* padding length

* encryption parameters

* IV

* salt

This allows forward-compatible format upgrades.

## Clipboard Behavior (Important)

rcypher can copy secrets to the system clipboard for convenience.

**⚠️ Clipboard security is inherently limited:**

* Desktop clipboard managers (KDE, GNOME, Windows, macOS) may:

  * retain clipboard history

  * synchronize clipboard contents

  * defeat time-based clearing (TTL)

Because of this:

* Clipboard use is explicit

* Users are warned

* Clearing is best-effort only

If clipboard retention is unacceptable, use terminal output instead.

# Usage Notes

* Secrets printed to the terminal may remain in:

  * terminal scrollback

  * tmux/screen history

  * screen recordings

* Clipboard copy trades security for convenience

* Use strong, unique master passwords

# Limitations

* No automatic synchronization (manual file sync tools like Dropbox/Syncthing can be used with conflict resolution)

* No secret sharing or recovery

* No formal security audit

* Not intended as a drop-in replacement for audited password managers

# Ideas for the next steps

## Security

- [ ] Extend the header with Argon2id parameters, autodetect too fast key derivation and auto-bump complexity
- [ ] Warn about weak master password
- [ ] Add a command to change master password
- [ ] Add authentication with a YubiKey and Google Authenticator
- [ ] Add a user notification at start to perform regular backups in multiple places
- [ ] Add memory locking to prevent from swapping
- [ ] Enable MIRI in CI
- [ ] Add wrapping #[clippy::has_significant_drop] struct DecryptedValue for all decrypted data.

## Features
- [ ] Add password generation feature
- [ ] Implement nested hardened encryption for most important secrets. It is a good practice for users to split secrets in two separate places:
  - The most important data, which is the most safety critical. This data is usually accessed unfrequently and therefore kept encrypted most of the time.
  - Everything else - passwords from least crical services and other non-critical secrets. This would normally be most of the database.
  
  So the idea is to require an extra password for accessing those secrets that are marked as hardened. This would add an extra level of security for this most secure data and prevent from leakage even when an attacker managed to obtain the main encryption key, e.g. on compromised OS or by shoulder-surfing.
- [ ] Add command: rename for keys
- [ ] Add groups/levels/folders
  - [ ] Support rename for groups/levels/folders
- [ ] Implement or intergrate some existing encrypted fs to store files securely in a storage
  - [ ] Commands for extracting files outside and adding back in

# Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b some/amazing-feature)
3. Commit your changes (git commit -m 'Add some amazing feature')
4. Push to the branch (git push origin some/amazing-feature)
5. Open a Pull Request

# License

Apache-2.0

# Disclaimer

This software is provided as-is, without warranty of any kind.
No security claims are made beyond what is explicitly documented.

**A note to users**

If you need:

* multi-device sync

* browser integration

* audited security guarantees

Consider established, audited tools such as Bitwarden or KeePassXC.

rcypher is for users who prefer a **small, transparent, offline tool** and understand its limitations.
