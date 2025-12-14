![CI](https://github.com/justpresident/rcypher/actions/workflows/rust.yml/badge.svg)
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
cypher > put github.username my-username
github.username stored

cypher > put github.password my-password
github.password stored

cypher > put github.token my-secret-token
github.token stored

cypher > get github.*
github.password: my-password
github.token: my-secret-token
github.username: my-username

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

To upgrade an existing encrypted storage file to the latest supported format:
```(sh)
$ rcypher --upgrade-storage secrets.db
Enter Password for secrets.db:
```

The file is updated in place.

---

# Features

* Offline, single-file encrypted storage

* Password-based encryption using Argon2id

* Strong authenticated encryption (AES + HMAC)

* Constant-time authentication checks

* Secure password input (no terminal echo)

* Secure terminal output using raw TTY access (bypasses stdout)

* Automatic zeroing of sensitive memory

* Optional clipboard copy with warnings

* Minimal dependencies and attack surface

* Explicit file format versioning

# Threat Model

rcypher is designed to protect secrets:

✔ against **offline attackers** who obtain the encrypted file

✔ against accidental disclosure via plaintext files

✔ against tampering and corruption of encrypted data

It **does not** protect against:

❌ a compromised operating system

❌ malware, keyloggers, or malicious clipboard managers

❌ privileged (root) attackers

❌ memory dumps, debuggers, or swap attacks

❌ shoulder-surfing or screen recording

This tool focuses on **at-rest encryption**, not runtime secrecy.

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

# Testing

The project includes:

* Unit tests

* Integration tests for the CLI

* Negative tests covering:

  * corrupted HMAC

  * truncated files

  * invalid padding

  * unsupported file versions

Tests are located in the tests/ directory.

# Limitations

* No synchronization or multi-device support

* No secret sharing or recovery

* No formal security audit

* Not intended as a drop-in replacement for audited password managers

# License

Apache-2.0

# Disclaimer

This software is provided as-is, without warranty of any kind.
No security claims are made beyond what is explicitly documented.

A note to users

If you need:

* multi-device sync

* browser integration

* audited security guarantees

Consider established, audited tools such as Bitwarden or KeePassXC.

rcypher is for users who prefer a **small, transparent, offline tool** and understand its limitations.
