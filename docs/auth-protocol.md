# Multi-factor unlock protocol

How rcypher protects a vault with an arbitrary boolean **access policy** over
named factors — for example `pass1 OR (pass2 AND fido2)`. This document is the
normative description of the construction so it can be audited against the
literature rather than taken on faith.

Status: design complete; password and FIDO2 security-key factors implemented (the
FIDO2 device I/O is behind the `fido2` cargo feature).
Vault format version: **8** (policy vault), distinct from the version-7 plain
password envelope.

## Goals

- Unlock a vault when, and only when, a satisfying set of factors is presented,
  for any monotone boolean policy (any nesting of AND/OR over factors).
- Manage factors and the policy from an unlocked vault **without re-presenting
  every factor**, and **without re-encrypting the stored data**.
- Keep rcypher's existing at-rest guarantees: a stable per-vault data key, a fresh
  IV on every save, authenticated encryption, and zeroization of key material.

## Notation and primitives

- `‖` — byte concatenation. `⊕` — XOR. `⊥` — failure/absent.
- **`wrap(K, m [, aad])`** — authenticated encryption of message `m` under 64-byte
  key material `K`, producing a self-contained blob with a fresh random IV. The
  optional **associated data** `aad` is authenticated but not encrypted: it is
  folded into the HMAC, so `unwrap` fails unless the same `aad` is supplied. An
  absent/empty `aad` is byte-for-byte the plain envelope.
- **`unwrap(K, c [, aad])`** — the inverse; returns `m`, or **`⊥` when
  authentication fails** (wrong key, tampered ciphertext, **or mismatched
  `aad`**). This failure is the protocol's "wrong key / factor not satisfied"
  signal — there is no separate check and no padding/decryption oracle, because
  the MAC is verified (in constant time) before any plaintext is produced.

  > **Precision note.** `wrap`/`unwrap` here is rcypher's existing envelope —
  > **AES-256-CBC encrypt-then-HMAC-SHA256** (the same construction the rest of
  > rcypher uses), keyed by `K = (32-byte AES key ‖ 32-byte HMAC key)`. It is
  > **not** the RFC 3394 / NIST SP 800-38F "AES Key Wrap" algorithm. We use the
  > word "wrap" in its general sense ("authenticated-encrypt a key under a key",
  > as in PKCS#11 `C_WrapKey`), not as a reference to that specific primitive. The
  > envelope's `salt` header field is unused for key-material keys (it only feeds
  > password derivation) and is left zeroed.

- **`Argon2id(password, salt) → 64B`** — memory-hard password hashing
  (RFC 9106), producing 64 bytes of key material.
- **`distribute` / `reconstruct`** — secret sharing over the policy tree
  (defined below).

## Keys

All key material is **64 bytes = a 32-byte AES-256 key ‖ a 32-byte HMAC key**.

| Key | Obtained from | Role |
|---|---|---|
| **DEK** (data-encryption key) | fresh random bytes at vault creation | encrypts the stored payload; the secret the policy protects |
| **auth-KEKᵢ** (one per factor) | password: `Argon2id(passwordᵢ, saltᵢ)`; FIDO2: `HKDF-SHA256(hmac-secret output, info)` (no extract salt — the output is already a uniform PRF value) | wraps that factor's policy-leaf shares |
| **shareⱼ** (one per policy leaf) | the DEK, secret-shared down the policy | reconstructs the DEK when enough leaves are unwrapped |

KEK/DEK is the standard envelope-encryption split (NIST, cloud KMS, LUKS): a data
key encrypts data; a key-encryption key wraps the data key.

### FIDO2 factors and the `hmac-secret` user-verification binding

A FIDO2 factor's `hmac-secret` input is obtained from a CTAP2 authenticator: enrol
runs `make_credential` (a *non-resident* credential, with the `hmac-secret`
extension) to get a `credential_id`, then a `get_assertion` to read the secret for a
random per-factor `salt`. The secret is `HMAC(CredRandom, salt)`, where `CredRandom`
is a per-credential random fixed on the key at creation. Both the `credential_id`
(non-resident, so independent of the key's later state) and `CredRandom` survive a
later PIN change — the key is **not** a different device, and the bound secret is
stable.

**The subtlety:** on CTAP 2.1 a credential has **two** `CredRandom` values, and the
authenticator picks by whether **user verification was performed in that
`get_assertion`** — `CredRandomWithUV` when a PIN/biometric was used, `CredRandom
WithoutUV` for touch-only. So a factor's auth-KEK is bound to the **uv mode** used at
enrolment. rcypher records that mode (`require_pin` in the factor, set from whether
the key had a PIN at enrol time) and **replays the same mode at unlock**, so the same
secret — and thus the same auth-KEK — is reproduced. It deliberately does *not*
re-detect the key's current PIN state at unlock: switching modes would derive the
*other* secret and fail to unwrap the leaf share.

**Consequences for changing a key's policy after enrolment:**

- *Setting a PIN* on a key a factor was enrolled touch-only on is **safe** — unlock
  still uses the touch-only (`WithoutUV`) path and the same secret.
- *Enabling "always require user verification" (`alwaysUv`)* on a key with a
  touch-only factor, or *removing the PIN* a factor was enrolled with, makes the
  enrolled uv mode impossible. The bound secret becomes unreachable and **that factor
  can no longer satisfy its leaf** — the stored data is untouched, but you must unlock
  via another satisfying branch of the policy and re-enrol the key.

This is one more reason a FIDO2 factor should rarely be a policy's only branch (see
the weak-`or`/recovery guidance in the README).

## Data structures

```
PolicyMetadata {
    factors : [ Factor ]
    policy  : PolicyNode
}

Factor {
    id                : string            // e.g. "pass1", "fido2-main"
    kind              : FactorKind        // derivation parameters (below)
    authkek_under_dek : bytes             // = wrap(DEK, auth-KEK_of_this_factor)
}

FactorKind =
    | Password { salt, memory_cost, time_cost, parallelism }
    | Fido2  { credential_id, rp_id, salt, require_pin }

PolicyNode =
    | And  [ PolicyNode, … ]              // satisfied iff all children are
    | Or   [ PolicyNode, … ]              // satisfied iff any child is
    | Leaf { factor : string,            // which factor unlocks this leaf
             wrapped_share : bytes }      // = wrap(auth-KEK_of(factor), this leaf's share)
```

### On-disk layout

```
file = u16(8)  ‖  bincode(PolicyMetadata)  ‖  wrap(DEK, serialize(store), aad = header)
       └────────────── header ─────────────┘  └── the encrypted payload ──┘
```

The leading `u16(8)` distinguishes a policy vault from a plain version-7 envelope
(tag `7`) by probing the first two bytes. The `PolicyMetadata` bytes are stable
across saves; only the payload carries a fresh IV per save (see *Save*).

**The header is authenticated.** The whole leading `header` (`u16(8) ‖
bincode(PolicyMetadata)` — the policy tree, factor table, KDF params, and every
wrapped share) is passed as the payload's **associated data**, so the payload's
HMAC also covers it. The metadata stays cleartext (so the policy can be displayed
before unlock), but it cannot be altered, downgraded, or spliced onto a different
payload without the DEK — which only a party that satisfies the policy can
recover. This adds no bytes to the file; only the tag's input grows.

## The auth-KEK bridge

Each factor's `auth-KEKᵢ` is reachable **two ways**, and this is the crux of the
design:

```
   password ──Argon2id(·,saltᵢ)──▶  auth-KEKᵢ  ◀──unwrap(DEK, authkek_under_dekᵢ)── DEK
                                       │
                                       └── wraps the leaf shares for factor i
```

- **Unlock direction** (no DEK yet): `password → auth-KEKᵢ → unwrap leaf shares →
  reconstruct DEK`.
- **Management direction** (DEK in hand): `DEK → auth-KEKᵢ → re-wrap leaf shares`.

Storing `authkek_under_dek` reveals nothing to an attacker who lacks the DEK (it
is authenticated ciphertext of a high-entropy key), while letting a holder of the
unlocked DEK recover every factor's wrapping key. Because `auth-KEK =
Argon2id(password)` is one-way, recovering it never reveals the password.

## Secret sharing (`distribute` / `reconstruct`)

The DEK is shared down the policy tree using the classic construction for
monotone access structures (Benaloh–Leichter, see *References*):

`distribute(secret, node)` assigns one share to each leaf in left-to-right DFS
order:

- **Or(children)** — *replicate*: every child receives a copy of `secret`.
- **And(children)** — *XOR-split* (n-of-n additive sharing): pick random
  `s₁…sₙ₋₁`, set `sₙ = secret ⊕ s₁ ⊕ … ⊕ sₙ₋₁`, give child *k* the secret `sₖ`.
- **Leaf** — receives the secret that reached it; that becomes the leaf's share.

`reconstruct(node, provided)` consumes one slot per leaf in the same DFS order
(`Some(share)` if that leaf's factor was satisfied, else `None`):

- **Leaf** — yields its provided share, or `None`.
- **Or** — yields any one satisfied child's value (they are all equal to the node
  secret); `None` if all children are `None`.
- **And** — yields the XOR of all children's values **iff all are present**; else
  `None`.

The root yields `Some(DEK)` exactly when the satisfied leaves satisfy the policy.

## Operations

Each operation below names the corresponding `PolicyVault` method.

### CREATE(id, password) — `create`
1. `DEK ← random 64 B`.
2. `auth-KEK ← Argon2id(password, saltᵢ ← random)`.
3. Append `Factor{ id, kind = Password{salt, params}, authkek_under_dek = wrap(DEK, auth-KEK) }`.
4. `policy ← Leaf(id)`; `distribute(DEK, policy)` gives the single leaf `share = DEK`;
   set its `wrapped_share = wrap(auth-KEK, DEK)`.
5. The vault holds the DEK in memory (unlocked).

### SAVE — `encrypt_payload` + serialize
Serialize `header = u16(8) ‖ bincode(metadata)`, then write `header ‖ wrap(DEK,
serialize(store), aad = header)`. The payload's `wrap` uses a fresh IV, so each
save is fresh, unlinkable ciphertext under the **same** DEK, and binds that save's
exact `header` as associated data. The metadata (keyslots + policy) is unchanged
from the last management operation and is re-serialized byte-for-byte.

### UNLOCK(secrets) — `unlock` + `decrypt_payload`
1. Parse the file → `header` + `metadata` + encrypted payload.
2. For each provided factor: `auth-KEKᵢ ← Argon2id(passwordᵢ, factor.saltᵢ)`.
3. For each policy leaf (DFS order): if its factor's auth-KEK is held,
   `unwrap(auth-KEKᵢ, wrapped_share)` → `Some(share)` (MAC ok) or `None`
   (wrong password, or factor not provided).
4. `reconstruct(policy, shares)` → `Some(DEK)` iff the policy is satisfied, else
   the unlock fails.
5. With the DEK, `unwrap(DEK, payload, aad = header)` yields the store — **and
   re-verifies the header**: if the policy/factor table was tampered with or a
   stale header spliced in, the associated data no longer matches and decryption
   fails here, even though step 4 may have reconstructed a DEK. So a downgraded
   file is rejected, not opened (and therefore never re-saved in its weaker form).

A wrong password produces a wrong `auth-KEK`, so `unwrap` fails the MAC and the
leaf is treated as unsatisfied — no oracle distinguishes "wrong password" from
"absent factor".

### ENROLL password(id, password) — `enroll_password`
*Requires: an unlocked DEK and the new password only.*
1. `auth-KEK_new ← Argon2id(password, salt ← random)`.
2. Append `Factor{ id, kind, authkek_under_dek = wrap(DEK, auth-KEK_new) }`.
3. The policy is unchanged; call SET_POLICY to start using the new factor.

### SET_POLICY(expr) — `set_policy`
*Requires: an unlocked DEK only — no passwords.*
1. Parse `expr` → tree; validate every referenced factor exists.
2. Recover all auth-KEKs: `auth-KEKᵢ ← unwrap(DEK, factor.authkek_under_dekᵢ)`.
3. `distribute(DEK, new_tree)` → a fresh share per leaf.
4. For each leaf, `wrapped_share = wrap(auth-KEK_of(leaf.factor), share)`; replace
   the policy.

The DEK is unchanged, so the **payload is not re-encrypted**; only the policy and
its leaf wraps change.

### REMOVE_FACTOR(id) — `remove_factor`
Refuses if the current policy still references `id` (change the policy first),
then drops the factor and its `authkek_under_dek`.

### CHANGE_PASSWORD(id, new) — *not yet implemented; supported by design*
Derive `auth-KEK_new`; the policy and DEK are unchanged, so the factor's shares
are unchanged — re-wrap only **that factor's** leaves under `auth-KEK_new` and set
`authkek_under_dek = wrap(DEK, auth-KEK_new)`. The DEK, the payload, and all other
factors are untouched: a password change costs one keyslot re-wrap, never a vault
re-encryption.

## Worked example: `p1 OR (p2 AND p3)`, DEK = `D`

`distribute(D, Or[ Leaf(p1), And[ Leaf(p2), Leaf(p3) ] ])`:

```
Or  ── replicate D ──┬─ Leaf(p1): share = D
                     └─ And(secret D) ── XOR-split D = r ⊕ (D⊕r)
                            ├─ Leaf(p2): share = r
                            └─ Leaf(p3): share = D⊕r
```

Stored wraps:

```
p1.wrapped_share = wrap(auth-KEK_p1, D)        p1.authkek_under_dek = wrap(D, auth-KEK_p1)
p2.wrapped_share = wrap(auth-KEK_p2, r)        p2.authkek_under_dek = wrap(D, auth-KEK_p2)
p3.wrapped_share = wrap(auth-KEK_p3, D⊕r)      p3.authkek_under_dek = wrap(D, auth-KEK_p3)
```

Unlock outcomes:

- **p1** → unwrap p1 → `D`; `Or` takes the satisfied child → `D`. ✓
- **p2 + p3** → unwrap → `r`, `D⊕r`; `And` → `r ⊕ (D⊕r) = D`. ✓
- **p2 only** → `r`, then p3 `⊥`; `And` needs both → `⊥`; `Or` → `⊥`. Locked. ✓
- **p3 with wrong password** → wrong auth-KEK → `unwrap` MAC fails → `⊥`. Locked. ✓

## Security properties and limitations

- **Stable key, fresh IV per save.** The DEK is generated once and reused for the
  vault's life; every save re-encrypts the payload under it with a fresh IV. The
  data key is never re-derived per save (the original design never did this
  either — the password is zeroized after the one-time derivation).
- **At-rest cost against a password is unchanged.** An attacker with the file must
  still break Argon2id on a keyslot to recover an `auth-KEK`. The envelope/DEK
  layer adds no shortcut.
- **The XOR split leaks nothing below threshold (information-theoretic).** An
  `And` over *n* children uses n-of-n additive sharing: `s₁…sₙ₋₁` are drawn from
  the OS CSPRNG and `sₙ = secret ⊕ s₁ ⊕ … ⊕ sₙ₋₁`. Any *n−1* of the *n* shares are
  jointly uniform and independent of `secret` — a one-time-pad argument — so a
  coalition missing even one child learns *nothing* about the reconstructed
  secret, with no computational assumption. Each share is *also* wrapped under its
  factor key, so an unsatisfied factor's share cannot even be obtained in the
  clear. Soundness rests only on the CSPRNG quality and on shares being the
  secret's full length (both hold here).
- **OR is as strong as its weakest satisfying set.** In `p1 OR (…)`, an attacker
  attacks `p1` alone — the strongest other branch does not help. Any factor (or
  set) that can unlock on its own must itself be strong; a password-only branch
  bounds the vault's offline strength by that password. Password strength is
  enforced per factor at enroll time (see Argon2/zxcvbn below).
- **`authkek_under_dek` is safe to store.** Without the DEK it is opaque
  authenticated ciphertext; with the DEK the holder already has full access, and
  it never reveals a password (Argon2id is one-way).
- **The keyslot header is authenticated and bound to the payload.** The cleartext
  metadata (policy tree, factor table, KDF params, wrapped shares) is the
  payload's associated data, so the payload's HMAC covers it. Forging an
  acceptable modification requires the DEK, and recovering the DEK requires
  satisfying the *original* policy — so an attacker who merely holds or can
  rewrite the file cannot tamper with it. This closes a policy-**downgrade**
  attack: e.g. in `p1 OR (p2 AND fido2)`, OR replicates the full DEK to the `p1`
  branch, so without this binding an attacker could strip the policy down to the
  original `p1` leaf, get the victim to unlock with `p1` alone, and have the
  weakened policy persist on the next save.
- **No rekeying on password change** (LUKS-style, intentional): changing or
  removing a factor re-wraps keyslots but does not rotate the DEK or re-encrypt
  the data. True rekeying (new DEK + re-encrypt) is deliberately *not* performed,
  to avoid decrypting and re-encrypting on every credential change.
- **Anti-debug.** Internal `wrap`/`unwrap` operations do not each run the
  debugger check; it is enforced once at the unlock entry point (and continuously
  by the watchdog), so the keyslot operations are not a per-call oracle for it.
- **Zeroization.** The DEK, recovered auth-KEKs, and the transient secret-shares
  in the sharing path are all held in zeroizing buffers (`distribute` /
  `reconstruct` / `unwrap_share` carry `Zeroizing<Vec<u8>>` end to end), so no
  share or recovered key lingers in memory un-wiped.

## References

- **J. Benaloh, J. Leichter. "Generalized Secret Sharing and Monotone
  Functions." CRYPTO 1988.** The construction realizing any monotone access
  structure from its formula: AND ⇒ additive split, OR ⇒ replicate. This protocol
  uses XOR as the additive (n-of-n) split.
- A. Shamir. "How to Share a Secret." CACM 1979. (Foundational secret sharing;
  "share"/"reconstruct" terminology.)
- **Key-wrapping terminology**: PKCS#11 (`C_WrapKey`/`C_UnwrapKey`); RFC 3394 /
  NIST SP 800-38F (the AES Key Wrap algorithm — *not* used here; see the
  precision note above).
- **Envelope encryption / keyslots**: LUKS (`cryptsetup`) master-key keyslots;
  cloud KMS envelope encryption — the DEK + per-credential-wrapped-DEK model.
- RFC 9106 (Argon2), FIPS 197 (AES), FIPS 198-1 (HMAC).
- FIDO2 CTAP2 `hmac-secret` extension (the FIDO2 factor's `auth-KEK` source).
