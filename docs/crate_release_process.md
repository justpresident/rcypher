# Crate release process

Publishing a new release of the `rcypher` workspace. Examples below use `v0.1.1`
as the previous release tag and `v0.2.0` as the new one — substitute the real
versions. Get the previous tag with `git describe --tags --abbrev=0`.

This is a **two-crate workspace**:

- **`rcypher`** — the reusable library (the root package). Publish this **first**.
- **`rcypher-cli`** — the CLI (depends on `rcypher` by version). Publish this
  **second**, after `rcypher` is live on crates.io.

crates.io versions are **immutable**: once `cargo publish` succeeds you cannot
overwrite or re-upload that version. Everything below the publish step exists to
make sure the artifact is correct *before* it goes out. The two crates share one
version number — bump them in lockstep.

## Pre-flight

0. Be on `main`, up to date, with a clean working tree and CI green on the last
   commit. Make sure you're authenticated to crates.io (`cargo login`, or
   `CARGO_REGISTRY_TOKEN` set) — otherwise the final publish fails after all the
   work. Releasing also pushes a tag and (optionally) creates a GitHub release,
   so you need push access to `origin` and, for the GitHub step, an authenticated
   `gh` (`gh auth status`).

## Review what's shipping

1. Check what has changed since the last release: `git log v0.1.1..HEAD`.
2. Check the files that changed: `git diff v0.1.1..HEAD --name-status`.
3. Read all the changed Rust files in full and make sure:
   - a) all code comments are correct and precise;
   - b) the CLI is well documented — every supported feature is discoverable via
     `rcypher --help`, and the README's "Use as a library" section matches the
     real public API.
4. **Look for opportunities to improve the code** — abstractions that can be
   simplified, code that can be made more readable, duplication that can be
   removed. THIS IS REALLY IMPORTANT. Ask a human if you have ideas you are not
   certain about. Commit and re-test any changes you make here before continuing.

## Validate

5. Make the full gate pass cleanly (and commit any fixes). This mirrors CI plus
   the lean-core build that proves the library is usable without the bundled
   storage format:
   ```bash
   cargo clippy --all --all-features -- -D warnings
   cargo clippy -p rcypher --no-default-features -- -D warnings
   cargo fmt --all -- --check
   cargo test --all --all-features
   cargo test -p rcypher --no-default-features          # lean core (crypto only)
   ```
   (Clippy runs **without** `--all-targets`: the crate-level `unwrap_used` /
   `expect_used` lints intentionally don't apply to test code, where `unwrap` is
   the assertion style — `cargo test` above already compiles every test target.)
   Then **validate the library example by hand**. `examples/custom_format.rs` is
   the bring-your-own-format readiness material; run it end to end and read the
   output — the in-memory and on-disk round-trips must both report OK:
   ```bash
   cargo run -p rcypher --example custom_format
   ```

## Update the changelog

6. Update `CHANGELOG.md` at the repo root (create it on the first release, using
   the [Keep a Changelog](https://keepachangelog.com/) format). From the
   `git log` review above, write a new section for the version, dated with today's
   date, grouping notable changes under `Added` / `Changed` / `Fixed` / `Removed`
   / `Security`. Keep it human-readable — summarize what users care about, not raw
   commit subjects. This section is the single source of truth for the GitHub
   release notes in the last step. (`CHANGELOG.md` ships in the published crate —
   `exclude` only drops `/docs` and other repo-meta dirs.)
   ```markdown
   ## [0.2.0] - 2026-06-20
   ### Added
   - `EncryptionKey::for_data`: derive a key from an in-memory blob's salt.
   ### Changed
   - ...
   ### Removed
   - ...
   ```

## Bump and verify the artifact

7. Decide the new version from the review above (pre-1.0 semver: breaking changes
   bump the **minor**, features/fixes bump the **patch**). Bump `version` in
   **three** places so the workspace stays consistent:
   - `Cargo.toml` `[package] version` (the `rcypher` library);
   - `rcypher-cli/Cargo.toml` `[package] version`;
   - `rcypher-cli/Cargo.toml` the `rcypher = { version = "..." }` dependency
     requirement (must match the new library version).

   Then run `cargo build` so `Cargo.lock` picks up the new versions.
8. Verify each package on a **clean** tree (do not use `--allow-dirty` — it would
   validate a tarball containing uncommitted changes you'll never tag). The
   library has no internal dependencies, so it dry-runs fully; the CLI depends on
   `rcypher` from the registry, which isn't published until step 12, so only its
   file list can be checked until then:
   ```bash
   cargo package -p rcypher --list           # eyeball the files (note: /docs is excluded)
   cargo publish -p rcypher --dry-run        # full verify of the library tarball
   cargo package -p rcypher-cli --list --no-verify   # CLI file list (build-verify needs rcypher live)
   ```

## Commit, tag, push

9. Commit the bump and changelog as the release commit:
   ```bash
   git add Cargo.toml Cargo.lock CHANGELOG.md rcypher-cli/Cargo.toml
   git commit -F- <<'MSG'
   Release v0.2.0
   MSG
   ```
10. Tag **that** commit so the tag and the published version agree:
    ```bash
    git tag v0.2.0
    ```
11. Push the commit and the tag:
    ```bash
    git push origin main
    git push origin v0.2.0
    ```

## Publish (library first, then CLI)

12. Publish from the clean, tagged tree. **Order matters** — `rcypher-cli`
    depends on `rcypher` from crates.io, so the library must be live (and indexed)
    first:
    ```bash
    cargo publish -p rcypher
    # wait for it to appear in the index, then:
    cargo publish -p rcypher-cli
    ```
    If `rcypher-cli` fails with "no matching package named `rcypher`", the index
    hasn't caught up yet — wait a minute and retry.

## Create the GitHub release

13. Create a GitHub release for the tag, using the new `CHANGELOG.md` section as
    the notes. Write that section to a **temporary** scratch file at
    `docs/release-notes-v0.2.0.md` — `docs/` keeps it out of the crate package
    (`exclude` drops `/docs`), but it is still a scratch file: **never commit it,
    and delete it as soon as the release exists**. Preferred (automated, via the
    `gh` CLI):
    ```bash
    gh release create v0.2.0 --title "v0.2.0" --notes-file docs/release-notes-v0.2.0.md
    rm docs/release-notes-v0.2.0.md   # done with it — remove, don't commit
    ```
    If `gh` is unavailable or unauthenticated, create it manually: GitHub →
    **Releases** → **Draft a new release** → choose the existing `v0.2.0` tag →
    paste the changelog section → **Publish release** → then delete the scratch
    file.

## Attach the prebuilt binary

14. Publishing the release in the previous step **fires the binary workflow** —
    that is the trigger, so the release must be *published*, not left as a draft.
    `.github/workflows/release.yml` builds three binaries on their native runners
    and attaches them:

    | Target | Runner | Asset |
    |---|---|---|
    | `x86_64-unknown-linux-musl` | `ubuntu-latest` | static Linux binary (any distro, any glibc) |
    | `x86_64-apple-darwin` | `macos-15-intel` | macOS Intel |
    | `aarch64-apple-darwin` | `macos-15` | macOS Apple Silicon |

    Each is a `rcypher-vX.Y.Z-<target>.tar.gz` (holding the stripped `rcypher` +
    `README.md` + `LICENSE`) with a sibling `.sha256`. Watch the run finish
    (`gh run watch` / Actions tab) and confirm **all six assets** (three archives +
    three checksums) are attached. The binaries are stripped and fat-LTO'd via
    `[profile.release]` in `Cargo.toml` — nothing to do per target.

    Windows is not covered (the CLI is Unix-only); Windows users use WSL or the
    library crate. macOS keeps the same security model as Linux via platform
    equivalents — `setitimer(ITIMER_REAL)` for the watchdog timer and a continuous
    `sysctl`/`P_TRACED` check for debugger detection (see `src/security.rs`).

15. **If CI is unavailable**, build and upload each binary by hand from the tagged
    tree (the two `apple-darwin` targets must be built on a Mac — cross-compiling
    Apple targets from Linux needs Apple's SDK and is not supported). Per target:
    ```bash
    rustup target add x86_64-unknown-linux-musl   # or the apple-darwin target on a Mac
    cargo build --release --locked --target x86_64-unknown-linux-musl -p rcypher-cli --bin rcypher
    name="rcypher-v0.2.0-x86_64-unknown-linux-musl"
    mkdir "$name" && cp target/x86_64-unknown-linux-musl/release/rcypher README.md LICENSE "$name/"
    tar czf "$name.tar.gz" "$name" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"
    gh release upload v0.2.0 "$name.tar.gz" "$name.tar.gz.sha256"
    ```

### Smoke-testing the workflow without cutting a release

The workflow also has a `workflow_dispatch` trigger taking an existing tag, so you
can exercise the whole build/package/upload path against a release that already
exists (it attaches the asset to that release):
```bash
gh workflow run "Release binaries" -f tag=v0.2.0
gh run watch
```
Use this to validate a change to `release.yml` before relying on it for a real
release.
