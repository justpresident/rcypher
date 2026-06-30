#!/usr/bin/env bash
#
# release.sh — publish the rcypher workspace (library + CLI) to crates.io + GitHub.
#
# Usage:
#   scripts/release.sh [--yes]
#
#   --yes   skip the confirmation prompt before the irreversible steps
#
# rcypher is a TWO-crate workspace that shares ONE version (read from the root
# Cargo.toml). Publish ORDER matters: `rcypher` (the library) first, then
# `rcypher-cli`, which resolves `rcypher = "X.Y"` from crates.io and so needs the
# library live first. The release tag is the bare `vX.Y.Z`; publishing the GitHub
# release fires .github/workflows/release.yml, which builds and attaches the four
# prebuilt binaries.
#
# This automates the mechanical half of docs/crate_release_process.md — it assumes
# the review, validation gate, changelog entry, and version bump (in ALL THREE
# places) are already done and committed as the "Release vX.Y.Z" commit. In order:
#   1. pre-flight: on main, clean tree, tools authenticated, the three versions
#      agree, and vX.Y.Z is neither tagged nor already on crates.io;
#   2. git pull --rebase — absorb the coverage-badge "[skip ci]" commit BEFORE
#      tagging, so the tag lands on the final commit and never has to be moved;
#   3. cargo publish -p rcypher --dry-run — verify the library tarball in isolation;
#   4. confirm, then tag + push the branch and the tag;
#   5. cargo publish -p rcypher (IRREVERSIBLE — versions are immutable), wait for
#      the index, then cargo publish -p rcypher-cli;
#   6. gh release create (notes from CHANGELOG.md) — this fires the binary workflow.
set -euo pipefail

die() { echo "release: $*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }

# --- parse args ---------------------------------------------------------------
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --yes | -y) ASSUME_YES=1 ;;
        *) die "unknown argument: $arg  (usage: release.sh [--yes])" ;;
    esac
done

# --- run from the repo root ---------------------------------------------------
ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repository"
cd "$ROOT"

# --- read and cross-check the version -----------------------------------------
# The first `version = "..."` inside a manifest's [package] table.
pkg_version() {
    sed -n '/^\[package\]/,/^\[/{s/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p;}' "$1" |
        head -n1
}
VERSION="$(pkg_version Cargo.toml)"
[ -n "$VERSION" ] || die "could not read [package] version from Cargo.toml"
CLI_VERSION="$(pkg_version rcypher-cli/Cargo.toml)"
# The rcypher-cli -> rcypher path dependency's version requirement.
CLI_DEP_VERSION="$(sed -n 's/^rcypher = .*version = "\([^"]*\)".*/\1/p' rcypher-cli/Cargo.toml | head -n1)"
TAG="v$VERSION"

[ "$CLI_VERSION" = "$VERSION" ] ||
    die "version mismatch: rcypher-cli is $CLI_VERSION but the library is $VERSION — bump both in lockstep"
[ "$CLI_DEP_VERSION" = "$VERSION" ] ||
    die "version mismatch: rcypher-cli depends on rcypher \"$CLI_DEP_VERSION\" but the library is $VERSION"

echo "release: rcypher + rcypher-cli  $VERSION  ->  tag $TAG"

# --- pre-flight ---------------------------------------------------------------
step "pre-flight"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" = "main" ] || die "not on main (on '$BRANCH')"
# Fully clean — including untracked files, which cargo publish would reject anyway.
[ -z "$(git status --porcelain)" ] ||
    die "working tree is not clean — commit the version bump + changelog (and remove stray files) first"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    die "tag $TAG already exists — already released, or delete the stale local tag (git tag -d $TAG)"
fi
# Refuse a version already on crates.io. `cargo publish --dry-run` does NOT check
# this (it only builds), so without it the clash would surface only at the final
# upload — after the rebase, tag, and push. Best-effort: needs curl + network; if
# either is missing we fall through to cargo's own check at publish time.
if command -v curl >/dev/null 2>&1; then
    # Sparse-index path for a name with >= 4 chars: /<first2>/<next2>/<name>.
    if curl -fsSL "https://index.crates.io/rc/yp/rcypher" 2>/dev/null | grep -Fq "\"vers\":\"$VERSION\""; then
        die "rcypher $VERSION is already published on crates.io (versions are immutable) — bump the version"
    fi
fi
command -v gh >/dev/null 2>&1 || die "the 'gh' CLI is required"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated — run 'gh auth login'"
[ -n "${CARGO_REGISTRY_TOKEN:-}" ] || ls ~/.cargo/credentials* >/dev/null 2>&1 ||
    die "no crates.io token — run 'cargo login' or set CARGO_REGISTRY_TOKEN"

# --- sync with the remote BEFORE tagging --------------------------------------
# The coverage CI job pushes an "Update coverage badge [skip ci]" commit after
# every push to main. Rebasing now means the release commit reaches its FINAL hash
# before we tag it, so the tag never has to be deleted and re-created.
step "git pull --rebase origin main"
git fetch origin main
git pull --rebase origin main

# --- verify the artifact (no upload) ------------------------------------------
# Full build-verify of the library tarball. rcypher-cli can't be build-verified
# until rcypher is live on crates.io, so only its file list is sanity-checked.
step "cargo publish -p rcypher --dry-run"
cargo publish -p rcypher --dry-run
step "cargo package -p rcypher-cli --list (file list only)"
cargo package -p rcypher-cli --list --no-verify >/dev/null

# --- confirm before anything irreversible -------------------------------------
echo
echo "About to PUSH and PUBLISH — this is IRREVERSIBLE (crates.io versions are immutable):"
echo "  crates:  rcypher $VERSION, then rcypher-cli $VERSION"
echo "  tag:     $TAG -> $(git rev-parse --short HEAD)  ($(git log -1 --format=%s))"
echo "  remote:  $(git remote get-url origin)"
if [ "$ASSUME_YES" -ne 1 ]; then
    printf 'Continue? [y/N] '
    read -r reply </dev/tty
    case "$reply" in y | Y | yes | YES) ;; *) die "aborted by user" ;; esac
fi

# --- tag, push ----------------------------------------------------------------
step "tag + push"
git tag -a "$TAG" -m "rcypher $VERSION"
git push origin main
git push origin "$TAG"

# --- publish: library first, then CLI -----------------------------------------
step "cargo publish -p rcypher"
cargo publish -p rcypher

# rcypher-cli resolves `rcypher = "X.Y"` from the registry, which lags the publish
# above by up to a minute. Retry until the index has caught up.
step "cargo publish -p rcypher-cli (waiting for the index if needed)"
for attempt in 1 2 3 4 5 6; do
    if cargo publish -p rcypher-cli; then
        break
    fi
    [ "$attempt" -lt 6 ] || die "rcypher-cli publish still failing after $attempt attempts"
    echo "release: rcypher not in the index yet — retrying in 20s ($attempt/6)…"
    sleep 20
done

# --- GitHub release (fires the binary workflow) -------------------------------
step "gh release create $TAG"
NOTES="$(mktemp)"
trap 'rm -f "$NOTES"' EXIT
# Pull this version's CHANGELOG section (everything between its heading and the next).
awk -v v="$VERSION" '
    $0 ~ "^## \\[" v "\\]" { f = 1; next }
    /^## \[/ { f = 0 }
    f { print }
' CHANGELOG.md >"$NOTES"
if [ -s "$NOTES" ]; then
    gh release create "$TAG" --title "$TAG" --notes-file "$NOTES"
else
    echo "release: WARNING — no '## [$VERSION]' section in CHANGELOG.md; using a generic note" >&2
    gh release create "$TAG" --title "$TAG" \
        --notes "rcypher $VERSION. See CHANGELOG.md and <https://crates.io/crates/rcypher/$VERSION>."
fi

REPO_URL="$(git remote get-url origin | sed 's#git@github.com:#https://github.com/#; s#\.git$##')"
echo
echo "release: done — rcypher + rcypher-cli $VERSION"
echo "  crates.io: https://crates.io/crates/rcypher/$VERSION"
echo "             https://crates.io/crates/rcypher-cli/$VERSION"
echo "  github:    $REPO_URL/releases/tag/$TAG"
echo
echo "The GitHub release fired .github/workflows/release.yml — watch the binary"
echo "build and confirm all eight assets (4 archives + 4 .sha256) attach:"
echo "  gh run watch"
