#!/usr/bin/env bash
#
# rcypher installer - download the prebuilt `rcypher` binary for this machine from
# the latest GitHub release, verify its checksum, and drop it on your PATH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/justpresident/rcypher/main/scripts/install.sh | bash
#
# This script must be EXECUTED, not SOURCED (it calls `exit` on errors).
#   [ok]  curl -fsSL ... | bash        [ok]  bash install.sh        [no]  source install.sh
#
# Prebuilt binaries cover x86_64 Linux (static musl) and macOS (Intel + Apple
# Silicon). Other Linux arches fall back to building from source via `cargo
# install`; Windows is not supported (use WSL).
#
# Environment overrides:
#   RCYPHER_VERSION         release tag to install (default: the latest), e.g. v0.2.0
#   RCYPHER_INSTALL_DIR     directory to install `rcypher` into
#                           (default: /usr/local/bin if writable, else ~/.local/bin)
#   RCYPHER_NO_MODIFY_PATH  set to 1 to NOT touch your shell rc; just print the
#                           PATH line to add yourself
set -euo pipefail

REPO="justpresident/rcypher"
BIN="rcypher"          # the binary
CRATE="rcypher-cli"    # the crates.io package (the cargo fallback)

# The download temp dir, removed on exit. GLOBAL (not main-local) so the EXIT
# trap - which runs after main's locals are gone - can still see it under `set -u`.
tmp=""
cleanup() { if [ -n "$tmp" ]; then rm -rf "$tmp"; fi; }
trap cleanup EXIT

# --- logging (to stderr, so stdout stays clean for scripting) --------------
if [ -t 2 ]; then
  C_BLUE=$'\033[0;34m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[1;33m'; C_RED=$'\033[0;31m'; C_OFF=$'\033[0m'
else
  C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''
fi
info() { printf '%s==>%s %s\n' "$C_BLUE" "$C_OFF" "$1" >&2; }
ok()   { printf '%s==>%s %s\n' "$C_GREEN" "$C_OFF" "$1" >&2; }
warn() { printf '%s==>%s %s\n' "$C_YELLOW" "$C_OFF" "$1" >&2; }
die()  { printf '%sError:%s %s\n' "$C_RED" "$C_OFF" "$1" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- download / fetch via curl or wget -------------------------------------
download() { # download <url> <out-file>
  if have curl; then curl -fsSL -o "$2" "$1"
  else wget -qO "$2" "$1"; fi
}
fetch() { # fetch <url> -> stdout
  if have curl; then curl -fsSL "$1"
  else wget -qO- "$1"; fi
}

# --- sha256 of a file, via whatever tool is present ------------------------
sha256() { # sha256 <file> -> hex on stdout, or non-zero if no tool
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum;   then shasum -a 256 "$1" | awk '{print $1}'
  elif have openssl;  then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else return 1; fi
}

# --- detect the release target triple --------------------------------------
# Sets TARGET on success; returns 1 when there's no prebuilt for this platform
# (the caller then falls back to `cargo install`); dies on an unsupported OS.
detect_target() {
  local os arch
  case "$(uname -s)" in
    Linux) os="unknown-linux-musl" ;;
    Darwin) os="apple-darwin" ;;
    MINGW* | MSYS* | CYGWIN*) die "Windows is not supported - use WSL, or 'cargo install ${CRATE}'" ;;
    *) die "unsupported OS '$(uname -s)' - prebuilt binaries cover Linux and macOS" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) die "unsupported architecture '$(uname -m)'" ;;
  esac
  # Releases ship x86_64 for Linux, and both arches for macOS.
  if [ "$os" = "unknown-linux-musl" ] && [ "$arch" != "x86_64" ]; then
    return 1 # non-x86_64 Linux: no prebuilt, build from source via cargo
  fi
  TARGET="${arch}-${os}"
}

# --- resolve the version tag (latest, unless RCYPHER_VERSION is set) --------
resolve_version() {
  if [ -n "${RCYPHER_VERSION:-}" ]; then VERSION="$RCYPHER_VERSION"; return; fi
  local json
  json="$(fetch "https://api.github.com/repos/$REPO/releases/latest")" \
    || die "couldn't reach the GitHub releases API for $REPO"
  VERSION="$(printf '%s' "$json" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$VERSION" ] || die "no published release found for $REPO (set RCYPHER_VERSION, or 'cargo install ${CRATE}')"
}

# --- put the install dir on PATH for future shells -------------------------
# Detects the login shell from $SHELL, appends the right line to its rc file
# (idempotently), unless the dir is already on PATH or RCYPHER_NO_MODIFY_PATH=1.
ensure_on_path() {
  local dir="$1"
  case ":${PATH:-}:" in
    *":$dir:"*) return 0 ;; # already on PATH - nothing to do
  esac

  local shell rc line
  shell="${SHELL:-/bin/sh}"
  shell="${shell##*/}"
  case "$shell" in
    zsh) rc="${ZDOTDIR:-$HOME}/.zshrc"; line="export PATH=\"$dir:\$PATH\"" ;;
    bash) rc="$HOME/.bashrc"; line="export PATH=\"$dir:\$PATH\"" ;;
    fish) rc="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish"; line="fish_add_path \"$dir\"" ;;
    *) rc="$HOME/.profile"; line="export PATH=\"$dir:\$PATH\"" ;;
  esac

  if [ "${RCYPHER_NO_MODIFY_PATH:-0}" = "1" ]; then
    warn "$dir is not on your PATH (RCYPHER_NO_MODIFY_PATH is set, so leaving $rc untouched). Add:"
    printf '    %s\n' "$line" >&2
    return 0
  fi

  if [ -f "$rc" ] && grep -Fq "$dir" "$rc" 2>/dev/null; then
    info "$dir is already configured in $rc - restart your shell, or run: $line"
    return 0
  fi

  mkdir -p "${rc%/*}" 2>/dev/null || true
  if printf '\n# Added by the rcypher installer\n%s\n' "$line" >>"$rc" 2>/dev/null; then
    ok "Added $dir to your PATH in $rc"
    info "Restart your shell, or run this now to use ${BIN} immediately:"
    printf '    %s\n' "$line" >&2
  else
    warn "couldn't write $rc - add $dir to your PATH manually:"
    printf '    %s\n' "$line" >&2
  fi
}

# --- fall back to building from crates.io ----------------------------------
fallback_cargo() {
  if have cargo; then
    warn "No prebuilt binary for this platform - installing from crates.io with cargo."
    cargo install "$CRATE" && { ok "Installed via 'cargo install ${CRATE}'."; exit 0; }
    die "'cargo install ${CRATE}' failed"
  fi
  die "no prebuilt binary for this platform, and cargo is not installed. Install Rust (https://rustup.rs), then: cargo install ${CRATE}"
}

main() {
  printf '\n  rcypher installer\n\n' >&2
  have tar || die "tar is required"
  have curl || have wget || die "need curl or wget"

  detect_target || fallback_cargo
  resolve_version
  info "Installing ${BIN} ${VERSION} (${TARGET})"

  local asset base
  asset="${BIN}-${VERSION}-${TARGET}.tar.gz"
  base="https://github.com/${REPO}/releases/download/${VERSION}"
  # A template (trailing X's) is portable: GNU mktemp defaults one, BSD mktemp requires it.
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/rcypher.XXXXXXXX")" || die "couldn't create a temp dir"

  info "Downloading ${asset}"
  download "${base}/${asset}" "${tmp}/${asset}" || { warn "download failed (${base}/${asset})"; fallback_cargo; }

  # Verify against the sibling .sha256, when both it and a hash tool exist.
  if download "${base}/${asset}.sha256" "${tmp}/${asset}.sha256" 2>/dev/null; then
    local want got
    want="$(awk '{print $1; exit}' "${tmp}/${asset}.sha256")"
    if got="$(sha256 "${tmp}/${asset}")"; then
      [ "$want" = "$got" ] || die "checksum mismatch for ${asset} - refusing to install"
      ok "Checksum verified"
    else
      warn "no sha256 tool (sha256sum/shasum/openssl) - skipping checksum verification"
    fi
  else
    warn "no checksum published for ${asset} - skipping verification"
  fi

  tar -xzf "${tmp}/${asset}" -C "$tmp" || die "failed to extract ${asset}"
  local src="${tmp}/${BIN}-${VERSION}-${TARGET}/${BIN}"
  [ -f "$src" ] || src="$(find "$tmp" -type f -name "$BIN" | head -n 1)"
  [ -n "${src:-}" ] && [ -f "$src" ] || die "the archive did not contain the ${BIN} binary"

  # Where to install. Prefer OVERWRITING an existing `rcypher` already on PATH over
  # dropping a SECOND copy that PATH order could shadow (the script-vs-cargo footgun).
  local dir existing
  existing="$(command -v "${BIN}" 2>/dev/null || true)"
  if [ -n "${RCYPHER_INSTALL_DIR:-}" ]; then dir="$RCYPHER_INSTALL_DIR"
  elif [ -n "$existing" ] && [ -w "$(dirname "$existing")" ]; then
    dir="$(dirname "$existing")"
    info "${BIN} is already installed at $existing - updating it in place (no duplicate)."
  elif [ -w /usr/local/bin ]; then dir="/usr/local/bin"
  else dir="${HOME}/.local/bin"; fi
  mkdir -p "$dir" || die "couldn't create ${dir}"
  cp "$src" "${dir}/${BIN}" || die "couldn't write ${dir}/${BIN} - set RCYPHER_INSTALL_DIR to a writable directory"
  chmod 0755 "${dir}/${BIN}"

  # Clear the macOS Gatekeeper quarantine flag on the unsigned binary, if present.
  [ "$(uname -s)" = "Darwin" ] && xattr -d com.apple.quarantine "${dir}/${BIN}" 2>/dev/null || true

  ok "Installed ${BIN} to ${dir}/${BIN}"
  ensure_on_path "$dir"

  # A pre-existing copy elsewhere on PATH would shadow this one (or vice versa).
  if [ -n "$existing" ] && [ "$existing" != "${dir}/${BIN}" ]; then
    warn "Another ${BIN} is installed at $existing - depending on PATH order one will"
    warn "shadow the other. Remove the older copy so an update isn't hidden behind a stale binary."
  fi

  printf '\nGet started:\n  %s secrets.db                       # open/create an encrypted key-value store\n  %s --encrypt file --output file.enc   # encrypt an arbitrary file\n\n' "$BIN" "$BIN" >&2
}

main "$@"
