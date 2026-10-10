#!/usr/bin/env bash
# check-offline.sh: static offline rules (SPEC §10.2).
# Scans crates/*/src only (crates/*/tests may use std::process::Command).
# Prints every violation as "rule: file:line:text" and exits 1 if any.
# Portable: Git Bash, Ubuntu bash, macOS bash 3.2 + BSD grep (no \b, no arrays).
set -eu
cd "$(dirname "$0")/.."

src_dirs=""
for d in crates/*/src; do
  if [ -d "$d" ]; then src_dirs="$src_dirs $d"; fi
done
if [ -z "$src_dirs" ]; then
  echo "check-offline: no crates/*/src directories found"; exit 1
fi

fail=0

# print_hits RULE HITS: prefix each "file:line:text" hit with the rule name.
print_hits() {
  printf '%s\n' "$2" | while IFS= read -r h; do echo "check-offline: $1: $h"; done
}

# scan RULE GREP_FLAGS ERE DIR...: report lines matching ERE in *.rs files.
scan() {
  rule=$1; flags=$2; re=$3; shift 3
  set +e
  # shellcheck disable=SC2086  # $flags and dirs are intentionally word-split
  hits=$(grep -rnE $flags --include='*.rs' -e "$re" "$@")
  rc=$?
  set -e
  if [ "$rc" -gt 1 ]; then echo "check-offline: grep failed (rc=$rc)"; exit 2; fi
  if [ -n "$hits" ]; then print_hits "$rule" "$hits"; fail=1; fi
}

# 1. Networking APIs (also catches grouped imports like `use std::{io, net}`).
# shellcheck disable=SC2086
scan "network API" "" \
  'std::net|TcpStream|UdpSocket|TcpListener|ToSocketAddrs|std::\{[^}]*net' $src_dirs

# 2. Process launching (also `use std::process::{Command, ..}`).
# shellcheck disable=SC2086
scan "process::Command" "" 'process::Command|process::\{[^}]*Command' $src_dirs

# 3. GUI only: hyperlinks / URL opening. Case-insensitive so egui's
#    `Hyperlink` widget and `OpenUrl` are caught as well as `hyperlink`/`open_url`.
if [ -d crates/veilcode-gui/src ]; then
  scan "GUI URL opening" "-i" 'hyperlink|open_url|openurl' crates/veilcode-gui/src
fi

# 4. http:// or https:// in Rust source, except on lines that start with `//`
#    (covers `///` and `//!` doc comments too).
set +e
# shellcheck disable=SC2086
url_hits=$(grep -rnE --include='*.rs' -e 'https?://' $src_dirs)
rc=$?
set -e
if [ "$rc" -gt 1 ]; then echo "check-offline: grep failed (rc=$rc)"; exit 2; fi
if [ -n "$url_hits" ]; then
  url_hits=$(printf '%s\n' "$url_hits" | awk '{
    text = $0; sub(/^[^:]*:[0-9]+:/, "", text)
    if (text !~ /^[ \t]*\/\//) print $0
  }')
  if [ -n "$url_hits" ]; then print_hits "URL in source" "$url_hits"; fail=1; fi
fi

# 5. No build scripts: they run arbitrary code at build time. Catches both a
#    build.rs file anywhere under crates/ and a custom `build = "..."` key.
for f in $(find crates -name build.rs -type f); do
  echo "check-offline: build script: $f"; fail=1
done
if grep -nE '^[[:space:]]*build[[:space:]]*=' crates/*/Cargo.toml; then
  echo "check-offline: build script key (above) is not allowed"; fail=1
fi

# 6. No source pulled in from outside the scanned tree: `#[path = ...]`,
#    `include!` and `include_bytes!`. `include_str!` stays allowed (it embeds
#    rules/gitleaks.toml as text, per SPEC/ARCHITECTURE).
# shellcheck disable=SC2086
scan "path/include" "" \
  '#!?\[[[:space:]]*path|(^|[^A-Za-z0-9_])include(_bytes)?[[:space:]]*!' $src_dirs

# 7. Every workspace member must live directly under crates/ (otherwise its
#    src would escape this scan), and the root manifest must not be a package.
members=$(awk '
  /^[[:space:]]*members[[:space:]]*=/ { on = 1 }
  on { print; if ($0 ~ /\]/) exit }
' Cargo.toml | grep -oE '"[^"]*"' | tr -d '"')
if [ -z "$members" ]; then
  echo "check-offline: cannot read [workspace] members from Cargo.toml"; fail=1
fi
for m in $members; do
  case "$m" in
    *..*) echo "check-offline: workspace member outside crates/: $m"; fail=1 ;;
    crates/*/*) echo "check-offline: workspace member outside crates/<name>: $m"; fail=1 ;;
    crates/?*) ;;
    *) echo "check-offline: workspace member outside crates/: $m"; fail=1 ;;
  esac
done
if grep -nE '^[[:space:]]*\[package\]' Cargo.toml; then
  echo "check-offline: root Cargo.toml must stay a virtual manifest"; fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "check-offline: FAILED (SPEC §10.2)"; exit 1
fi
echo "check-offline: OK"
