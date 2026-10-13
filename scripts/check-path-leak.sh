#!/usr/bin/env bash
# check-path-leak.sh FILE PATH... (D92, release.yml)
# Fails if any build-machine PATH appears inside FILE (a release binary or
# SBOM). Each PATH is searched case-insensitively in three forms: as given,
# with '\' turned into '/', and with '/' turned into '\', so both D:\a\x and
# D:/a/x are caught. Exit 0 = clean, 1 = leak found, 2 = usage error.
# Plain bash: works on Git Bash, Ubuntu and macOS bash 3.2.
set -u

if [ "$#" -lt 2 ] || [ ! -f "$1" ]; then
  echo "usage: check-path-leak.sh FILE PATH..." >&2
  exit 2
fi
file=$1
shift

status=0
for p in "$@"; do
  # An empty path would match everything; treat it as a caller bug.
  if [ -z "$p" ]; then
    echo "check-path-leak: empty PATH argument" >&2
    exit 2
  fi
  fwd=$(printf '%s' "$p" | tr '\\' '/')
  back=$(printf '%s' "$p" | tr '/' '\\')
  for v in "$p" "$fwd" "$back"; do
    if grep -a -i -F -q -e "$v" -- "$file"; then
      echo "check-path-leak: $file contains build path: $v" >&2
      status=1
    fi
  done
done

if [ "$status" -eq 0 ]; then
  echo "check-path-leak: OK ($file)"
fi
exit "$status"
