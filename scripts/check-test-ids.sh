#!/usr/bin/env bash
# Fails if any `Type: auto` test ID in docs/TEST_CASES.md, for phases up to the
# current phase in docs/PLAN.md, has no Rust test fn named `<id>_...`, or if any
# test is #[ignore]d. Prevents claiming tests that do not exist.
set -euo pipefail
cd "$(dirname "$0")/.."

cur=$(grep -Eo 'Current phase: P[0-9]+' docs/PLAN.md | head -n1 | grep -Eo '[0-9]+$')
[ -n "$cur" ] || { echo "check-test-ids: cannot read current phase from docs/PLAN.md"; exit 1; }

ids=$(awk -v cur="$cur" '
  /^## P[0-9]+/              { p = substr($2, 2) + 0 }
  /^### [A-Z]+[0-9]+[a-z]? / { id = $2 }
  /^Type: auto/ && p <= cur  { print id }
' docs/TEST_CASES.md)

pending=$(awk -v cur="$cur" '
  /^## P[0-9]+/              { p = substr($2, 2) + 0 }
  /^### [A-Z]+[0-9]+[a-z]? / { id = $2 }
  /^Type: pending/ && p <= cur { print id }
' docs/TEST_CASES.md)

dirs=()
for d in crates app/src-tauri; do
  if [ -d "$d" ]; then dirs+=("$d"); fi
done

fail=0
if [ -n "$ids" ]; then
  if [ ${#dirs[@]} -eq 0 ]; then
    echo "check-test-ids: no source directories found"; exit 1
  fi
  for id in $ids; do
    fn=$(printf '%s' "$id" | tr 'A-Z' 'a-z')
    if ! grep -rqE "fn ${fn}_[a-z0-9_]*[[:space:]]*\(" --include='*.rs' "${dirs[@]}"; then
      echo "MISSING test for $id (expected: fn ${fn}_...)"
      fail=1
    fi
  done
fi

if [ ${#dirs[@]} -gt 0 ] && grep -rnE '#\[ignore' --include='*.rs' "${dirs[@]}"; then
  echo "check-test-ids: #[ignore] is not allowed"
  fail=1
fi

for id in $pending; do
  echo "note: $id is pending a decision (see docs/DECISIONS.md)"
done

[ $fail -eq 0 ] && echo "check-test-ids: OK (phase P$cur)"
exit $fail
