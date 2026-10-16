#!/usr/bin/env bash
# check-version.sh TAG VERSION...   (D121; used by every release.yml job with a checkout)
# Fails unless each VERSION equals the tag's version: TAG without the leading
# 'v' and without a '-rcN' suffix (v0.2.0-rc1 -> 0.2.0). VERSION may be given as:
#   0.2.0                                   plain
#   veilcode 0.2.0                          `veilcode --version` output (last word)
#   path+file:///.../veilcode-cli#0.2.0     `cargo pkgid` output (after '#',
#   path+file:///...#veilcode-cli@0.2.0      then after '@' if present)
# Exit 0 = all equal, 1 = mismatch, 2 = usage error. Plain bash (Git Bash, macOS 3.2).
set -u

if [ "$#" -lt 2 ]; then
  echo "usage: check-version.sh TAG VERSION..." >&2
  exit 2
fi
tag=$1
shift
want=${tag#v}
case "$want" in
  *-rc[0-9]*) want=${want%-rc*} ;;
esac
case "$want" in
  ''|*[!0-9.]*) echo "check-version: tag '$tag' has no plain x.y.z version" >&2; exit 1 ;;
esac

status=0
for raw in "$@"; do
  v=${raw##* }     # last word of `--version` output
  v=${v##*#}       # cargo pkgid: after '#'
  v=${v##*@}       # cargo pkgid: after '@' (name@version form)
  if [ "$v" = "$want" ]; then
    echo "check-version: '$raw' -> $v OK"
  else
    echo "check-version: '$raw' -> '$v', but tag $tag means $want" >&2
    status=1
  fi
done
exit "$status"
