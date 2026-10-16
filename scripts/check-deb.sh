#!/usr/bin/env bash
# check-deb.sh DEB GUI_BIN CLI_BIN   (PKG1, D114; used by release.yml package-linux)
# Fails unless the .deb has (PKG1, D123):
#   - Package veilcode, Architecture amd64, the D114 Maintainer;
#   - a Depends line with libc6 and every GUI runtime library below;
#   - exactly the expected regular files (no more, no fewer);
#   - usr/bin/veilcode-gui and usr/bin/veilcode byte-identical to GUI_BIN/CLI_BIN;
#   - modes -rwxr-xr-x 0/0 for usr/bin/*, -rw-r--r-- 0/0 otherwise;
#   - a control archive holding exactly ./control (no maintainer scripts).
# Exit 0 = OK, 1 = mismatch, 2 = usage error. Needs dpkg-deb.
# Plain bash: no mapfile or associative arrays.
set -u

if [ "$#" -ne 3 ] || [ ! -f "$1" ] || [ ! -f "$2" ] || [ ! -f "$3" ]; then
  echo "usage: check-deb.sh DEB GUI_BIN CLI_BIN" >&2
  exit 2
fi
deb=$1 gui=$2 cli=$3
status=0
fail() { echo "check-deb: $*" >&2; status=1; }

field() { dpkg-deb -f "$deb" "$1"; }
[ "$(field Package)" = veilcode ] || fail "Package is '$(field Package)', want veilcode"
[ "$(field Architecture)" = amd64 ] || fail "Architecture is '$(field Architecture)', want amd64"
want_maint='Muhammed Noufal <muhammednoufal7@gmail.com>'
[ "$(field Maintainer)" = "$want_maint" ] || fail "Maintainer is '$(field Maintainer)'"

# Depends: split on ',' and '|', drop version constraints, one name per line.
depends=$(field Depends | tr ',|' '\n\n' | sed -e 's/(.*//' -e 's/[[:space:]]//g' | grep -v '^$')
for lib in libc6 libgl1 libgl1-mesa-dri libglx-mesa0 libegl1 libegl-mesa0 \
           libx11-6 libx11-xcb1 libxcursor1 libxi6 libxrandr2 libxkbcommon0 \
           libxkbcommon-x11-0 libwayland-client0 libwayland-cursor0; do
  printf '%s\n' "$depends" | grep -Fxq "$lib" || fail "Depends lacks $lib"
done

# Regular files only ('-' in the mode column); directories are not listed.
want_files='./usr/bin/veilcode
./usr/bin/veilcode-gui
./usr/share/applications/veilcode.desktop
./usr/share/doc/veilcode/LICENSE-APACHE
./usr/share/doc/veilcode/LICENSE-MIT
./usr/share/doc/veilcode/THIRD_PARTY_NOTICES
./usr/share/doc/veilcode/copyright'
listing=$(dpkg-deb -c "$deb")
got_files=$(printf '%s\n' "$listing" | awk 'substr($1,1,1) != "d" {print $6}' | LC_ALL=C sort)
if [ "$got_files" != "$want_files" ]; then
  fail "file list differs from the expected set:"
  printf '%s\n' "$got_files" >&2
fi

# Modes and owners (D123): binaries -rwxr-xr-x 0/0, every other file -rw-r--r-- 0/0.
bad_modes=$(printf '%s\n' "$listing" | awk 'substr($1,1,1) != "d" {
  want = ($6 ~ /^\.\/usr\/bin\//) ? "-rwxr-xr-x" : "-rw-r--r--"
  if ($1 != want || $2 != "0/0") print $1, $2, $6 }')
[ -z "$bad_modes" ] || fail "unexpected mode or owner: $bad_modes"

# The control archive holds only the control file: no maintainer scripts (D123).
ctrl=$(dpkg-deb --ctrl-tarfile "$deb" | tar -tf - | LC_ALL=C sort)
[ "$ctrl" = './control' ] || fail "control archive is not exactly ./control: $(printf '%s' "$ctrl" | tr '\n' ' ')"

# The packaged binaries must be the attested build outputs, unmodified.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dpkg-deb -x "$deb" "$tmp"
cmp -s "$tmp/usr/bin/veilcode-gui" "$gui" || fail "usr/bin/veilcode-gui differs from $gui"
cmp -s "$tmp/usr/bin/veilcode" "$cli" || fail "usr/bin/veilcode differs from $cli"

[ "$status" -eq 0 ] && echo "check-deb: $deb OK"
exit "$status"
