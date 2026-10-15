#!/usr/bin/env bash
# net-audit.sh: runtime syscall audit (SPEC §10.3). Linux only, needs strace,
# unshare and setpriv (util-linux).
#
# Usage: net-audit.sh [--stdin FILE] [binary [args...]]
#   no arguments: build the CLI and the GUI and audit the default scenarios
#                 below (C9: --help, scan, mask, restore, vault status, vault
#                 purge; G6: veilcode-gui for GUI_SECONDS under xvfb-run).
#   binary args:  audit just that command (used by test O4 with probes).
#   --stdin FILE: the audited command reads FILE on stdin (a plain shell
#                 redirect, so no extra process appears in the trace).
#                 Without it, stdin is /dev/null.
#
# Each scenario runs inside an empty network namespace (only a down `lo`)
# under `strace -f -e trace=socket,connect,execve,io_uring_setup`. It fails on:
#   - socket()/connect() with ANY family other than AF_UNIX (named or numeric;
#     stricter than SPEC §10.3, which lists AF_INET/INET6/PACKET/NETLINK);
#   - any io_uring_setup (io_uring can do network I/O that strace's socket
#     filter would not see);
#   - any execve after the first one (the scenario binary itself);
#   - a scenario that exits non-zero or times out (the GUI scenario instead
#     must still be running when its GUI_SECONDS timer kills it).
# If any of these appear, stop and report; never allow-list them here.
set -eu
cd "$(dirname "$0")/.."

if [ "$(uname -s)" != "Linux" ]; then
  echo "net-audit: Linux only (strace); skipped on $(uname -s). Linux CI always runs it."
  exit 1
fi
for tool in strace unshare setpriv timeout od; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "net-audit: $tool not found (apt-get install strace util-linux coreutils)"
    exit 1
  fi
done

# Pick a way into an empty network namespace that works here:
#   root (WSL dev):         unshare -n
#   unprivileged userns:    unshare -rn  (often blocked by AppArmor on Ubuntu 24.04)
#   passwordless sudo (CI): sudo unshare -n, then drop back to our uid/gid
if [ "$(id -u)" -eq 0 ]; then
  NETNS="unshare -n --"
elif unshare -rn true >/dev/null 2>&1; then
  NETNS="unshare -rn --"
elif sudo -n true >/dev/null 2>&1; then
  NETNS="sudo -n unshare -n -- setpriv --reuid=$(id -u) --regid=$(id -g) --clear-groups --"
else
  echo "net-audit: cannot create a network namespace (no root, userns or sudo)"
  exit 1
fi

# Self-check: the namespace must contain no interface except loopback.
# shellcheck disable=SC2086  # $NETNS is a command prefix, split on purpose
ifaces=$($NETNS cat /proc/net/dev | awk -F: 'NR > 2 { gsub(/ /, "", $1); print $1 }')
if [ "$ifaces" != "lo" ]; then
  echo "net-audit: network namespace is not empty (interfaces: $ifaces)"
  exit 1
fi

TIMEOUT_S=60
GUI_SECONDS=10
fail=0
work=""
log=$(mktemp "${TMPDIR:-/tmp}/net-audit.XXXXXX")
trap 'rm -f "$log"; if [ -n "$work" ]; then rm -rf "$work"; fi' EXIT

# check_trace LOG: print offending strace lines; exit status 1 if any.
check_trace() {
  awk '
    /socket\(/ {
      s = $0; sub(/.*socket\(/, "", s); split(s, a, /[,)]/)
      if (a[1] != "AF_UNIX") { print "  forbidden socket family: " $0; bad = 1 }
    }
    /connect\(/ && match($0, /sa_family=[^,}]*/) {
      f = substr($0, RSTART + 10, RLENGTH - 10)
      if (f != "AF_UNIX") { print "  forbidden connect family: " $0; bad = 1 }
    }
    /io_uring_setup\(/ { print "  io_uring is not allowed: " $0; bad = 1 }
    /execve\(/ { if (++n > 1) { print "  process spawn (execve) is not allowed: " $0; bad = 1 } }
    END { exit bad }
  ' "$1"
}

# audit STDIN_FILE CMD [ARGS...]: run one scenario in the netns under strace,
# stdin redirected from STDIN_FILE, and check it. Output is discarded so no
# value the binary prints can reach the log.
audit() {
  in=$1; shift
  echo "net-audit: running: $*"
  set +e
  # shellcheck disable=SC2086
  timeout "$TIMEOUT_S" $NETNS strace -f -e trace=socket,connect,execve,io_uring_setup \
    -o "$log" -- "$@" <"$in" >/dev/null 2>&1
  rc=$?
  set -e
  if ! check_trace "$log"; then
    echo "net-audit: FAIL: forbidden syscall(s) above in: $*"
    fail=1
  elif [ "$rc" -ne 0 ]; then
    echo "net-audit: FAIL: scenario exited $rc (124 = timeout): $*"
    fail=1
  else
    n=$(grep -cE '(socket|connect)\(' "$log" || true)
    echo "net-audit: ok ($n socket/connect calls, all AF_UNIX; no spawn, no io_uring)"
  fi
}

# audit_gui BIN: G6 (SPEC §10.3, D100). Runs BIN in the netns on a private
# Xvfb display for GUI_SECONDS. strace sits INSIDE xvfb-run, so only the GUI's
# own process tree is traced (not xvfb-run, xauth or Xvfb), and `timeout` sits
# outside strace, so the GUI is still the only execve allowed. WAYLAND_DISPLAY
# is unset so winit uses X11 (VERIFY_LOG 2026-10-14), and HOME/XDG dirs are
# throwaway. The inner exit status goes to a file, so the outer hang guard's
# 124 cannot be mistaken for the inner timer's 124 ("ran until killed").
audit_gui() {
  gui=$1
  gd="$work/gui"
  mkdir -p "$gd/home" "$gd/run"
  chmod 700 "$gd/run"
  echo "net-audit: running: xvfb-run -a $gui (${GUI_SECONDS} s)"
  set +e
  # shellcheck disable=SC2086,SC2016  # $NETNS split on purpose; sh -c script is literal
  timeout "$TIMEOUT_S" $NETNS env -u WAYLAND_DISPLAY \
    HOME="$gd/home" XDG_CONFIG_HOME="$gd/home/.config" XDG_DATA_HOME="$gd/home/.local/share" \
    XDG_CACHE_HOME="$gd/home/.cache" XDG_STATE_HOME="$gd/home/.local/state" XDG_RUNTIME_DIR="$gd/run" \
    xvfb-run -a -s "-screen 0 1280x800x24" \
    sh -c 'timeout "$1" strace -f -e trace=socket,connect,execve,io_uring_setup -o "$2" -- "$3"; echo $? >"$4"' \
    sh "$GUI_SECONDS" "$log" "$gui" "$gd/rc" </dev/null >/dev/null 2>&1
  set -e
  rc=$(cat "$gd/rc" 2>/dev/null || echo "none (xvfb-run failed or hung)")
  if ! check_trace "$log"; then
    echo "net-audit: FAIL: forbidden syscall(s) above in: $gui"
    fail=1
  elif [ "$rc" != 124 ]; then
    echo "net-audit: FAIL: GUI did not run for ${GUI_SECONDS} s (exit $rc; 124 = ran until killed): $gui"
    fail=1
  elif ! grep -q 'X11-unix' "$log"; then
    echo "net-audit: FAIL: GUI never connected to the X server: $gui"
    fail=1
  else
    n=$(grep -cE '(socket|connect)\(' "$log" || true)
    echo "net-audit: ok ($n socket/connect calls, all AF_UNIX; no spawn, no io_uring; ran ${GUI_SECONDS} s)"
  fi
}

# rand_hex BYTES: BYTES random bytes as lowercase hex (never printed).
rand_hex() {
  od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'
}

# default_scenarios: C9, the real CLI flow on a throwaway tree whose fake
# secrets are generated here at runtime (no secret-shaped literals in git).
default_scenarios() {
  cargo build --locked --quiet -p veilcode-cli --bin veilcode
  bin="${CARGO_TARGET_DIR:-target}/debug/veilcode"
  work=$(mktemp -d "${TMPDIR:-/tmp}/net-audit-work.XXXXXX")
  chmod 700 "$work"
  mkdir "$work/in"
  key=$(rand_hex 20)
  dbpw=$(rand_hex 12)
  printf 'API_KEY=%s\n' "$key" >"$work/in/.env"
  printf 'db = "%s://u:%s@h/db"\n' "postgres" "$dbpw" >"$work/in/config.toml"
  printf 'fn main() {}\n' >"$work/in/main.rs"
  (umask 077 && rand_hex 16 >"$work/pass" && echo >>"$work/pass")

  # Isolated vault and profile (a missing profile file means defaults).
  g="--vault $work/vault.vc --profile $work/profile.toml --passphrase-stdin"
  p="$work/pass"
  audit /dev/null "$bin" --help
  # shellcheck disable=SC2086  # $g is a list of plain flags, split on purpose
  audit /dev/null "$bin" $g scan "$work/in"
  # shellcheck disable=SC2086
  audit "$p" "$bin" $g mask "$work/in" --out "$work/out"
  # shellcheck disable=SC2086
  audit "$p" "$bin" $g restore "$work/out" --out "$work/out2" --keep
  # shellcheck disable=SC2086
  audit "$p" "$bin" $g vault status
  # shellcheck disable=SC2086
  audit "$p" "$bin" $g vault purge --yes

  # Round trip: masked copy must hide both secrets; restored copy must equal
  # the input byte for byte; purge must remove the vault. Never print values.
  if [ "$fail" -eq 0 ]; then
    if grep -rqF -e "$key" -e "$dbpw" "$work/out"; then
      echo "net-audit: FAIL: masked output still contains a generated secret"; fail=1
    fi
    if ! diff -rq "$work/in" "$work/out2" >/dev/null; then
      echo "net-audit: FAIL: restored output differs from the input"; fail=1
    fi
    if [ -e "$work/vault.vc" ]; then
      echo "net-audit: FAIL: vault file still exists after purge"; fail=1
    fi
    if [ "$fail" -eq 0 ]; then echo "net-audit: round trip ok (masked, restored == input, purged)"; fi
  fi

  # G6: the GUI, on a virtual X display (needs xvfb-run, from package xvfb).
  if ! command -v xvfb-run >/dev/null 2>&1; then
    echo "net-audit: FAIL: xvfb-run not found (apt-get install xvfb); the GUI audit cannot run"
    fail=1
    return
  fi
  cargo build --locked --quiet -p veilcode-gui --bin veilcode-gui
  audit_gui "${CARGO_TARGET_DIR:-target}/debug/veilcode-gui"
}

stdin_file=/dev/null
if [ "${1:-}" = "--stdin" ]; then
  if [ "$#" -lt 3 ] || [ ! -r "$2" ]; then
    echo "net-audit: usage: net-audit.sh [--stdin FILE] binary [args...]"; exit 1
  fi
  stdin_file=$2; shift 2
fi

if [ "$#" -gt 0 ]; then
  audit "$stdin_file" "$@"
else
  default_scenarios
fi

if [ "$fail" -ne 0 ]; then echo "net-audit: FAILED (SPEC §10.3)"; exit 1; fi
echo "net-audit: OK"
