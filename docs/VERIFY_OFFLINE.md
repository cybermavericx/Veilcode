# Verifying Veilcode yourself

You do not have to trust the offline claim or the release files. This page
shows how to check both. The claim being checked is exactly SPEC §2.1 (see
[THREAT_MODEL.md](THREAT_MODEL.md) §8).

Examples use a throwaway folder `app/` with generated test values. Never use
real secrets while experimenting, and never paste secret values into commands.

---

## 1. Check the release files

Each GitHub release has these files (`<tag>` is the release tag, for example
`v0.2.0`). Releases up to `v0.1.0-rc2` contain only the four CLI files below
plus `SHA256SUMS`.

**Command-line tool (CLI)**

| File | What it is |
|---|---|
| `veilcode-<tag>-x86_64-unknown-linux-musl` | Linux x86_64 CLI binary (static) |
| `veilcode-<tag>-x86_64-pc-windows-msvc.exe` | Windows x86_64 CLI binary |
| `veilcode-<tag>-x86_64-unknown-linux-musl.cdx.json` | CycloneDX SBOM of the Linux CLI |
| `veilcode-<tag>-x86_64-pc-windows-msvc.cdx.json` | CycloneDX SBOM of the Windows CLI |

**Desktop app (from v0.2.0)**

| File | What it is |
|---|---|
| `veilcode-gui-<tag>-x86_64-unknown-linux-gnu` | Linux x86_64 GUI binary (needs glibc and X11/Wayland libraries) |
| `veilcode-gui-<tag>-x86_64-pc-windows-msvc.exe` | Windows x86_64 GUI binary |
| `veilcode-gui-<tag>-x86_64-unknown-linux-gnu.cdx.json` | CycloneDX SBOM of the Linux GUI (see the note below) |
| `veilcode-gui-<tag>-x86_64-pc-windows-msvc.cdx.json` | CycloneDX SBOM of the Windows GUI |
| `veilcode-<tag>-amd64.deb` | Debian/Ubuntu package with the CLI, the GUI, a desktop entry and the licences |
| `veilcode-<tag>-x86_64-linux.tar.gz` | The same Linux files as a plain archive |
| `veilcode-<tag>-x86_64-windows.msi` | Windows per-user installer (CLI, GUI, Start-menu shortcut; no admin needed) |
| `veilcode-<tag>-x86_64-windows.zip` | The same Windows files as a portable archive |

That is 12 files from v0.2.0 on. Every release also has `SHA256SUMS`: the
SHA-256 checksums of every file above. `SHA256SUMS` itself is not attested;
it is checked against the attested files.

**Note on the Linux GUI SBOM (D119):** it lists 12 crates, among them zbus,
atspi and accesskit_unix, that the Linux build does not compile. The likely
cause is that the SBOM tool merges features across platforms; this has not
been confirmed. Over-listing never hides a component. To see exactly what the
Linux GUI contains, run
`cargo tree --locked -e normal -p veilcode-gui --target x86_64-unknown-linux-gnu`
in the source tree at the release tag.

Build-provenance attestations for all 12 files (binaries, packages and SBOMs) are stored by
GitHub and checked with `gh` (below). Download the files into one folder and
verify them **before** renaming anything. Below, `<file>` stands for one of the
file names above.

### Checksums

Linux:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

Each downloaded file must print `OK`. (`--ignore-missing` skips files listed in
`SHA256SUMS` that you did not download.)

Windows (PowerShell):

```powershell
# Get-FileHash uses SHA256 by default and prints upper-case hex; PowerShell's
# -eq on strings is case-insensitive, so it matches the lower-case SHA256SUMS.
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators
$name = '<file>'
$expected = ((Get-Content .\SHA256SUMS | Where-Object { $_ -like "*$name" }) -split '\s+')[0]
(Get-FileHash -Algorithm SHA256 -LiteralPath ".\$name").Hash -eq $expected
```

It must print `True`.

A checksum only proves the file matches `SHA256SUMS`, which came from the same
release page. The attestation below proves who built it.

### Build-provenance attestation

With the GitHub CLI (`gh`, logged in):

```sh
gh attestation verify <file> \
  --repo cybermavericx/Veilcode \
  --signer-workflow cybermavericx/Veilcode/.github/workflows/release.yml \
  --source-ref refs/tags/<tag> \
  --deny-self-hosted-runners
```

This checks that `<file>` was built by the `release.yml` workflow of
`cybermavericx/Veilcode`, from the tag `<tag>`, on a GitHub-hosted runner. Run
it for each binary and SBOM you downloaded. If it fails, do not use the file,
and report it (see [SECURITY.md](../SECURITY.md)).

The signer check proves **which workflow file** built the file, not that the
workflow's content was reviewed. Also check that the release tag points to a
commit on the `main` branch of the repository.

Release binaries are **not code signed** yet (D143). On Windows, SmartScreen may
warn when you start `veilcode.exe` or the `.msi` ("Windows protected your PC",
"Publisher: Unknown publisher"); the checksum and attestation are how you check
the file instead. Choose **More info**, then **Run anyway**, only after both
checks above pass.

---

## 2. Linux: run Veilcode with no network at all

### 2.1 In an empty network namespace

A new network namespace has only a loopback interface, which is down, so no
program inside it can reach any network. If Veilcode works there, it did not
need the network.

```sh
unshare -rn veilcode scan app
unshare -rn veilcode mask app --out app-masked --vault app.vc
```

`-r` maps your user to root inside a new user namespace, and `-n` creates the
network namespace; you stay unprivileged on the host.

Some distributions block unprivileged user namespaces (for example Ubuntu 24.04
restricts them with AppArmor), and `unshare -rn` then fails with
"Operation not permitted". In that case use `sudo` to create the namespace and
`setpriv` to drop back to your own user before Veilcode starts:

```sh
sudo unshare -n -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups -- \
  "$PWD/veilcode" mask "$PWD/app" --out "$PWD/app-masked" \
  --vault "$PWD/app.vc" --profile "$PWD/app.profile.toml"
```

Notes for this form:

- Give the binary as an absolute path (here a `veilcode` in the current
  folder): `sudo` searches its own `secure_path`, not your `PATH`.
- `sudo` may change `HOME`, which would change the default vault and profile
  locations, so pass `--vault` and `--profile` explicitly. An explicitly passed
  profile file that does not exist yet is treated as an empty profile, so this
  works even if you never created `app.profile.toml`; point it at your real
  per-project profile if you have one.

To confirm the namespace really is empty:

```sh
unshare -rn cat /proc/net/dev
```

Only `lo` should be listed.

### 2.2 Watching the system calls with strace

```sh
strace -f -e trace=socket,connect,execve -o veilcode.trace \
  veilcode mask app --out app-masked --vault app.vc
grep -E 'socket\(|connect\(|execve\(' veilcode.trace
```

What to look for:

- **`execve`:** exactly one line, the start of `veilcode` itself. Any further
  `execve` would mean Veilcode launched another program.
- **`socket(` / `connect(`:** the only family allowed is `AF_UNIX` (local
  sockets, for example a display server once the desktop app ships). Any
  `AF_INET`, `AF_INET6`, `AF_PACKET` or `AF_NETLINK` line is a failure; please
  report it. The CLI normally makes no socket calls at all.

You can combine both checks: `unshare -rn strace -f -e trace=socket,connect,execve …`.

The trace file contains file names and arguments, not file contents, but
delete it when you are done.

### 2.3 The repository's own audit script

From a clone of the repository, on Linux (or WSL) with Rust, `strace` and
util-linux installed:

```sh
bash scripts/net-audit.sh
```

It builds the CLI, generates a throwaway folder with random fake secrets, and
runs `--help`, `scan`, `mask`, `restore`, `vault status` and `vault purge`
inside an empty network namespace under
`strace -f -e trace=socket,connect,execve,io_uring_setup`. It fails on any
socket or connect family other than `AF_UNIX`, any `io_uring` use, any process
launch, or any scenario that fails, and finally checks that the round trip
restored the input byte for byte. It ends with `net-audit: OK` on success.

To audit a single command of your own (for example a downloaded release
binary), pass **absolute paths**, because the script changes to the
repository root before it runs anything:

```sh
bash scripts/net-audit.sh "$PWD/veilcode" scan "$PWD/app"
bash scripts/net-audit.sh --stdin "$PWD/passphrase.txt" \
  "$PWD/veilcode" --passphrase-stdin --vault "$PWD/app.vc" vault status
```

`--stdin FILE` feeds FILE to the command's standard input (use a file with a
throwaway passphrase, readable only by you). The command's own output is
discarded; the script prints only its verdict. The script picks `unshare -n` as
root, `unshare -rn` if user namespaces work, or `sudo -n unshare -n` with
`setpriv` otherwise.

---

## 3. Windows: block Veilcode in Windows Firewall

There is no strace equivalent in Windows CI, so this check is manual.

### 3.1 Add an outbound block rule

In an elevated PowerShell ("Run as administrator"), with the full path to your
`veilcode.exe`:

```powershell
# Parameters per Microsoft Learn, New-NetFirewallRule:
# https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
# -Direction Outbound | -Action Block | -Program takes the full path to the .exe
# | -Profile defaults to Any (Domain, Private and Public).
New-NetFirewallRule -DisplayName "Veilcode - block outbound" -Direction Outbound -Action Block -Program "C:\path\to\veilcode.exe"
```

Then run a full round trip as usual (`scan`, `mask`, `restore`). It must work
exactly as without the rule.

To remove the rule afterwards:

```powershell
# https://learn.microsoft.com/en-us/powershell/module/netsecurity/remove-netfirewallrule
Remove-NetFirewallRule -DisplayName "Veilcode - block outbound"
```

A block rule shows that Veilcode works without the network; it does not by
itself show that Veilcode never *tried*. For that, watch it:

### 3.2 Watch for network activity

- **Resource Monitor** (`resmon`): open the Network tab while Veilcode runs
  and check that `veilcode.exe` does not appear in the network activity or TCP
  connection lists.
- **Wireshark:** start a capture on your active network interface, run the
  round trip, stop the capture. Wireshark cannot filter by process, so close
  other network-heavy programs first and look for traffic that starts exactly
  when Veilcode runs. There should be none.

---

## 4. If you find network activity

Stop using that build and report it privately (see
[SECURITY.md](../SECURITY.md)). Include the command you ran, your OS, and the
offending trace lines, but **never** include secret values.
