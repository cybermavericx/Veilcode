# Veilcode

Developers paste server code into AI assistants, often including `.env` files
and config secrets. Veilcode masks those secrets in a copy of a code folder with
unique placeholders, keeps the real values in a local encrypted vault, and
restores them after the AI work is done, even if the AI moved, renamed or edited
the code. It is a CLI today; a native desktop app ships with v0.2.0 (not yet
released).

- [Threat model](docs/THREAT_MODEL.md): what Veilcode protects against, and
  what it does not.
- [Verify it yourself](docs/VERIFY_OFFLINE.md): run it with no network, watch
  its system calls, check release checksums and attestations.

## Status

**Pre-alpha.** The current release is the CLI pre-release `v0.1.0-rc2`; it
contains the `veilcode` CLI only. The desktop app (`veilcode-gui`) ships in
v0.2.0, which is not released yet. Read
[Honest limitations](#honest-limitations) before relying on it for real
secrets.

## Offline

**Offline design.** Veilcode has no network features. Its own crates make no
network calls and do not use `std::process::Command`; CI enforces this with
text checks and type-aware clippy bans. A fixed list of HTTP, TLS, DNS,
WebSocket and browser-launch crates is banned from the dependency graph (SPEC
§10.1). Some lower-level libraries can still open a network connection if the
environment tells them to: the X11 client libraries connect over TCP when
`DISPLAY` names another machine, or when a local display number gets no
answer. So on Linux the desktop app links no D-Bus client crate, and it starts
only if `DISPLAY` is unset or names a local display whose X server answers on
its local socket (D104, D105, D109). On Linux, CI runs defined CLI and GUI
scenarios under strace in an empty network namespace and fails if any
non-local socket is opened. This tests those scenarios; it does not prove
every possible code path. Windows has no runtime audit in CI.

See [VERIFY_OFFLINE.md](docs/VERIFY_OFFLINE.md) to check this yourself, and
[THREAT_MODEL.md](docs/THREAT_MODEL.md#8-offline-design-and-how-it-is-checked)
for exactly what is enforced and what is only tested.

## Supported platforms

- Windows 10/11, x86_64
- Linux, x86_64. The CLI is a static binary that does not depend on the
  distribution's C library. The desktop app is not static: it needs glibc and
  the X11 or Wayland and OpenGL runtime libraries (see below).

macOS is built and tested in CI but not released.

## Install

1. From the [GitHub Releases page](https://github.com/cybermavericx/Veilcode/releases),
   download `SHA256SUMS` and the binary for your platform (`<tag>` is the
   release tag, for example `v0.1.0`):
   - Linux (static binary): `veilcode-<tag>-x86_64-unknown-linux-musl`
   - Windows: `veilcode-<tag>-x86_64-pc-windows-msvc.exe`

   Each release also has one CycloneDX SBOM per binary:
   `veilcode-<tag>-x86_64-unknown-linux-musl.cdx.json` and
   `veilcode-<tag>-x86_64-pc-windows-msvc.cdx.json`.
2. **Before renaming anything**, verify the checksum and the build-provenance
   attestation as described in
   [VERIFY_OFFLINE.md](docs/VERIFY_OFFLINE.md#1-check-the-release-files).
   On Linux: `sha256sum -c --ignore-missing SHA256SUMS`.
3. Rename the binary and put it somewhere on your `PATH`:

   ```sh
   # Linux
   mv veilcode-<tag>-x86_64-unknown-linux-musl veilcode
   chmod +x veilcode
   ```
   ```powershell
   # Windows (PowerShell)
   Rename-Item veilcode-<tag>-x86_64-pc-windows-msvc.exe veilcode.exe
   ```

The binaries are **not code signed** yet (planned for a later version, D143). On
Windows, SmartScreen may warn when you start `veilcode.exe` or the `.msi`; the
checksum and attestation are how you check the file instead. See
[Troubleshooting](#troubleshooting) for what the warning looks like.

### Running the CLI

`veilcode` is a **command-line tool**: run it from PowerShell or a terminal.
Double-clicking `veilcode.exe` only flashes a console window that closes
straight away, because with no arguments it prints its help and exits.

Windows (PowerShell), from the folder you downloaded to:

```powershell
cd $HOME\Downloads
.\veilcode.exe --help
```

Linux, from the folder you downloaded to:

```sh
cd ~/Downloads
./veilcode --help
```

To run it as plain `veilcode` from any folder, move it into a folder on your
`PATH`.

### Desktop app (from v0.2.0)

**These files arrive with v0.2.0, which is not released yet.** Until then the
releases contain the CLI only. From v0.2.0 the release page also offers:

- **Windows:** a per-user `.msi` installer (no administrator rights needed; it
  adds a Start-menu shortcut for the desktop app), or a portable `.zip` with
  both `veilcode.exe` and `veilcode-gui.exe`. The installer does not add the
  CLI to `PATH`; run it by its full path in the install folder. Both files are
  unsigned, so SmartScreen may warn.
- **Linux:** a `.deb` package, installed with
  `sudo apt install ./veilcode-<tag>-amd64.deb` (for example
  `veilcode-v0.2.0-amd64.deb`), or a `.tar.gz` with both binaries. On Linux the
  desktop app is built for glibc (the CLI stays a static binary) and needs the
  X11 or Wayland and OpenGL runtime libraries. The `.deb` declares them as
  dependencies; with the `.tar.gz`, install them yourself. On Debian or Ubuntu,
  CI installs: `libgl1 libgl1-mesa-dri libglx-mesa0 libegl1 libegl-mesa0
  libx11-6 libx11-xcb1 libxcursor1 libxi6 libxrandr2 libxkbcommon0
  libxkbcommon-x11-0 libwayland-client0 libwayland-cursor0`.
- On Linux the desktop app **refuses to start unless `DISPLAY` is unset**
  (the Wayland path) **or names a local display** whose X server answers on
  its local socket. A forwarded or remote `DISPLAY`, such as one set by SSH X
  forwarding, is refused (D105, D109).
- **No screen-reader support on Linux** in v0.2.0. The accessibility bridge is
  built for Windows only, because the Linux one pulls in a D-Bus client that
  can be pointed at a network address (D104).

Verify every downloaded file (checksum and attestation) as described in
[VERIFY_OFFLINE.md](docs/VERIFY_OFFLINE.md#1-check-the-release-files) before
installing or extracting it.

## 60-second demo

This uses a throwaway folder with random test values (Linux shell; on Windows,
create the two files with any editor). Never experiment with real secrets.
The values are deliberately short (8 hex characters): longer random values are
also caught by the gitleaks `generic-api-key` rule, which would change the
output below.

```sh
mkdir my-app
printf 'DB_PASSWORD=%s\n' "$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')" > my-app/.env
printf 'customapi-pass: %s\n' "$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')" > my-app/config.yml
```

**1. Scan** (previews only, no vault needed):

```sh
veilcode scan my-app --profile my-app.profile.toml
```
```
.env:1:13  env-file  DB_PASSWORD  xxxx…(8)
1 findings in 2 scanned files (0 ignored by profile)
2 rule or ignore-file warnings (see --json)
```

`customapi-pass` is not a key name Veilcode knows, so it was missed.

**2. Teach the detection profile** that key name, then scan again:

```sh
veilcode profile add-key customapi-pass --profile my-app.profile.toml
veilcode scan my-app --profile my-app.profile.toml
```
```
.env:1:13  env-file  DB_PASSWORD  xxxx…(8)
config.yml:1:17  custom-key  customapi-pass  xxxx…(8)
2 findings in 2 scanned files (0 ignored by profile)
2 rule or ignore-file warnings (see --json)
```

**3. Mask** into a new folder, with a vault just for this project. Veilcode
asks for a passphrase (at least 12 characters) and creates the vault:

```sh
veilcode mask my-app --out my-app-masked --vault my-app.vc --profile my-app.profile.toml
veilcode vault status --vault my-app.vc
```
```
creating a new vault at my-app.vc
masked 2 secrets in 2 files (session <id>, expires in 30 days)
sessions: 1
...
```

`my-app-masked/config.yml` now reads `customapi-pass: VEILCODE_CUSTOMAPI_PASS_<hex8>`.
Share `my-app-masked` with your AI assistant.

Tokens have the form `<PREFIX><NAME>_<hex8>`. The prefix is `VEILCODE_` unless
you choose another one with `--token-prefix` (or the "Placeholder prefix" field
on the app's Mask screen), for example `--token-prefix Infra_Mask_`. A prefix is
2–16 ASCII characters: a letter first, then letters, digits or `_`, ending with
`_`. Restore finds the tokens of every prefix stored in the vault. A prefix
other than `VEILCODE_` must not start with `VEILCODE_`. `veilcode scan` has
no vault, so it lists tokens of a custom prefix as findings; `mask` and
`restore` know the vault's prefixes and leave them alone (`mask` prints how
many findings already were placeholder tokens).

The prefix of a successful mask is remembered for that folder, inside the
encrypted vault (D141). The next `mask` of the same folder without
`--token-prefix` uses it, and every `mask` prints the prefix it used, for
example `placeholder prefix: Infra_Mask_ (remembered for this folder)`. Pass
`--token-prefix VEILCODE_` to go back to the default. In the app, the field
is filled in when you scan the folder, with the hint "remembered for this
project" and a "Reset to default" button. The memory is kept only while the
vault file exists: when the last session is forgotten (for example after a
clean restore of your only session) the vault file is deleted, and the memory
with it. Saving the vault with v0.2.0-rc3 drops the memory (tested).

Older versions: the v0.2.0-rc3 CLI, tested, refuses a vault that holds a
token with a custom prefix, with "wrong passphrase or corrupted vault" (the
vault is not damaged). A vault with only `VEILCODE_` tokens written by this
version opened and restored in v0.2.0-rc3. Versions before rc3 were not
tested (D138).

**4. Restore** the folder the AI gave back (here `my-app-from-ai`) into a new
folder:

```sh
veilcode restore my-app-from-ai --out my-app-restored --vault my-app.vc --profile my-app.profile.toml
veilcode vault status --vault my-app.vc
```
```
restored 2 files, 2 tokens replaced
session forgotten; vault file removed (no sessions left)
error: no vault at my-app.vc
```

The restore was clean, so Veilcode forgot the session and deleted the now
empty vault. `my-app-restored` contains the real values again; treat it like
the original folder.

Notes:

- Veilcode never modifies the input folder. `--out` must be a new folder
  outside the input.
- `--passphrase-stdin` reads the passphrase as one line from stdin instead of
  the terminal (for scripts).
- `veilcode --help` and `veilcode <command> --help` list every option. Exit
  code 0 means success, 2 means error.

## Detection profile

The profile is a small TOML file that tunes detection. It **never contains
secret values**. Default location: `profile.toml` in Veilcode's local config
dir; use `--profile FILE` for a per-project profile (recommended, like
per-project vaults).

```sh
veilcode profile add-key customapi-pass        # also detect this key name
veilcode profile ignore-key DB_NAME            # never auto-select this key name
veilcode profile ignore --path config/.env --key APP_KEY_ID   # one false positive in one file
veilcode profile list
```

`remove-key`, `unignore-key` and `unignore` undo these. Key names are matched
case-insensitively, with `-`, `.` and space treated as `_`.

- Ignored findings are still listed and counted ("ignored by profile"); they
  are just not masked by default.
- **The profile is never read from the input folder.** A repository (or an AI
  edit) cannot ship a profile that hides its own secrets. Only `--profile` or
  your config dir is used.
- To skip a finding for one run only, write `veilcode scan --json FILE`, delete
  that finding from FILE, and pass `veilcode mask --findings FILE`.

## Secret retention

The vault holds the real secrets of every project that has not finished its
round trip, so Veilcode keeps it as small as possible:

- After a clean restore, the project's session and its secrets are forgotten
  (use `--keep` to retain them).
- Sessions expire after 30 days by default (`--ttl-days`, 1–365).
- An empty vault file is deleted.
- A separate vault per project (`--vault <project>.vc`) is recommended.
  Keep it outside the project folder.
- `veilcode vault status` shows how many sessions remain and when the next one
  expires; `veilcode vault purge` removes everything.
- The default vault and profile live in your **local** (non-roaming) data and
  config folders: on Windows under `%LOCALAPPDATA%\Cybermavericx\Veilcode\`,
  on Linux in `~/.local/share/veilcode/` and `~/.config/veilcode/` (or the
  `$XDG_DATA_HOME` / `$XDG_CONFIG_HOME` equivalents).

Limits you should know about:

- Deleting rewrites or removes the encrypted file, but SSD wear-levelling,
  backups or cloud sync of the Veilcode data folder may keep older encrypted
  copies. Exclude that folder (and your per-project vault files) from sync and
  backup.
- Your passphrase is the last line of defence for any copy that survives. There
  is no recovery if you forget it.
- Malware running while the vault is unlocked defeats all of this.

## Honest limitations

- **Detection is best-effort.** Veilcode cannot recognise every secret.
  Anything no detector matches stays in the masked output. Review the scan
  before sharing the masked folder, add missing key names to your profile, and
  use `.veilcodeignore` to exclude files.
- **PHP `define()` values containing a quote character are not detected.**
- **The restore output contains real secrets.** Restore puts a value back
  wherever its token appears, including places the AI moved it to. Review the
  AI's changes before you run or publish them.
- **Binaries are unsigned** for now; Windows SmartScreen may warn.
- **macOS is not released** (built and tested in CI only).
- **The desktop app (from v0.2.0) has no screen-reader support on Linux**
  (D104).
- Veilcode does not protect against malware or other users with your
  privileges, a compromised build pipeline, or clipboard and backup tools
  copying restored secrets. See the [threat model](docs/THREAT_MODEL.md).

## Troubleshooting

- **Windows shows "Windows protected your PC".** This is Microsoft Defender
  SmartScreen. It lists "Publisher: Unknown publisher" because the release
  files are not code signed yet (D143); it was seen with the
  `v0.2.0-rc4` `.msi`. Verify the file's checksum and attestation first
  ([VERIFY_OFFLINE.md](docs/VERIFY_OFFLINE.md#1-check-the-release-files)).
  Only if both pass, choose **More info**, then **Run anyway**. If either
  check fails, do not run the file.

- **The desktop app does not open on Windows.** Look for
  `startup-error.txt` in `%LOCALAPPDATA%\Cybermavericx\Veilcode\data`. It
  holds the error that stopped the window from opening.

## Prior art

Other projects already work on masking sensitive data before it reaches an
LLM. Veilcode builds on the same idea:

- [opsmask](https://github.com/ching-kuo/opsmask): a Go CLI that pseudonymizes
  secrets and identifiers in logs and supports a round trip back to the
  originals.
- [CodeMask OSS](https://github.com/codemasklab/codemask-oss): an open-source
  code and text masker for LLM safety, with Python and Text modes.
- [Carnaval](https://github.com/carnaval-ai/carnaval): reversible PII
  anonymization for LLM pipelines.
- [ragkit-redactor](https://pypi.org/project/ragkit-redactor/): reversible
  masking of PII and secrets in text.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option. Third-party material is listed in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
