# Veilcode

Developers paste server code into AI assistants, often including `.env` files
and config secrets. Veilcode masks those secrets in a copy of a code folder with
unique placeholders, keeps the real values in a local encrypted vault, and
restores them after the AI work is done, even if the AI moved, renamed or edited
the code. It is a CLI today; a native desktop app is planned.

- [Threat model](docs/THREAT_MODEL.md): what Veilcode protects against, and
  what it does not.
- [Verify it yourself](docs/VERIFY_OFFLINE.md): run it with no network, watch
  its system calls, check release checksums and attestations.

## Status

**Pre-alpha.** v0.1.0 is the first release and contains the `veilcode` CLI
only. The desktop app (`veilcode-gui`) is not released yet. Read
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
- Linux, x86_64 (a static binary that does not depend on the distribution's C
  library)

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

The binaries are **not code signed** yet (planned for a later version). On
Windows, SmartScreen may warn when you start `veilcode.exe`; the checksum and
attestation are how you check the file instead.

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
- Veilcode does not protect against malware or other users with your
  privileges, a compromised build pipeline, or clipboard and backup tools
  copying restored secrets. See the [threat model](docs/THREAT_MODEL.md).

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
