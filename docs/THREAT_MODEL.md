# Veilcode — Threat model

This expands SPEC §11. It describes what Veilcode protects, against whom, how,
and, just as important, what it does **not** protect against. Decision numbers
(Dnn) refer to `docs/DECISIONS.md`; section numbers (§n) refer to `docs/SPEC.md`.

Scope: the `veilcode` CLI (v0.1.0) and the core library. The desktop app
(`veilcode-gui`) is not released yet; GUI-specific notes below describe its
planned design (SPEC §6.3, §7, §10.4).

## 1. What Veilcode does

You run `veilcode mask` on a code folder. Veilcode writes a **new** folder in
which detected secrets are replaced by placeholder tokens such as
`VEILCODE_DB_PASSWORD_<hex8>`, and stores the real values in an encrypted vault
file. You give the masked folder to an AI assistant yourself. Afterwards
`veilcode restore` writes another new folder with the tokens replaced by the
real values. Veilcode has no feature that talks to the AI assistant or to any
other network service; §8 says exactly what is enforced and what is only
tested.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Secret values in your code | The input folder (unchanged), the vault (encrypted), the restore output (plain) | The thing being protected |
| The vault file (`vault.vc`) | Default: the local (non-roaming) data dir, see §7 below; or `--vault FILE` | Holds the real values of every session that has not finished its round trip |
| The vault passphrase | Your head / password manager; briefly in Veilcode's memory | Decrypts the vault; there is no recovery |
| The restore output folder | Wherever you pass to `restore --out` | Contains **real secrets in plain text**, by design |
| The detection profile (`profile.toml`) | Default: the local config dir; or `--profile FILE` | Controls which findings are masked; holds no secret values (D74, D79) |
| Reports and findings files (`--report`, `--json`) | Wherever you write them (refused inside the input folder, D89) | Contain previews only (first 4 characters + `…` + length), never values |

## 3. Trust boundaries

Everything crossing these boundaries is treated as hostile (ARCHITECTURE §2):

| Input | Why it is untrusted | Guard |
|---|---|---|
| Input folder content | Arbitrary or AI-modified files: huge, binary, symlinks, odd encodings | Walk never follows symlinks; files are classified (binary: NUL in first 8 KiB; oversized: > 5 MiB; symlink); only text files are scanned, with byte regexes (§5) |
| Findings / ScanReport file (`mask --findings`) | User-editable JSON: path traversal, bogus offsets | Every `rel_path` is validated before any I/O (no `..`, `.`, empty, root, drive or UNC components); offsets are bounds-checked; every file must match its recorded sha256 ("file changed since scan — rescan"); read through a 64 MiB cap (§6.1, D89) |
| Vault file | Tampered or corrupted header and ciphertext | KDF parameters are bounds-checked before Argon2 runs; AEAD with the header as associated data; one generic error for every failure: "wrong passphrase or corrupted vault" (§7) |
| Output dir path | May overlap the input, already exist, or sit under a link | Must not exist and must not be inside the input; Veilcode creates it (`0700` on Unix) and, on Unix, refuses a group/other-writable parent without the sticky bit (§6.1, D68); every joined write path must stay under the output dir (§6.2) |
| Passphrase | User input | Minimum 12 Unicode scalar values on vault creation; held in a zeroizing buffer (§7, D82) |
| Detection profile | Anyone who can write it can make Veilcode skip findings | Never read from the input folder (D75); must be a regular file of at most 1 MiB, strict TOML, validated key names and paths, size limits (D79, D88) |

## 4. Attacker models and what Veilcode does

### 4.1 The AI provider (and anyone it shares data with)

Goal: read your secrets from what you upload.

- Detected secrets are replaced by tokens before you share anything; values
  stay in the encrypted vault (§2.3).
- `.git/` is always excluded and cannot be re-enabled, because git history
  holds secrets (§5).
- Binary and oversized files are **not copied** to the masked folder unless you
  pass `--include-unscanned`, because they were not scanned (§6.1).
- Symlinks and excluded paths are never copied (§6.1).

What the provider still sees: all code and every secret **no detector
recognised** (detection is best-effort, §6 below), the file layout, and the
token names. A token name is built from the key name or rule id
(`<PREFIX><NAME>_<HEX8>`, §4; the prefix is `VEILCODE_` unless the user chose
another one, D138), so it reveals *that* a value such as a database password
exists, but not the value. The `HEX8` part is random and carries no
information about the value. A custom prefix hides that Veilcode was used only
as far as the prefix itself does; the token shape (`_` + 8 lowercase hex) is
the same.

### 4.2 A malicious repository or AI-modified input

Goal: make Veilcode miss secrets, write outside its output folder, hang, or
leak values.

- **Shipped profile:** the detection profile is never read from the input
  folder automatically (D75), so a repo cannot ship a profile that ignores
  everything. Ignored findings are always listed and counted, never silently
  dropped (D78).
- **Path tricks:** symlinks are never followed or copied; `rel_path` values are
  validated; every write path is checked to stay under the output dir;
  the output dir must be new (§6, D68).
- **Changed files:** mask refuses if any text file changed since the scan or a
  new one appeared (§6.1).
- **Resource abuse:** files over 5 MiB are not scanned; the custom-key detector
  is linear-time (D87); the profile and findings files have size caps
  (D79, D88, D89).
- **On restore**, the AI-edited folder is scanned again: any finding is
  reported as a **new secret introduced by the AI**; token-shaped strings not in
  the vault are left untouched and reported as **unknown**; tokens of the
  session that no longer appear are reported as **missing** (§6.2). A restore
  that is not clean keeps its session in the vault and says why (D60).

Limitation: restore replaces **every** known token wherever it appears (§6.2
step 3), because the AI is allowed to move and rename code. An AI edit can
therefore copy a token into a new place (for example a log statement or a file
you later publish), and restore will put the real value there. Review the
restored changes like any other AI change before you run or publish them.

### 4.3 Another local user on the same machine

Goal: read the vault, the restore output, or tamper with output folders.

- The vault is encrypted with XChaCha20-Poly1305 under a key derived with
  Argon2id (64 MiB, 3 passes) from your passphrase (§7). It is saved as
  `0600` on Unix.
- Output folders are created by Veilcode itself as `0700` on Unix, and Unix
  parents that others can write to (without the sticky bit) are refused (D68).
- Restore output contains real secrets by design. Protect it like the original
  folder and delete it when you are done.

On Windows, Veilcode relies on the default permissions of your user profile
folders; it does not set its own ACLs.

### 4.4 Malware on the same machine

Veilcode does **not** protect against malware running as you or as an
administrator. It can read your input folder, your restore output and your
keystrokes, and while the vault is unlocked it can read the decrypted values in
Veilcode's memory. The only mitigation is that a vault file copied while locked
is encrypted, so a strong passphrase is the last line of defence (§11).

### 4.5 Supply chain (dependencies and the build pipeline)

- `Cargo.lock` is committed and builds use `--locked`.
- Only the dependencies listed in SPEC §9 are allowed. `cargo deny` bans HTTP,
  TLS, DNS, WebSocket and browser-launch crates (§10.1) and checks licences and
  advisories.
- The gitleaks rules are vendored from a pinned release-tag commit with a
  recorded sha256 (THIRD_PARTY_NOTICES).
- GitHub Actions are pinned to commit SHAs.
- Each release ships `SHA256SUMS`, one CycloneDX SBOM per binary and target,
  and build-provenance attestations for all 12 assets (D90, D93, D115), so you
  can check that a file was built by this repository's release workflow from a
  given tag (see VERIFY_OFFLINE.md). `SHA256SUMS` itself is not attested; it is
  checked against the attested files. The attestation proves which workflow
  file produced a file, not that the workflow's content was reviewed. For the
  SBOMs it proves only that the workflow produced them, not that the
  third-party SBOM tool reported the dependencies honestly or completely (D120).
- The release job takes each artifact by exact name and copies only the
  expected file names into the release (D120). Before hashing and attesting it
  extracts the `.deb` and `.tar.gz` with the runner's own `dpkg-deb` and `tar`
  and checks that their binaries are byte-identical to the build-job binaries.
  The `.msi` is not re-checked in the release job: its content check (an
  administrative extract compared by hash with the build outputs) runs in the
  read-only `package-windows` job, which uses only the runner image's WiX and
  `msiexec`.
- Release builds normalise embedded build paths (D92). The **Linux** build is
  byte-for-byte reproducible across machines: the v0.1.0-rc2 binary built by
  CI has the same sha256 as one built locally from the same commit, so anyone
  can rebuild it and compare. Reproducibility of the **Windows** build is
  **unverified** (the MSVC linker writes a timestamp).

Not protected: a compromised build pipeline or a malicious upstream crate
version that passes these checks (§11). Release binaries are **not code
signed** yet (code signing is planned for v1.x, §13).

**Repository settings** (maintainer-side controls; enabled and checked via the
GitHub API on 2026-10-14, D94; settings can change, so re-check before
relying on them):

- A tag ruleset for `v*` tags: only the maintainer can create, move or delete
  release tags.
- A protected `release` environment with a required reviewer: the job that
  signs and creates the release cannot start until the maintainer approves it.
- Read-only default workflow permissions (`GITHUB_TOKEN`), with write access
  granted per job only where needed.
- Actions limited to GitHub-owned actions plus the Rust toolchain action, all
  pinned to full commit SHAs.
- Immutable releases: published release assets and their tag cannot be
  replaced.

### 4.6 A network observer

Veilcode itself sends nothing, so there is nothing for an observer to see from
it (§8 below). Moving the masked folder to the AI assistant is done by you,
over whatever channel you choose; that traffic is outside Veilcode.

## 5. Secret retention (D60–D65)

The vault concentrates the secrets of every project that has not finished its
round trip. Veilcode keeps retention short:

- After a **clean** restore (0 missing, 0 unknown, 0 new secrets, nothing left
  uncopied), the session and every value no other session uses are forgotten,
  unless you pass `--keep` (D60, D71).
- Sessions expire after 30 days by default (`mask --ttl-days N`, 1–365).
  Expired sessions are purged on every successful vault open (D61).
- A vault with zero sessions is **deleted**, not saved as an empty file (D62).
- `veilcode vault status` shows counts and times only; `veilcode vault purge`
  removes everything (D63).
- A separate vault per project, `--vault <project>.vc`, is recommended, so
  finishing one project leaves nothing behind for it (D64).
- The default vault and profile live in the **local, non-roaming** data and
  config dirs (D81). On Windows that is under `%LOCALAPPDATA%`, not the
  roaming `%APPDATA%`, which roams with domain profiles and is often synced.

**Honest limits (D65):**

- Keep retention short: the vault concentrates secrets.
- Deleting rewrites or removes the encrypted file, but **SSD wear-levelling,
  backups and cloud sync** of the data dir may keep old encrypted copies.
  Exclude the Veilcode data dir (and any per-project vault files) from sync and
  backup.
- **Passphrase strength is the last line of defence** for any copy that
  survives. There is no recovery if you forget it.
- **Malware active while the vault is unlocked defeats all of this.**

If saving the vault after a clean restore fails (for example another Veilcode
process changed the vault), the restore returns that error. The output folder
is complete and the vault on disk still holds the session, so nothing is lost;
reopen the vault to see its true state (D67, D72).

## 6. What Veilcode does NOT protect against

- **Secrets no detector recognises.** Detection is best-effort (§5). Anything
  not detected stays in the masked output. Known gap: a PHP `define()` value
  that contains a quote character is not detected (§5, D3 detector). Review the
  scan report, add missing key names to your profile, and use
  `.veilcodeignore` to exclude files.
- **A tampered detection profile.** Anyone who can write your profile file can
  make Veilcode skip findings. Mitigations: it is never read from the input
  folder (D75); ignored findings are always listed and counted (D78); keep the
  profile in your own config dir.
- **Malware or another user with your privileges** on the same machine (§4.3,
  §4.4 above).
- **A compromised build pipeline** (§4.5 above).
- **OS components outside the app:** graphics drivers, the accessibility bus,
  clipboard managers keeping history of copied restored text, and backup or
  sync tools copying the restore output folder (which holds real secrets).
- **Memory forensics on a running process.** Key and plaintext buffers are
  zeroized on drop, but intermediate serialisation buffers are best-effort
  (§7); zeroization in general is best-effort. In the desktop app, text typed
  into a field is held by the GUI library (egui), including its undo history.
  Veilcode removes that state after a passphrase is submitted and on lock, but
  egui frees those strings without overwriting them first, so copies can
  remain in freed memory until it is reused (D106). Text Mode contents are
  handled the same way. The finding viewer (D137) holds the file text in
  zeroizing buffers that are dropped on close and on lock. Until the user
  clicks Reveal it holds no finding value at all, only offsets; Reveal reads
  the file again and holds that one value until hide, close or lock. The text
  egui lays out to draw it, including a revealed value, is a plain copy in
  egui's text-layout cache that Veilcode cannot wipe. The viewer never opens
  the file in another program.
- **Old copies of the vault** kept by SSD wear-levelling, backups or sync
  (§5 above).
- **A weak passphrase** on any vault copy an attacker obtains.
- **Where restore puts values** after the AI moved tokens around (§4.2 above).

## 7. Residual risks (accepted, documented)

- **FIFO swap during scan (D45).** After opening a file, Veilcode checks that it
  is still a regular file and, on Unix, that its device and inode match the
  walk entry; a mismatch is reported as `changed_during_scan`. A FIFO swapped in
  between the walk and the open can still make the open **block**. Avoiding
  this needs `O_NONBLOCK`, which needs a crate outside SPEC §9. Impact: a hang,
  not a leak.
- **Finding viewer folder swap (D137, like D45).** The viewer checks every
  folder below the scanned folder without following links, checks that the
  file's real path is inside the scanned folder, and refuses a file whose
  opened handle is not the one it checked (Unix: device and inode; Windows:
  the file is opened as a reparse point and refused if it is one; Unix also
  opens with `O_NOFOLLOW | O_NONBLOCK`). A parent folder swapped for a link
  between those checks and the open is not detected on Windows, where std
  reports no file identity. The viewer then still shows nothing unless the
  file it reached has exactly the sha256 recorded by the scan, so it can only
  ever show the content that was scanned. Nothing is written.
- **Look-alike prefixes (D138, Info 5).** A prefix such as `XVEILCODE_` is
  allowed. Its tokens contain a `VEILCODE_` shape, so a plain scan lists such
  a token as a finding and a restore with a vault that lacks that prefix
  reports the inner text as unknown. This affects reports only.
- **Custom-prefix token shapes (D138, L3).** For a custom prefix, Veilcode
  treats text as a token only if its 8 hex characters include a letter `a`–`f`
  (every generated token does). A detected value that is exactly such a token
  of the chosen prefix or of a prefix in the vault, such as
  `Infra_Mask_DB_1234abcd`, is not masked by `mask`, and restore reports it as
  unknown if the vault does not hold it; a plain `scan` still lists it.
  The default `VEILCODE_` shape is unchanged.
- **Output-dir race (D68).** Output folders are created fresh (`0700`) and
  unsafe Unix parents are refused, but writes are not done through directory
  file descriptors. Fully race-free writes would need a crate outside SPEC §9.
  Do not put output folders under directories other users can write to.
- **Profile FIFO race (D88).** The profile file is checked with `lstat`, opened,
  and on Unix its device and inode are compared; a FIFO swapped in during that
  window can block, the same accepted risk as D45.
- **X11 display race (D109).** On Linux the desktop app connects to the local
  X socket itself before starting and refuses to run if no local server
  answers. If the X server stops between that check and the GUI library's own
  connection, the X11 libraries fall back to TCP on `localhost:6000+N`. That
  window is short, and something must also be listening on that port for the
  connection to succeed.
- **Network locations in the desktop app (D130).** Typed or pasted network and
  device paths (`\\server\share`, `\\?\UNC\…`, `\\.\…`, `//host/…`) are refused as
  text before any file access. Two cases are not covered: a **mapped network
  drive letter** (for example `Z:`) looks like a local disk and cannot be told
  apart from its text, and the built-in file dialog can still browse to such
  drives. Opening a folder there makes Windows talk to that server. Keep
  projects, vaults and profiles on local disks.
- **Runtime C libraries are not audited for network use.** The checks above
  cover Rust crates. System libraries loaded at run time (graphics drivers,
  Mesa/libGL, libX11, libwayland) are not inspected; the strace audit only
  shows what they did in the scenarios it ran.
- **Best-effort zeroization** (§6 above).
- **Best-effort detection** (§6 above).
- **Tampered profile** (§6 above).

## 8. Offline design and how it is checked

The exact claim, and nothing stronger (SPEC §2.1, D107):

> **Offline design.** Veilcode has no network features. Its own crates make no
> network calls and do not use `std::process::Command`; CI enforces this with
> text checks and type-aware clippy bans. A fixed list of HTTP, TLS, DNS,
> WebSocket and browser-launch crates is banned from the dependency graph (SPEC
> §10.1). Some lower-level libraries can still open a network connection if the
> environment tells them to: the X11 client libraries connect over TCP when
> `DISPLAY` names another machine, or when a local display number gets no
> answer. So on Linux the desktop app links no D-Bus client crate, and it starts
> only if `DISPLAY` is unset or names a local display whose X server answers on
> its local socket (D104, D105, D109). On Linux, CI runs defined CLI and GUI
> scenarios under strace in an empty network namespace and fails if any
> non-local socket is opened. This tests those scenarios; it does not prove
> every possible code path. Windows has no runtime audit in CI.

**Enforced** (the build fails if violated): items 1 and 2 below, for code in
`crates/*/src`, plus the crate bans for the whole dependency graph.
**Tested, not proven**: item 3 covers only the scenarios it runs; a dependency
code path those scenarios never reach is not exercised.

How it is enforced (SPEC §10):

1. **Static bans.** `cargo deny` refuses the banned crates (§10.1).
   `scripts/check-offline.sh` fails on `std::net`, socket types,
   `std::process::Command`, and `http://`/`https://` URL strings in
   `crates/*/src` (§10.2).
2. **Clippy type bans.** `clippy.toml` lists the `std::net` socket types,
   `ToSocketAddrs` and `std::process::Command` as `disallowed-types` and
   `disallowed-methods`; CI runs clippy with `-D warnings`, so any use in
   `crates/*/src` fails the build. Unlike the text check, it is not fooled
   by aliases or unusual imports. It applies to our crates only, not to code
   inside dependencies.
3. **Runtime syscall audit.** `scripts/net-audit.sh` runs the CLI end to end
   (help, scan, mask, restore, vault status, vault purge) inside an **empty
   network namespace** (only a down loopback) under
   `strace -f -e trace=socket,connect,execve,io_uring_setup`. It fails on any
   socket or connect with a family other than `AF_UNIX`, on any `io_uring`
   setup, and on any process launch. It also launches the GUI under Xvfb for
   10 seconds with the same rules. Linux CI runs it on every change.

Windows has no strace equivalent in CI. VERIFY_OFFLINE.md describes a manual check (firewall rule plus monitoring); that manual check has not yet been carried out for a release.

## 9. How you can verify

See [VERIFY_OFFLINE.md](VERIFY_OFFLINE.md): running Veilcode with no network on
Linux and Windows, watching its system calls, and checking release checksums
and attestations.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
