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
real values. Veilcode never talks to the AI assistant or to anything else on
the network.

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
(`VEILCODE_<NAME>_<HEX8>`, §4), so it reveals *that* a value such as a database
password exists, but not the value. The `HEX8` part is random and carries no
information about the value.

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
- Each release ships `SHA256SUMS`, one CycloneDX SBOM per target and
  build-provenance attestations (D90, D93), so you can check that a binary was
  built by this repository's release workflow from a given tag (see
  VERIFY_OFFLINE.md). The attestation proves which workflow file built it, not
  that the workflow's content was reviewed.
- Release builds normalise embedded build paths (D92). Byte-for-byte
  reproducibility is verified **only for the Linux build, on one host** (two
  build directories gave identical sha256). Reproducibility across machines,
  and for the Windows build, is **unverified**.

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
  (§7); zeroization in general is best-effort.
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
- **Output-dir race (D68).** Output folders are created fresh (`0700`) and
  unsafe Unix parents are refused, but writes are not done through directory
  file descriptors. Fully race-free writes would need a crate outside SPEC §9.
  Do not put output folders under directories other users can write to.
- **Profile FIFO race (D88).** The profile file is checked with `lstat`, opened,
  and on Unix its device and inode are compared; a FIFO swapped in during that
  window can block, the same accepted risk as D45.
- **Best-effort zeroization** (§6 above).
- **Best-effort detection** (§6 above).
- **Tampered profile** (§6 above).

## 8. Offline guarantee

The exact claim, and nothing stronger (SPEC §2.1, D2):

> **Offline by construction.** Veilcode's own code contains no network calls and
> does not launch other programs. HTTP, TLS, DNS, WebSocket and browser-launch
> crates are banned from the dependency graph. On Linux, CI proves at runtime
> that neither the CLI nor the GUI opens an internet socket (§10).

How it is enforced (SPEC §10):

1. **Static bans.** `cargo deny` refuses the banned crates (§10.1).
   `scripts/check-offline.sh` fails on `std::net`, socket types,
   `std::process::Command`, and `http://`/`https://` URL strings in
   `crates/*/src` (§10.2).
2. **Clippy type bans.** `clippy.toml` lists the `std::net` socket types,
   `ToSocketAddrs` and `std::process::Command` as `disallowed-types` and
   `disallowed-methods`; CI runs clippy with `-D warnings`, so any use in
   `crates/*/src` fails the build. Unlike the text check, this cannot be
   bypassed with aliases or unusual imports.
3. **Runtime syscall audit.** `scripts/net-audit.sh` runs the CLI end to end
   (help, scan, mask, restore, vault status, vault purge) inside an **empty
   network namespace** (only a down loopback) under
   `strace -f -e trace=socket,connect,execve,io_uring_setup`. It fails on any
   socket or connect with a family other than `AF_UNIX`, on any `io_uring`
   setup, and on any process launch. Linux CI runs it on every change. The
   GUI is added to this audit when it ships.

Windows has no strace equivalent in CI; it is verified by hand (§10.5).

## 9. How you can verify

See [VERIFY_OFFLINE.md](VERIFY_OFFLINE.md): running Veilcode with no network on
Linux and Windows, watching its system calls, and checking release checksums
and attestations.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
