# Veilcode — Specification (v1.1, frozen 2026-10-09)

Repo: https://github.com/cybermavericx/Veilcode · License: MIT OR Apache-2.0
Changes to this file need the maintainer's approval. v1.1 folds in DECISIONS.md D0–D23. In particular, D22 replaced Tauri with a native Rust GUI.

## 1. Problem & positioning
Developers paste server code into AI assistants, including `.env` files and config secrets. Veilcode masks those secrets with unique placeholders, stores the real values in a local encrypted vault, and restores them after the AI work is done, even if the AI moved, renamed, or edited the code.

**Prior art (credit in README only after verifying each one per D21; never claim "first"):** opsmask, CodeMask OSS, Carnaval, ragkit-redactor.
**Veilcode's niche:**
- A fully open desktop app and CLI for **Windows and Linux**.
- **No web engine.** The whole program is one Rust dependency graph, with no JavaScript, npm or webview.
- A whole-folder round trip for any language.
- Offline behaviour is enforced in CI, both statically and with a runtime syscall audit.
- Reproducible releases with provenance.

## 2. Non-negotiable principles
1. **Offline by construction.** Veilcode's own code contains no network calls and does not launch other programs. HTTP, TLS, DNS, WebSocket and browser-launch crates are banned from the dependency graph. On Linux, CI proves at runtime that neither the CLI nor the GUI opens an internet socket (§10). This is the exact claim the README may make, and nothing stronger.
2. The user's input folder is never modified.
3. Secret values never leave the encrypted vault except into the restore output and Text Mode (§6.3).
4. Secure defaults: when in doubt, exclude and report.

## 3. Architecture
```
crates/veilcode-core   library: scan, mask, restore, vault, tokens (all logic, no I/O prompts)
crates/veilcode-cli    binary `veilcode` (clap)
crates/veilcode-gui    binary `veilcode-gui` (eframe/egui, native, no webview)
rules/gitleaks.toml    vendored detection rules (pinned upstream release-tag commit, MIT notice)
scripts/check-offline.sh, scripts/check-test-ids.sh, scripts/net-audit.sh
```
- All three crates are members of one Cargo workspace (D20).
- The core is the only place with logic. The CLI and GUI are thin wrappers.
- **Supported platforms for v1:** Windows 10/11 x86_64 and Linux x86_64 (glibc; X11 and Wayland). macOS is built and tested in CI but not released (§13).

## 4. Placeholder tokens
- Format: `VEILCODE_<NAME>_<HEX8>`
  - `NAME` is the key name, or the rule id if there is no key name. Uppercase it, map every character outside `[A-Z0-9]` to `_`, collapse runs of `_`, trim leading/trailing `_`, truncate to 24 characters. If the result is empty, use `SECRET`.
  - `HEX8` is 8 lowercase hex characters from 4 bytes of OS randomness (`getrandom`). It **must contain at least one letter `a`–`f`**; regenerate if not (D4).
- Matching regex: `VEILCODE_[A-Z0-9_]{1,24}_[0-9a-f]{8}` (no `\b`). The **whole match** is the vault lookup key.
  - NAME never contains lowercase letters and HEX8 always does, so a match always equals the original token, whatever bytes sit next to it.
- The same secret value always maps to the same token (dedupe within the vault). The NAME comes from the first occurrence.
- If a generated token already exists in the vault, or already appears in any input file, regenerate it.

## 5. Detection (scanner)
**Input walk** (`walkdir`, never follow symlinks):
- `.git/` is always excluded. This cannot be overridden, because git history contains secrets.
- Default excluded directories, which the user can disable with `--no-default-excludes`: `node_modules`, `vendor`, `target`, `.venv`, `venv`, `__pycache__`.
- Glob patterns in an optional `.veilcodeignore` at the input root are also excluded (`globset`, one pattern per line, `#` starts a comment).
- Each file is classified as:
  - **binary**: a NUL byte appears in the first 8 KiB
  - **oversized**: larger than 5 MiB (exactly 5 MiB is scanned)
  - **symlink**
  - **text**: everything else

  Only **text** files are scanned.
- Scanning uses `regex::bytes`, so files that are not valid UTF-8 are handled and offsets are byte offsets.

**Detectors** (run in this order):
- **D1 gitleaks rules.** Uses `rules/gitleaks.toml` from the commit of the latest gitleaks **release tag** at the start of P2 (tag, commit and file sha256 recorded in VERIFY_LOG and THIRD_PARTY_NOTICES).
  - Supported fields: `id`, `regex`, `secretGroup`, `entropy`, `keywords`, `path`, and the rule-level allowlist (`regexes`, `stopwords`) in **whichever schema the pinned commit uses**.
  - Rules with no `regex` (path-only) are skipped and counted as unsupported. The global allowlist is ignored in v1. Other fields are ignored and listed in a doc comment.
  - Secret-group selection and entropy calculation follow upstream `detect/detect.go` at the same commit.
  - A rule that fails to compile in Rust is skipped with a warning, and the count is reported. Any raised `RegexBuilder` size limit is recorded in a code comment.
- **D2 env files.** Applies to files named `.env`, `.env.*`, or `*.env`.
  - Compiled with `(?m)`. Lines matching `^[ \t]*(export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*([^\r\n]*)$`.
  - The key name must contain (case-insensitive) one of: `PASS`, `PWD`, `SECRET`, `TOKEN`, `KEY`, `SALT`, `AUTH`, `CREDENTIAL`, `DSN`, `PRIVATE`.
  - Value: if it starts with `"` or `'`, the secret is the bytes up to the matching closing quote. Otherwise cut at the first ` #` (space + hash), then trim trailing spaces and tabs.
  - Skip empty values and values starting with `${` or `$(`. `\r` is never part of a span.
- **D3 PHP define.** Applies to `*.php`.
  - Pattern: `define\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)`
  - Same key-name filter as D2. This covers `wp-config.php`. Values containing a quote character are not detected; the README lists this limitation.
- **D4 URL credentials.** Applies to all text files.
  - Pattern: `[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s@/]+)@`
  - The secret is group 1 (the password only).

**Post-processing:**
- A keyword pre-filter (case-insensitive) runs before each D1 regex.
- Drop any finding whose secret span is, or contains, a match of the §4 token regex.
- **Overlap resolution (deterministic):**
  1. Sort candidates by (span length desc, detector D1<D2<D3<D4, rule index in gitleaks.toml asc, start asc).
  2. Accept candidates greedily, skipping any that overlap an accepted one.
  3. Output sorted by (rel_path, start).

**Finding** (serialisable):
```
id (hex sha256 of rel_path|start|end|rule_id, first 16 chars), rel_path, line, column,
start, end (byte offsets), rule_id, detector (D1..D4), key_name (optional),
preview ("abcd…(40)"), file_sha256
```
- `line` and `column` are 1-based, and `column` counts bytes.
- `rel_path` uses `/` separators on every OS and is built from path components.
- A Finding **never** contains the secret value.

**ScanReport:** findings; `scanned_files: [{rel_path, sha256}]` covering every text file; lists of skipped files (binary, oversized, symlink, excluded); rule-load warnings.

## 6. Operations
### 6.1 Mask (`folder → new folder`)
Inputs: input dir, output dir, ScanReport plus a selection of finding ids (default: all), vault (unlocked).
1. Refuse if the output dir exists and is non-empty, or if it is inside the input dir. Compare canonicalised paths; for a not-yet-existing output dir, canonicalise its nearest existing ancestor.
2. **Validate every `rel_path`** that comes from the ScanReport or findings file. It must be relative and `/`-separated, with no `..`, `.` or empty components, and no root, drive or UNC prefix. Reject before any I/O.
3. Verify that **every** text file to be written matches `scanned_files` (sha256), and that no text file exists that is absent from `scanned_files`. On mismatch, fail with "file changed since scan — rescan".
4. Get or create a token for each selected secret. Store `token → {value_hex, name, rule_id}` in the vault and record a session.
5. Write the output tree:
   - Text files: replace spans right-to-left. All other bytes stay identical, including CRLF and encoding.
   - Binary and oversized files are **not copied** unless `include_unscanned=true`.
   - **Symlinks are never copied.**
   - Excluded paths are never copied.
6. Save the vault, then return a MaskReport: session id, counts, files not copied. The report contains no secret values.

### 6.2 Restore (`AI-modified masked folder → new folder`)
Inputs: input dir, output dir, vault, optional session id (default: newest session).
1. Same output-dir rules and walk rules as mask. `.git` is excluded and symlinks are not copied.
2. Scan the input with detectors D1–D4. Any finding is a **new secret introduced by the AI**; report it.
3. In text files, replace every token match found **anywhere in the vault** with its value. Token-shaped strings not in the vault are left untouched and reported as **unknown**.
4. Tokens of the chosen session that never appear in the input are reported as **missing** (the AI may have deleted them).
5. Copy every other non-symlink file as-is, then return a RestoreReport. The report contains no secret values.

Every write path must be checked: the joined output path must stay under the output dir.

### 6.3 Text Mode (GUI only)
`mask_text(text) -> (masked_text, session)` and `restore_text(text) -> (restored, report)` use the same detectors, tokens and vault.
- The restored-text panel shows the warning "contains real secrets — clipboard managers may keep history".

### 6.4 Sessions
`list` shows id, created (unix seconds), source label, token count. `delete <id>` removes the session and any vault entries no other session uses. Deleting an unknown id is an error.

## 7. Vault
- Location: `directories::ProjectDirs::from("com", "Cybermavericx", "Veilcode")` data dir, file `vault.vc`. Overridable via `--vault` / config (used by tests).
- Binary layout:
  ```
  magic "VEILCODE" (8) | format u8 = 1 | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE |
  salt (16) | xnonce (24) | ciphertext+tag
  ```
- **KDF:** Argon2id, m_cost = 65536 KiB, t_cost = 3, p_cost = 1, 32-byte output.
  - Parameters are read from the header when opening, and must be within `m ∈ [8, 262144]`, `t ∈ [1, 10]`, `p ∈ [1, 4]` **before** the KDF runs. Otherwise open fails with the generic error.
  - The salt is kept for the vault's lifetime.
- **AEAD:** XChaCha20-Poly1305, with a fresh random nonce on every save. AAD = all header bytes before the ciphertext.
- **Plaintext:** JSON `{ "version":1, "sessions":[...], "entries":{ token: {value_hex,name,rule_id} } }`. `value_hex` is the lowercase hex of the raw secret bytes.
- **Save:** write `vault.vc.tmp`, fsync, rename over `vault.vc`.
- **Concurrent writers:** on open, remember the sha256 of the file bytes. Before saving, re-hash the file on disk; if it differs, refuse with "vault changed by another Veilcode process — reopen".
- **Passphrase:** minimum 12 Unicode scalar values (`chars().count()`) when creating a vault.
  - A wrong passphrase, a corrupted file, a bad magic value, an unknown format or out-of-range params all produce the same error: "wrong passphrase or corrupted vault".
  - Key and plaintext buffers are zeroized on drop. Intermediate serde buffers are best-effort; the threat model says so.
  - There is no recovery. This is acceptable because the originals are never modified.
- **GUI:** the vault auto-locks after 10 minutes without input (injectable clock).

## 8. Testing rules
- Every test ID in TEST_CASES.md maps to a test function whose name starts with that ID in lowercase, followed by `_`. `scripts/check-test-ids.sh` enforces this.
- **No secret-shaped literals in the repo.** Tests build secrets at runtime, written into `tempfile` dirs.
- Property test (proptest) for random file trees and secrets: `restore(mask(x)) == x` byte for byte, with `failure_persistence` disabled. `proptest-regressions/` is gitignored.
- CLI tests run the built binary via `env!("CARGO_BIN_EXE_veilcode")` and `std::process::Command`, which is allowed in tests only.
- The dev profile builds the argon2 crates with `opt-level = 3`, so tests using production KDF params stay fast. The binaries have no test-params backdoor.

## 9. Allowed dependencies (add with `cargo add`; never hand-write versions)
| Crate | Where | Purpose |
|---|---|---|
| regex, serde, serde_json, toml, walkdir, globset, sha2, thiserror, directories | core | logic |
| chacha20poly1305, argon2, getrandom, zeroize | core | crypto (check enabled features in docs for the locked version) |
| clap (derive), rpassword, anyhow | cli | CLI |
| eframe (**`default-features = false`**; enable only: a renderer, `default_fonts`, `x11`, `wayland`, `accesskit`; plus clipboard support if it is a separate feature at the locked version), egui-file-dialog, anyhow | gui | native GUI, in-process file picker |
| proptest, tempfile | dev | tests |

**Forbidden eframe/egui features:** `links` (opens the system browser) and `persistence` (writes UI state to disk). Also forbidden: any image or font loader that fetches URLs.
**Release tooling (CI only, not linked into binaries):** cargo-deny, cargo-cyclonedx, and the packager chosen at P7 (cargo-packager, or cargo-deb + cargo-wix). Install with `--locked` and a version from VERIFY_LOG.
**Toolchain:** pinned stable in `rust-toolchain.toml` (≥ 1.85, and ≥ the MSRV of the locked eframe); `edition = "2024"` in `[workspace.package]`. No Node/npm anywhere.

## 10. Offline enforcement
1. **Banned crates** (`deny.toml` `[bans] deny`): `reqwest`, `ureq`, `hyper`, `h2`, `curl`, `isahc`, `attohttpc`, `surf`, `tungstenite`, `quinn`, `rustls`, `native-tls`, `openssl`, `hickory-resolver`, `trust-dns-resolver`, `webbrowser`, `open`, `opener`.
   - If a dependency pulls one of these transitively, **stop and report to the maintainer**. Do not add `wrappers`.
   - The PR description must explain any appearance of the watch-list crates `socket2`, `mio`, `tokio` or `async-net` in `cargo tree`.
2. **Static check:** `scripts/check-offline.sh` fails on any of the following under `crates/*/src`. Code that needs these (CLI tests) lives in `crates/*/tests/`, which the check does not scan:
   - `std::net`, `TcpStream`, `UdpSocket`, `TcpListener`, `ToSocketAddrs`
   - `std::process::Command` or `process::Command`
   - `hyperlink`, `open_url` or `OpenUrl` in `crates/veilcode-gui`
   - an `http://` or `https://` URL string in Rust source, except on `//` comment lines
3. **Runtime syscall audit** (`scripts/net-audit.sh`, Linux CI):
   - Run the CLI end-to-end (scan → mask → restore) under `strace -f -e trace=socket,connect`.
   - Run the GUI under `xvfb-run` for 10 s, also under strace.
   - Fail on any `socket(AF_INET|AF_INET6|AF_PACKET|AF_NETLINK, …)`. `AF_UNIX` (display server, accessibility bus) is allowed.
   - If a forbidden family appears, stop and report; do not allow-list it quietly.
4. **GUI hardening:** no webview, no HTML, no hyperlinks, no URL opening, in-process file picker only, persistence disabled. Secret values appear only in the Text Mode widgets; all other views hold previews.
5. Windows has no strace equivalent in CI. Manual verification is documented in VERIFY_OFFLINE.md (firewall outbound block plus Resource Monitor / Wireshark).

## 11. Threat model (summary; full text in THREAT_MODEL.md)
- **Protects against:** secrets reaching AI providers, the app leaking data over the network, accidental commits of masked output containing `.git` history.
- **Does not protect against:**
  - malware or another user on the same machine (mitigation: an encrypted vault with a strong passphrase)
  - a compromised build pipeline (mitigation: locked dependencies, CI bans, provenance attestations)
  - secrets that no detector recognises (mitigation: user review and `.veilcodeignore`; the README must say detection is best-effort)
  - OS components outside the app: graphics drivers, the accessibility bus, clipboard managers keeping history of copied restored text, and backup or sync tools copying the restore output folder (which holds real secrets)
  - memory forensics on a running process (zeroization is best-effort)

## 12. Verified facts
| Date | Fact | Source |
|---|---|---|
| 2026-10-09 | chacha20poly1305 latest 0.11.0 (aead 0.6, MSRV 1.85); NCC Group audit (2020, older version) found no significant issues | docs.rs/chacha20poly1305, nccgroup.com |
| 2026-10-09 | argon2 latest 0.6.0 (MSRV 1.85); `hash_password_into` for key derivation | docs.rs/argon2 |
| 2026-10-09 | cargo-deny `[bans] deny = [{ crate = "...", reason = "..." }]` syntax | embarkstudios.github.io/cargo-deny |
| 2026-10-09 | gitleaks rules at `config/gitleaks.toml`, MIT license | github.com/gitleaks/gitleaks |
| 2026-10-09 | Repo public, README only, default branch `main` | api.github.com/repos/cybermavericx/Veilcode |
| 2026-10-09 | eframe 0.36.2, MIT OR Apache-2.0; default features include `links`, `wgpu`, `accesskit`, `x11`, `wayland`, `default_fonts`; `glow` and `persistence` are optional | crates.io/api/v1/crates/eframe/0.36.2 |
| 2026-10-09 | egui-file-dialog 0.15.0, MIT | crates.io/api/v1/crates/egui-file-dialog |
| 2026-10-09 | cargo-packager 0.11.8 (Apache-2.0 OR MIT), cargo-deb 3.8.0 (MIT), cargo-wix 0.3.9 (MIT/Apache-2.0) | crates.io API |

## 13. Out of scope for v1
Zip input, format-preserving dummies, vault export/import, auto-update, editor plugins, Flatpak, macOS releases (CI build and test only), code signing (planned v1.x), fuzzing (backlog), `--strict` restore exit code (backlog), any web or webview UI.
