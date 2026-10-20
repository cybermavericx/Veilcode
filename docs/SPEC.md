# Veilcode — Specification (v1.4, 2026-10-19)

Repo: https://github.com/cybermavericx/Veilcode · License: MIT OR Apache-2.0
Changes to this file need the maintainer's approval. v1.1 folds in DECISIONS.md D0–D23. In particular, D22 replaced Tauri with a native Rust GUI. v1.2 (maintainer-approved) adds the **secret lifecycle / retention** design, D60–D66, plus D57r and D58. Implementation-level decisions D24–D59 are binding through DECISIONS.md. v1.3 (maintainer-requested) adds the detection profile, custom keys, false-positive handling and review-before-mask (§5.1; D74–D80), and brings the §5 text in line with D41 and D48–D50. v1.4 (maintainer-approved, from the rc3 Windows feedback) adds the custom placeholder prefix (§4, §6.1, §6.2, §7; D138), the prefix remembered per project (§4, §6.1, §7; D141, maintainer-requested 2026-10-20) and the read-only finding viewer with Reveal (§10.4; D137).

## 1. Problem & positioning
Developers paste server code into AI assistants, including `.env` files and config secrets. Veilcode masks those secrets with unique placeholders, stores the real values in a local encrypted vault, and restores them after the AI work is done, even if the AI moved, renamed, or edited the code.

**Prior art (credit in README only after verifying each one per D21; never claim "first"):** opsmask, CodeMask OSS, Carnaval, ragkit-redactor.
**Veilcode's niche:**
- A fully open desktop app and CLI for **Windows and Linux**.
- **No web engine.** The whole program is one Rust dependency graph, with no JavaScript, npm or webview.
- A whole-folder round trip for any language.
- Offline behaviour is checked in CI: static bans, plus a runtime syscall audit of defined scenarios (not a proof of every code path).
- Releases with build provenance. The Linux release binary has been rebuilt byte-for-byte identically; the Windows build is not yet verified as reproducible.

## 2. Non-negotiable principles
1. **Offline design.** Veilcode has no network features. Its own crates make no network calls and do not use `std::process::Command`; CI enforces this with text checks and type-aware clippy bans. A fixed list of HTTP, TLS, DNS, WebSocket and browser-launch crates is banned from the dependency graph (SPEC §10.1). Some lower-level libraries can still open a network connection if the environment tells them to: the X11 client libraries connect over TCP when `DISPLAY` names another machine, or when a local display number gets no answer. So on Linux the desktop app links no D-Bus client crate, and it starts only if `DISPLAY` is unset or names a local display whose X server answers on its local socket (D104, D105, D109). On Linux, CI runs defined CLI and GUI scenarios under strace in an empty network namespace and fails if any non-local socket is opened. This tests those scenarios; it does not prove every possible code path. Windows has no runtime audit in CI. This is the exact claim the README may make, and nothing stronger (D107).
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
- **Supported platforms for v1:** Windows 10/11 x86_64 and Linux x86_64 (CLI: static musl binary, D91; GUI: glibc, X11 and Wayland). macOS is built and tested in CI but not released (§13).

## 4. Placeholder tokens
- Format: `<PREFIX><NAME>_<HEX8>`. The default `PREFIX` is `VEILCODE_`, so the default token is `VEILCODE_<NAME>_<HEX8>` (D138).
  - `PREFIX` is chosen per mask (GUI "Placeholder prefix" field on the Mask screen, CLI `mask --token-prefix`). It is 2–16 ASCII characters: the first is a letter (`A`–`Z`, `a`–`z`), the rest are letters, digits or `_`, and the last is `_`. Any other prefix is refused before the mask starts (D138).
  - `NAME` is the key name, or the rule id if there is no key name. Uppercase it, map every character outside `[A-Z0-9]` to `_`, collapse runs of `_`, trim leading/trailing `_`, truncate to 24 characters. If the result is empty, use `SECRET`.
  - `HEX8` is 8 lowercase hex characters from 4 bytes of OS randomness (`getrandom`). It **must contain at least one letter `a`–`f`**; regenerate if not (D4).
- Each vault entry stores the prefix its token was made with (§7). Restore never has to split a token to find its prefix: it uses the set of prefixes stored in the vault, plus `VEILCODE_` (D138).
- Matching regex for a prefix `P`: `P[A-Z0-9_]{1,24}_[0-9a-f]{8}`, with `P` matched literally (no `\b`). For the default prefix this is `VEILCODE_[A-Z0-9_]{1,24}_[0-9a-f]{8}`. The **whole match** is the vault lookup key.
  - NAME never contains lowercase letters and HEX8 always does, so the bytes after a token cannot change its match. The bytes before it can: text ending in `P[A-Z0-9_]*` directly before a token can make the leftmost match swallow it, which restore handles by trying every offset where a known prefix starts (D29, D138).
- The same secret value **with the same prefix** always maps to the same token (dedupe within the vault). The NAME comes from the first occurrence. The same value masked with a different prefix gets its own token (D138).
- If a generated token already exists in the vault, or already appears in any input file, regenerate it.
- Text Mode (§6.3) always uses the default prefix.
- **Remembered per project (D141):** a successful folder mask remembers its prefix for the input folder in the vault (§7); `VEILCODE_` removes the memory. The next mask of the same folder starts from it: the GUI pre-fills the field (hint "remembered for this project", "Reset to default"), and CLI `mask` without `--token-prefix` uses it, else `VEILCODE_`, and prints which prefix it used and why. An explicit `--token-prefix` updates the memory.

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
  - Pattern: `define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)` (D49)
  - Same key-name filter as D2, including profile `extra_keys` (§5.1). This covers `wp-config.php`. Values containing a quote character are not detected; the README lists this limitation.
- **D4 URL credentials.** Applies to all text files.
  - Pattern: `[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s/]+)@`. The password group is greedy up to the last `@` (D50).
  - The secret is group 1 (the password only).
- **D5 custom-key assignment** (D77). Applies to all text files, and only for profile `extra_keys`.
  - Matches: an optionally quoted key with word boundaries, then `:` or `=`, then a quoted value or an unquoted value.
  - Byte mode. `rule_id = "custom-key"`.

D2–D5 compile in byte mode with `unicode(false)` (D41).

**Post-processing:**
- A keyword pre-filter (case-insensitive) runs before each D1 regex.
- Drop a candidate only if its span is **exactly** a §4 token match of a known prefix (D48a). A plain scan has no vault, so it knows only `VEILCODE_`: tokens of a custom prefix are reported as findings there. Restore uses every prefix in the vault, and mask also never re-masks a token of the chosen prefix or of a vault prefix (D138).
- **Overlap resolution (deterministic, D10 + D48b):**
  1. Sort candidates by (span length desc, detector D1<D2<D3<D4<D5, rule index in gitleaks.toml asc, start asc).
  2. Merge overlapping candidates into their union span, credited to the first candidate in that order.
  3. Output sorted by (rel_path, start).
- **Profile marking (D78):** findings matched by `ignored_keys` or an `[[ignored]]` entry are kept, with `ignored` set.

**Finding** (serialisable):
```
id (hex sha256 of rel_path|start|end|rule_id, first 16 chars), rel_path, line, column,
start, end (byte offsets), rule_id, detector (D1..D5), key_name (optional),
preview ("abcd…(40)"), file_sha256, ignored (optional: profile key | profile entry)
```
- `line` and `column` are 1-based, and `column` counts bytes.
- `rel_path` uses `/` separators on every OS and is built from path components.
- A Finding **never** contains the secret value.

**ScanReport:** findings; `scanned_files: [{rel_path, sha256}]` covering every text file; the `ScanOptions` used; lists of skipped files (binary, oversized, symlink, excluded, non-UTF-8 name, changed during scan); warnings.

### 5.1 Detection profile (D74–D80)
A user-editable TOML file that tunes detection. It **never contains secret values**:
```toml
version = 1
extra_keys   = ["customapi-pass", "dbname"]   # also detect these key names (D2, D3, D5)
ignored_keys = ["DB_NAME"]                    # never auto-select these key names
[[ignored]]                                   # one specific false positive
rel_path = "config/.env"
key_name = "APP_KEY_ID"                       # or: rule_id = "generic-api-key"
```
- **Location:** the `ProjectDirs` **local** config dir `profile.toml` by default (D81), or `--profile FILE` (a per-project profile is recommended, like per-project vaults). The profile is **never read from the input folder automatically** (D75).
- **Matching:** key names are normalised (uppercased; `-`, `.` and space become `_`) and matched exactly (D76).
- **Effect:**
  - Ignored findings are reported and excluded from the default selection. Selecting one explicitly still masks it.
  - Reports count them (`ignored_by_profile`, `ignored_new_secrets`). They are never silently dropped (D78).
- **Safety:**
  - The file must be a regular file of at most 1 MiB, in strict TOML.
  - Key names and paths are validated.
  - Saves are atomic.
  - Entries are location- or key-based, never value-based: there are no hashes of secrets (D79, D78).
- **Review before mask (D80):** the GUI always shows a Review dialog before masking. Each finding can be unticked, or remembered or unremembered as a false positive, and missing key names can be added there. The CLI offers the same through `veilcode profile …` and the `--findings` file.

## 6. Operations
### 6.1 Mask (`folder → new folder`)
Inputs: input dir, output dir, ScanReport plus a selection of finding ids (default: all), vault (unlocked).
1. Refuse if the output dir already exists or is inside the input dir; Veilcode creates it itself, 0700 on Unix (D68). Compare canonicalised paths, and refuse an unsafe group/other-writable non-sticky parent on Unix. Compare canonicalised paths; for a not-yet-existing output dir, canonicalise its nearest existing ancestor.
2. **Validate every `rel_path`** that comes from the ScanReport or findings file. It must be relative and `/`-separated, with no `..`, `.` or empty components, and no root, drive or UNC prefix. Reject before any I/O.
3. Verify that **every** text file to be written matches `scanned_files` (sha256), and that no text file exists that is absent from `scanned_files`. On mismatch, fail with "file changed since scan — rescan".
4. Get or create a token for each selected secret, with the chosen prefix (§4). Store `token → {value_hex, name, rule_id, prefix}` in the vault and record a session.
5. Write the output tree:
   - Text files: replace spans right-to-left. All other bytes stay identical, including CRLF and encoding.
   - Binary and oversized files are **not copied** unless `include_unscanned=true`.
   - **Symlinks are never copied.**
   - Excluded paths are never copied.
6. Remember the chosen prefix for the input folder (§4, D141), save the vault, then return a MaskReport: session id, counts (including `already_tokens`, selected findings that already were tokens, D138), files not copied. The report contains no secret values.

### 6.2 Restore (`AI-modified masked folder → new folder`)
Inputs: input dir, output dir, vault, optional session id (default: newest session), `keep` (default false).
1. Same output-dir rules as mask. The walk uses the chosen session's recorded `scan_options` (D57r). `.git` is excluded and symlinks are not copied.
2. Scan the input with detectors D1–D4. Any finding is a **new secret introduced by the AI**; report it.
3. In text files, replace every token match found **anywhere in the vault** with its value. A match is tried at every offset where a known prefix starts (the prefixes stored in the vault, plus `VEILCODE_`; D29, D138). Strings shaped like a token of a known prefix but not in the vault are left untouched and reported as **unknown**. A finding whose span is exactly such a token is not reported as a new secret.
4. Tokens of the chosen session that never appear in the input are reported as **missing** (the AI may have deleted them).
5. Copy every other non-symlink file as-is. Fsync every written file, the created directories and the output root (on Unix).
6. **Forget by default (D60).** If the restore is clean (0 missing, 0 unknown, 0 new secrets) and `keep` is false, delete the chosen session and every entry no other session uses, then save under the D28 lock (or remove the vault file, §7 D62). This step runs only after step 5 has succeeded; any earlier error leaves the vault untouched.
7. Return a RestoreReport with `session_forgotten`, or `kept_reason` when the session is kept. The report contains no secret values.

Every write path must be checked: the joined output path must stay under the output dir.

### 6.3 Text Mode (GUI only)
`mask_text(text) -> (masked_text, session)` and `restore_text(text, session?, keep) -> (restored, report)` use the same detectors, tokens and vault.
- D2 and D3 always apply to pasted text (D58).
- `restore_text` defaults to the newest session labelled `"text"`, computes `missing` against it, and follows the same forget-by-default rule (D60).
- The restored-text panel shows the warning "contains real secrets — clipboard managers may keep history".

### 6.4 Sessions and retention
- **Session fields:** id, `created` (unix seconds), `expires_at` (D61), source label, `scan_options`, tokens.
- **Expiry (D61):** `expires_at = created + ttl_days × 86400`. `ttl_days` defaults to 30, range 1–365 (mask option; CLI `--ttl-days N`). Expired sessions are purged on every successful vault open (§7).
- **`list`** shows id, created, expires_at, source label and token count.
- **`delete <id>`** removes the session and any vault entries no other session uses. Deleting an unknown id is an error.
- **`status`** (D63) shows session count, oldest session age and next expiry. It shows no values.
- **`purge`** (D63) removes all sessions and entries, then the vault file. The CLI asks for confirmation unless `--yes` is given.
- **Empty vault removal (D62):** any operation that leaves zero sessions (forget, expiry, delete, purge) deletes `vault.vc` instead of saving an empty file.
- **Per-project vaults (D64):** `--vault <project>.vc` is the recommended pattern. The GUI offers "separate vault for this project".

## 7. Vault
- Location: `directories::ProjectDirs::from("com", "Cybermavericx", "Veilcode")` **local (non-roaming) data dir** (D81; on Windows `%LOCALAPPDATA%`), file `vault.vc`. Overridable via `--vault` (per-project vaults recommended, D64).
- Binary layout:
  ```
  magic "VEILCODE" (8) | format u8 = 1 | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE |
  salt (16) | xnonce (24) | ciphertext+tag
  ```
- **KDF:** Argon2id, m_cost = 65536 KiB, t_cost = 3, p_cost = 1, 32-byte output.
  - Parameters are read from the header when opening, and must be within `m ∈ [8, 262144]`, `t ∈ [1, 10]`, `p ∈ [1, 4]` **before** the KDF runs. Otherwise open fails with the generic error.
  - The salt is kept for the vault's lifetime.
- **AEAD:** XChaCha20-Poly1305, with a fresh random nonce on every save. AAD = all header bytes before the ciphertext.
- **Plaintext:** JSON `{ "version":1, "sessions":[...], "entries":{ token: {value_hex,name,rule_id[,prefix]} } }`. `value_hex` is the lowercase hex of the raw secret bytes. `prefix` is written only when it is not `VEILCODE_`, and an absent `prefix` reads as `VEILCODE_`, so a vault holding only default-prefix entries has the same JSON shape as before v1.4. On open, a stored prefix that breaks the §4 rule, or an entry key that is not a token of its own prefix, gives the generic error (D138).
  - `project_prefixes` (D141): an optional top-level object `{ key: prefix }`, omitted when empty. `key` is the lowercase hex sha256 of `veilcode project prefix v1\0` followed by the input folder's canonical path bytes (Unix: OS bytes; Windows: UTF-16LE), so no path text is stored; an entry is written only for a custom prefix (`VEILCODE_` removes the key). A key that is not 64 lowercase hex characters or a prefix that breaks the §4 rule gives the generic error. It is cleared with the file when D62 removes the vault.
- **Session record** in the plaintext: `{ id, created, expires_at, source_label, scan_options, tokens }`. `expires_at` is validated on deserialize (`created < expires_at <= created + 365 days`), otherwise the generic error.
- **Open (D61):** after a successful decrypt, sessions with `expires_at <= now` (from the core `Clock`) are purged, along with entries no remaining session uses. If any were purged, the vault is saved immediately, or removed (D62). The open result exposes `expired_removed` (a count only).
- **Save:** write `vault.vc.tmp`, fsync, rename over `vault.vc` (D28 lock, `0600` on Unix).
- **Removal (D62):** when zero sessions remain after a removal, `vault.vc` is deleted under the D28 lock: D7 hash check, remove, fsync the parent directory on Unix. It is never saved as an empty encrypted file.
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
| eframe (**`default-features = false`**; enable only: `glow` (D96), `default_fonts`, `x11`, `wayland`, plus `accesskit` on non-Linux targets only (D104: no D-Bus on Linux); clipboard is built in (D98)), egui-file-dialog, anyhow | gui | native GUI, in-process file picker |
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
   - Fail on any `socket()` or `connect()` with a family other than `AF_UNIX` (stricter than an AF_INET/AF_INET6/AF_PACKET/AF_NETLINK deny list), on `io_uring_setup`, and on any `execve` after the first. On Linux, `AF_UNIX` here means the display server (X11 or Wayland); the GUI links no D-Bus client crate on Linux (D104).
   - If a forbidden family appears, stop and report; do not allow-list it quietly.
4. **GUI hardening:** no webview, no HTML, no hyperlinks, no URL opening, in-process file picker only, persistence disabled. Secret values appear only in the Text Mode widgets and, after the user clicks Reveal, in the finding viewer for that one finding (D137): until Reveal the viewer holds offsets and lengths only, and the value is wiped on hide, close, opening another finding and lock. All other views hold previews.
5. Windows has no strace equivalent in CI. Manual verification is documented in VERIFY_OFFLINE.md (firewall outbound block plus Resource Monitor / Wireshark).

## 11. Threat model (summary; full text in THREAT_MODEL.md)
- **Protects against:** secrets reaching AI providers, the app leaking data over the network, accidental commits of masked output containing `.git` history.
- **Does not protect against:**
  - malware or another user on the same machine (mitigation: an encrypted vault with a strong passphrase)
  - a tampered detection profile: anyone who can write the profile file can make Veilcode skip findings (mitigation: the profile is never read from the input folder (D75); ignored findings are always listed and counted (D78); keep the profile in your own config dir)
  - a compromised build pipeline (mitigation: locked dependencies, CI bans, provenance attestations)
  - secrets that no detector recognises (mitigation: user review and `.veilcodeignore`; the README must say detection is best-effort)
  - OS components outside the app: graphics drivers, the accessibility bus, clipboard managers keeping history of copied restored text, and backup or sync tools copying the restore output folder (which holds real secrets)
  - memory forensics on a running process (zeroization is best-effort)
- **Retention (D60–D65).** The vault concentrates secrets from every project that has not finished its round trip. To limit this:
  - Sessions are forgotten after a clean restore, expire after 30 days by default, and the file is deleted when empty.
  - Per-project vaults are recommended.

  Honest limits, which README and THREAT_MODEL.md must state:
  - Deleting rewrites or removes the encrypted file, but SSD wear-levelling, backups and cloud sync of the data dir may keep old encrypted copies. Exclude the Veilcode data dir from sync and backup.
  - Passphrase strength is the last line of defence for any copy that survives.
  - Malware active while the vault is unlocked defeats all of this.

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
