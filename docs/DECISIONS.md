# Veilcode — Decisions log

This file records spec gaps and how they were resolved. The maintainer accepted D0–D23 on 2026-10-09, in some cases delegating the choice to the proposed default. **All are folded into SPEC v1.1**, so SPEC is the binding text and this file explains why.
New gaps found during implementation go at the bottom as `PROPOSED`. Claude Code must stop and ask while a decision blocking its phase is `PROPOSED`.

| ID | Decision | Where in SPEC | Status |
|---|---|---|---|
| D0 | Commits use `Muhammed Noufal <muhammednoufal7@gmail.com>` as a repo-local identity. No AI trailers or footers anywhere. | CLAUDE.md rule 9 | ACCEPTED |
| D1 | **Revised 2026-10-10:** develop in WSL Kali, because Windows Smart App Control blocks unsigned compiled binaries and this account is not an admin, so it cannot install the MSVC Build Tools. git runs from Windows. CI builds and tests natively on Linux, Windows and macOS. | CLAUDE.md "Dev environment" | ACCEPTED |
| D2 | Offline claim limited to the exact §2.1 wording, which is provable. | §2.1 | ACCEPTED |
| D3 | Test-ID renames: `SS1`→`SE1`, proptest `P1`→`PROP1`, enforced by `check-test-ids.sh`. | §8 | ACCEPTED |
| D4 | Token regex without `\b`; HEX8 must contain an a–f letter. | §4 | ACCEPTED |
| D5 | Vault stores `value_hex` (raw bytes), so non-UTF-8 secrets work. | §7 | ACCEPTED |
| D6 | Header KDF params are bounds-checked before Argon2 runs. | §7 | ACCEPTED |
| D7 | Concurrent writers detected by re-hashing the file before save. | §7 | ACCEPTED |
| D8 | Passphrase length counted in Unicode scalar values. | §7 | ACCEPTED |
| D9 | D2 value boundaries (`[^\r\n]`, quotes, ` #` comments). | §5 | ACCEPTED |
| D10 | Deterministic overlap algorithm. | §5 | ACCEPTED |
| D11 | gitleaks pinned to a release-tag commit; schema as found; path-only rules skipped. | §5 | ACCEPTED |
| D12 | 1-based line, byte column, `/` rel_path. | §5 | ACCEPTED |
| D13 | `scanned_files` hashes; mask verifies every text file. | §5, §6.1 | ACCEPTED |
| D14 | Strict `rel_path` validation before any I/O. | §6.1 | ACCEPTED |
| D15 | Symlinks never copied. | §6.1, §6.2 | ACCEPTED |
| D16 | proptest failure persistence off; `proptest-regressions/` gitignored. | §8 | ACCEPTED |
| D17 | `scan` needs no vault; `mask` creates the vault if missing (double prompt, or one stdin line); restore warnings exit 0. | PLAN P4 | ACCEPTED |
| D18 | Dev profile `opt-level = 3` for the argon2 crates; no test backdoor. | §8 | ACCEPTED |
| D19 | macOS is not released in v1 (CI build and test only), so the Intel-runner question is moot. | §3, §13 | ACCEPTED |
| D20 | All crates, including the GUI, are in one workspace. | §3 | ACCEPTED |
| D21 | Each prior-art project is verified (URL in VERIFY_LOG) before the README credits it; unverifiable ones are dropped. | §1 | ACCEPTED |
| D22 | **GUI stack: drop Tauri/Svelte; use eframe/egui + egui-file-dialog.** | §3, §9, §10.4 | ACCEPTED |
| D23 | **Runtime network-syscall audit in Linux CI.** | §10.3 | ACCEPTED |

---

## D22 — Why native egui instead of Tauri
The maintainer's goal is the most secure option, with no stack constraints.

| | Tauri 2 + Svelte (v1.0 plan) | **eframe/egui (chosen)** | iced | Slint |
|---|---|---|---|---|
| Web engine in process | Yes (WebView2 / WebKitGTK, a full browser that can fetch) | **No** | No | No |
| JavaScript / npm supply chain | Yes (Svelte, Vite, @tauri-apps/*) | **None** | None | None |
| Attack surface to lock down | CSP, IPC capabilities, `{@html}`, dist URLs | **Feature flags only** | Similar | Similar |
| One `cargo deny` graph covers everything | No (npm separate) | **Yes** | Yes | Yes |
| Licence | MIT/Apache | **MIT OR Apache-2.0** | MIT | GPL-3 / royalty-free / commercial (awkward for MIT+Apache) |
| Fit for form, list and textarea UI | Excellent | **Good** (immediate mode, simple) | Good, API changes often | Good |

**The cost:** a less "web-pretty" look, and a native-looking file picker is traded for an in-process one. **Required hardening:**
- eframe with `default-features = false`.
- The `links` feature is off (it would let the app open the system browser) and `persistence` is off.
- egui-file-dialog instead of `rfd`. `rfd` on Linux talks to the xdg portal over D-Bus, which is local but is still a service outside the process.
- The renderer (`wgpu` or `glow`) is chosen at P6 as the smallest dependency graph that renders on Windows 11 (including over RDP) and on Ubuntu LTS under X11 and Wayland. Record the choice in VERIFY_LOG.

## D23 — Proving "no network" instead of only claiming it
Static bans prove the HTTP/TLS/DNS crates are absent. The strace audit proves that no internet socket is opened, whatever a transitive dependency does. Display servers and the accessibility bus use `AF_UNIX`, which is local and allowed. Windows has no CI equivalent, so its manual procedure is documented in VERIFY_OFFLINE.md.

## Open (decide at the phase, with a VERIFY_LOG row)
- **P6 renderer:** `wgpu` vs `glow` (criteria above).
- **P6 clipboard:** whether clipboard support is a separate eframe/egui-winit feature at the locked version.
- **P7 packaging:** cargo-packager (one tool producing MSI/NSIS, `.deb` and AppImage) vs cargo-deb + cargo-wix. Prefer whichever needs **no network download at build time beyond pinned, checksummed tools**, and record it. Minimum deliverables: Windows `.msi` plus portable `.zip`; Linux `.deb` plus `.tar.gz` (AppImage optional).

## Decided during P1 (2026-10-10; the maintainer delegated these choices to the orchestrator)
| ID | Decision | Status |
|---|---|---|
| D24 | A session id is 16 lowercase hex characters (8 bytes from getrandom), and `created` is unix seconds from `SystemTime`. SPEC §6.4 did not define the id format. | ACCEPTED |
| D25 | **Preview of short secrets.** "First 4 chars" would reveal the whole of a ≤4-character secret. Rule: if the value has fewer than 8 chars, the preview is `…(N)` with no characters shown; otherwise it is the first 4 chars + `…(N)`. N is the length in chars of the lossy-UTF-8 value. This applies everywhere SPEC says "preview". | ACCEPTED |
| D26 | Enable chacha20poly1305's optional `zeroize` feature (the cipher state is wiped on drop). zeroize is already allowed by SPEC §9. | ACCEPTED |
| D27 | **Argon2 memory hygiene.** Enable argon2's `zeroize` feature. Derive the key with caller-allocated blocks (`hash_password_into_with_memory`, or whatever the 0.6.0 equivalent is, verified in VERIFY_LOG) and zeroize those blocks after use, so the 64 MiB of KDF state is not freed unwiped. | ACCEPTED |
| D28 | **Save lock and permissions.** `vault.vc.tmp` is created with `create_new(true)` (never follows or overwrites an existing file) and mode `0600` on Unix. If the tmp file already exists, save fails with "vault is being saved by another Veilcode process, or a previous save crashed — delete vault.vc.tmp if no Veilcode is running". The create_new acts as the writer lock and closes the D7 race between check and rename. After the rename, fsync the parent directory on Unix. | ACCEPTED |
| D29 | **Tokens preceded by `VEILCODE_`** (for P3 restore). The leftmost regex match can swallow a token that follows text ending in `VEILCODE_[A-Z0-9_]*`. Restore must therefore try a match at every `VEILCODE_` start offset, and a candidate counts only if it is a vault key. SPEC §4's "whatever bytes sit next to it" holds only for the right side; the left side is handled by this rule. Covered by R9. | ACCEPTED |
| D30 | Empty secret values are rejected by `get_or_create_token` (error, no value in the message). A vault path that is a directory or unreadable gives an `Io` error, not the generic one, because this is not a crypto oracle. | ACCEPTED |

## Decided during P2 (2026-10-10; delegated choices)
| ID | Decision | Status |
|---|---|---|
| D31 | gitleaks pinned to **v8.30.1** (commit `83d9cd68…`, file sha256 `e163e53b…`). Rule regexes compile with `RegexBuilder::size_limit(50 MiB)`, so all 221 compile (218 at the default limit). S15's ≥95% gate still applies. The compile time and memory of the full rule set are measured and reported in the P2 PR. | ACCEPTED |
| D32 | D1 regexes compile with `unicode(false)` (`regex::bytes`), so `\w`, `\d`, `\s` and `\b` are ASCII-only, matching Go RE2. The D2–D4 and token regexes stay as specified. | ACCEPTED |
| D33 | A rule-level allowlist regex that fails to compile is first retried with every `{` that does not start a valid `{n}`, `{n,}` or `{n,m}` quantifier escaped (Go accepts a literal `{`). If it still fails, that **single allowlist entry** is dropped with a warning (counted in ScanReport warnings); the rule itself stays active. A failure never means "allow everything" and never aborts the scan. `regexTarget` (`secret`/`match`/`line`), `stopwords`, `paths` and `condition = AND` follow upstream at the pinned commit. The global `[allowlist]` is ignored (SPEC §5). | ACCEPTED |
| D34 | Entropy is ported as upstream computes it: Shannon, log2, frequencies per char of the lossy-UTF-8 secret, divided by the secret's **byte** length; drop the finding if `entropy != 0 && H <= entropy`. Secret selection re-runs the rule regex on the match text, as upstream does: `secretGroup` > 0 takes that group, otherwise the first non-empty group, otherwise the whole match. | ACCEPTED |
| D35 | `.veilcodeignore` uses gitignore-like globs. `literal_separator(true)`. A pattern with no `/` matches at any depth (`**/` prepended). A pattern ending in `/` matches that directory and its contents. Patterns are relative to the input root. Blank lines and `#` comments are skipped. | ACCEPTED |
| D36 | Workspace `rust-version` is raised from 1.85 to **1.88**, because globset 0.4.20 needs it. The pinned toolchain is 1.99, so this only makes the stated minimum honest. | ACCEPTED |

## Proposed during P2 (2026-10-10; implemented as the stated default, needs a ruling)
| ID | Gap and proposed default | Status |
|---|---|---|
| D37 | **`rule_id` for D2–D4.** SPEC §5 gives every Finding a `rule_id` (used in the finding id and, via SPEC §4, as the token NAME when there is no key name) but names none for D2–D4. Proposed: `env-file` (D2), `php-define` (D3), `url-credentials` (D4), defined once in `scan/detect/mod.rs`. | ACCEPTED |
| D38 | **D2 quoted value without a closing quote** (`TOKEN="abc`). SPEC §5 only covers the matched-quote case. Proposed (safer, detects more): drop the opening quote and apply the unquoted rules (cut at ` #`, trim trailing spaces/tabs). The `${`/`$(` and empty checks apply to the extracted value, so `"${X}"` is also skipped. | ACCEPTED |
| D39 | **D2 CRLF.** In Rust `regex`, `(?m)$` matches only before `\n`, so the SPEC pattern never matches a CRLF line and S17 could not pass. D2 is compiled with `multi_line(true)` plus `crlf(true)` (Rust's `R` flag), so `$` also matches before `\r`; `[^\r\n]` keeps `\r` out of the span (D9). | ACCEPTED |
| D40 | **`.veilcodeignore` details not in D35.** A leading `/` is stripped (anchors to the root, as in gitignore). An invalid pattern is skipped with a ScanReport warning (excluding less is the safe failure). Non-file, non-dir, non-symlink entries (FIFOs, sockets) are never opened and are listed under `skipped.excluded`. | ACCEPTED |
| D41 | D2, D3 and D4 also compile with `unicode(false)` (`regex::bytes`), so values containing invalid UTF-8 bytes (Latin-1 `.env` files) are still detected. The token regex is ASCII-only either way. Secure default: detect more, never silently skip. | ACCEPTED |
| D42 | **Scanner complexity bound (sec M1).** Line and column come from one per-file sorted newline index plus binary search, never by re-counting from offset 0. A line is computed only for allowlists that need it. Overlap resolution uses a sorted interval structure, O(k log k). Covered by test S20. | ACCEPTED |
| D43 | **`.git` matching (sec M3).** A directory is the git dir if its name, after stripping trailing dots and spaces, equals `.git` **case-insensitively**, on every OS. Covered by S21. | ACCEPTED |
| D44 | **`.veilcodeignore` safety (sec M2).** It is read only if `symlink_metadata` shows a regular file of at most 1 MiB (read through `take`). Otherwise the scan fails with "unsafe .veilcodeignore (must be a regular file ≤ 1 MiB)", and nothing is read. Covered by S22. | ACCEPTED |
| D45 | **Read race (sec L1).** After opening a file, check `metadata().is_file()`. On Unix, also check that dev+ino match the walk entry. On a mismatch, list the file as skipped (`changed_during_scan`). The residual risk (a FIFO swapped in between walk and open, which can block) is accepted and documented, because `O_NONBLOCK` would need libc, which SPEC §9 does not allow. | ACCEPTED |
| D46 | **Non-UTF-8 file names (sec L2).** A file or directory whose name is not valid UTF-8 is not scanned and not copied; it is listed under `skipped.non_utf8_name`. This prevents `rel_path` collisions. Covered by S23 (Unix). | ACCEPTED |
| D47 | **Line-target allowlists are ignored (sec L3).** gitleaks allowlist entries with `regexTarget = "line"` are dropped (counted in warnings), because an AI controls line contents and could add a suppression comment. Entries targeting `secret` or `match` are kept. Covered by S24. | ACCEPTED |
| D48 | **Do not drop or partly mask real secrets (sec L4).** (a) A candidate is dropped only if its span is **exactly** a token match. A span that contains a token plus other bytes is kept and masked whole; restore returns the original bytes, old token included (S8b). (b) Overlapping candidates are **merged into their union span**, credited to the winner under the D10 ordering, so no secret byte is left unmasked. **This replaces D10's "skip overlapping".** S7 has been updated. | ACCEPTED |
| D49 | D3 pattern allows whitespace between `define` and `(`: `define\s*\(…`. Covered by S2b. | ACCEPTED |
| D50 | D4 password group is greedy up to the **last** `@` before the first `/` or whitespace, so a raw `@` in a password is fully masked: `[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s/]+)@`. Covered by S3c. | ACCEPTED |
