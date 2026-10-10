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

## Decided during P3 (2026-10-10; delegated choices)
| ID | Decision | Status |
|---|---|---|
| D51 | `ScanReport` records the `ScanOptions` it was produced with. Mask (and its re-walk check, D13) uses those same options, so the walk results always agree. A selection is a set of finding ids; the default is all. An id not present in the report is an error. | ACCEPTED |
| D52 | Mask and restore create the output dir (and missing parents) if it does not exist. If it exists, it must be an empty directory (SPEC §6.1 step 1). | ACCEPTED |
| D53 | A session's `source_label` is the input dir's final path component (lossy UTF-8). Text Mode uses `"text"`. Restore's default session is the newest by `created`, ties broken by id. Mask records a session even when it has 0 tokens. | ACCEPTED |
| D54 | Every output file is created with `create_new(true)` (never overwrites, never follows a pre-existing path or symlink). Directories are created only under the output dir via `safe_join`. | ACCEPTED |
| D55 | **Permissions.** On Unix, mask and restore copy each file's permission bits (`mode & 0o777`) from their input. Restored files in which at least one token was replaced by a real value get group and other bits cleared (`& 0o700`). Windows: no permission handling. Covered by R10. | ACCEPTED |
| D56 | Non-excluded empty directories are recreated in the output. Timestamps are not preserved. | ACCEPTED |

## Proposed during P3 (2026-10-10; implemented as the stated default, needs a ruling)
| ID | Gap and proposed default | Status |
|---|---|---|
| D57 | **Restore walk options.** SPEC §6.2 says restore uses "the same walk rules as mask", but restore has no ScanReport, so it has no `no_default_excludes`. Implemented: restore walks with `ScanOptions::default()` (`.git`, default excludes and the masked folder's `.veilcodeignore` apply). Consequence: a folder masked with `no_default_excludes` loses `node_modules`/`vendor`/… on restore. Alternative: a restore option (CLI `--no-default-excludes`), which would change the ARCHITECTURE §6 signature. | SUPERSEDED by D57r |
| D58 | **Text Mode detectors.** D2 and D3 are gated by file name (`.env`, `*.php`); pasted text has none. Implemented: Text Mode runs D1–D4 with D2 and D3 always applied (X1 needs the env line masked). `mask_text` saves the vault (otherwise the tokens are lost on exit). `restore_text` reports `new_secrets` and `unknown`; `missing` is always empty. | ACCEPTED |
| D59 | **Unwritable walked names.** A walked name that `RelPath::parse` rejects (on Unix a name containing `\`, or a first component like `C:x`) makes mask/restore fail with `BadRelPath` before any file is written, instead of skipping the file. Proposed: keep failing (no silent drop). | ACCEPTED |
| D57r | **Restore walk options (revised).** Each session records the `ScanOptions` its mask used (`scan_options`). Restore walks with the chosen session's options, so a folder masked with `no_default_excludes` round-trips completely. | ACCEPTED |
| D58 note | Text Mode restore takes an optional session id (default: the newest session labelled `"text"`) plus `keep`. `missing` is computed against that session, so the D60 forget rule applies to Text Mode too. | ACCEPTED |

## Secret lifecycle / retention (2026-10-10, maintainer-requested; folded into SPEC v1.2)
Threat: once projects finish their round trip and the plaintext copies are deleted, the vault becomes the only store of every past project's secrets. A later compromise (for example a keylogged passphrase) would leak all of them. **Goal: a completed project leaves no secrets in Veilcode.**

| ID | Decision | Status |
|---|---|---|
| D60 | **Forget by default after a clean restore.**<br>- **Clean** means `missing = 0`, `unknown = 0` and `new_secrets = 0`.<br>- Forgetting happens only **after** the output tree is fully written and fsynced: each file `sync_all`, plus created directories and the output root on Unix.<br>- Then the restore deletes the chosen session and every entry no other session uses, and saves under the D28 lock (or removes the file, D62).<br>- The RestoreReport says `session_forgotten: true`.<br>- `keep = true` (CLI `--keep`; GUI checkbox, default off) retains the session.<br>- A non-clean restore keeps the session and reports why (`kept_reason`: keep requested, or the missing/unknown/new_secrets counts).<br>- Any error before the forget step leaves the vault untouched.<br>- Applies to `restore` and `restore_text`. | ACCEPTED |
| D61 | **Session expiry.**<br>- Every session has `expires_at` (unix seconds) = `created + ttl_days × 86400`. `ttl_days` defaults to 30, may be 1–365 (`MaskOptions.ttl_days`, CLI `--ttl-days N`), and anything else is an error.<br>- On every successful vault open, sessions with `expires_at <= now` are purged, along with the entries no remaining session uses. If any were purged, the vault is saved immediately (or removed, D62).<br>- The open result exposes `expired_removed: usize` (a count only), and the CLI and GUI print "N expired sessions removed".<br>- Time comes from a `Clock` trait in core (`SystemClock` in production, a manual clock in tests).<br>- `expires_at` is validated on deserialize: `created < expires_at <= created + 365 days`, otherwise the generic open error. | ACCEPTED |
| D62 | **Empty vault removal.**<br>- When an operation (forget, expiry, delete, purge) leaves zero sessions, `vault.vc` is **deleted** instead of being saved as an empty encrypted file.<br>- The deletion happens under the D28 lock: the D7 hash check runs first, then remove, then fsync the parent directory on Unix.<br>- The in-memory vault then counts as "no file", so a later save creates a new file.<br>- Entries no session references are always purged with their last session. | ACCEPTED |
| D63 | **Status and purge.**<br>- Core: `Vault::status()` returns `VaultStatus { sessions, oldest_created, next_expiry }` (counts and times, no values). `Vault::purge()` removes all sessions and entries, then the file (D62).<br>- CLI (P4): `veilcode vault status`; `veilcode vault purge` (asks for confirmation, or `--yes`).<br>- GUI (P6): a Sessions screen with age and expiry columns, and "Purge all" with a confirmation dialog. | ACCEPTED |
| D64 | **Per-project vaults.** `--vault <project>.vc` is the documented, recommended pattern (README, CLI help). GUI (P6): a "separate vault for this project" option on the mask screen. | ACCEPTED |
| D65 | **Honest documentation** in README and THREAT_MODEL.md:<br>- The vault concentrates secrets, so keep retention short.<br>- Deleting rewrites or removes the encrypted file, but SSD wear-levelling, backups and cloud sync of the data dir may keep old encrypted copies; exclude the Veilcode data dir from sync and backup.<br>- Passphrase strength is the last line of defence.<br>- Malware active while the vault is unlocked defeats all of this. | ACCEPTED |
| D66 | Test IDs for this feature use the prefix `LF` (LF1–LF8), so cargo filters don't clash with other IDs. The vault plaintext stays `version: 1`: no release has shipped, so there is nothing to migrate. | ACCEPTED |
| D67 | **Forget-save failure.** If the save or removal that forgets a session fails after the outputs were written (VaultChanged, SaveLocked, a Windows remove error), restore returns that error. The output tree is complete and the on-disk vault still holds the session (fail-safe: nothing is lost). The in-memory vault has already dropped it, so the caller must reopen the vault to see the true state. The CLI and GUI say so. | ACCEPTED |
| D68 | **Output dir must be new (sec M1; replaces D52's "may exist if empty").** Mask and restore refuse an output dir that already exists, and create it themselves (`0700` on Unix). Missing parents are created too. On Unix, they also refuse when the nearest existing parent is group- or other-writable without the sticky bit, so another user cannot rename the new dir and swap in a link. Fully race-free dir-fd writes would need a crate outside SPEC §9; that residual risk is documented in THREAT_MODEL. Covered by M11. | ACCEPTED |
| D69 | **Failed run removes its partial output (sec L2).** If mask or restore fails after creating the output dir, it deletes the tree it created (it is ours, per D68) and returns `PartialOutput { cleaned: bool, cause }`. If cleanup fails, the message says "output folder may contain real secrets — delete it: <dir>". The vault is untouched (D60, LF7). Covered by R13. | ACCEPTED |
| D70 | **No production clock override (sec L3).** `open_with_clock` is `pub(crate)` and `ManualClock` is `#[cfg(test)]`. Only the `Clock` trait and `SystemClock` are public; GUI tests define their own clock against the trait. | ACCEPTED |
| D71 | **Stricter "clean" (sec L4, I1).** Clean also requires `not_copied == 0` and `tokens_in_unscanned == 0`. The second counts vault tokens still present in copied binary or oversized files, found with the token regex over their bytes. The report also gives `foreign_session_tokens` (tokens from sessions other than the chosen one), as a count only, which does not affect cleanliness. Covered by LF2b. | ACCEPTED |
| D72 | **Retention changes are transactional (QA F2; refines D67).** forget, purge-expired, delete_session and purge build the new state on a copy and swap it into the in-memory vault only after the save or removal succeeds. A failed persist leaves memory equal to disk. Covered by LF9. | ACCEPTED |
| D73 | **Restore needs a session (QA F4).** `restore`/`restore_text` with `session = None` on a vault with no (matching) session fail with "vault has no sessions to restore" before creating the output. Covered by R12. | ACCEPTED |

## Review, custom keys and false positives (2026-10-10, maintainer-requested; folded into SPEC v1.3)
Request: before masking, the user sees what will be masked (key names such as DB_NAME or DB_PASSWORD), can untick false positives, can mark them as false positives permanently (and undo that later), and can add missed key names such as `customapi-pass`.

| ID | Decision | Status |
|---|---|---|
| D74 | **Detection profile.** A plain TOML file holding **no secret values**: `version = 1`, `extra_keys = [...]` (key names to detect), `ignored_keys = [...]` (key names never auto-selected), and `[[ignored]]` entries `{ rel_path, key_name? , rule_id? }` (exactly one of key_name or rule_id). Default location: `ProjectDirs` config dir `profile.toml`; override with `--profile FILE`. The GUI offers a per-project profile next to the per-project vault (D64). A missing default profile means an empty profile. | ACCEPTED |
| D75 | **The profile is never read from the input folder automatically.** A malicious or AI-modified repo could otherwise ship a profile that ignores everything. Only an explicitly passed `--profile`, or the user's config dir, is used. | ACCEPTED |
| D76 | **Key-name matching.** Keys are normalised by uppercasing and mapping `-`, `.` and space to `_`, so `customapi-pass` = `CUSTOMAPI_PASS`. `extra_keys` and `ignored_keys` match the **whole** normalised key name exactly. The built-in D2/D3 list stays a substring filter. `extra_keys` add to the D2/D3 key filter and drive D5. | ACCEPTED |
| D77 | **D5, custom-key assignment detector**, applied to every text file and **only for `extra_keys`** (to keep false positives low). It matches an optionally quoted key, not preceded or followed by `[A-Za-z0-9_]`, then optional spaces, `:` or `=`, optional spaces, then the value. A quoted value is the bytes between matching quotes. An unquoted value runs up to whitespace, `,`, `;`, `#`, `}`, `)` or end of line. Empty values and values starting with `${` or `$(` are skipped. Byte mode with `unicode(false)` (D41). `rule_id = "custom-key"`. The overlap order becomes D1<D2<D3<D4<D5 (D10/D48). | ACCEPTED |
| D78 | **Ignored findings are never silent.**<br>- A finding matched by `ignored_keys` or an `[[ignored]]` entry stays in `ScanReport.findings` with `ignored: Some(IgnoreReason)` and is **excluded from the default selection**.<br>- Explicitly selecting its id still masks it (user override).<br>- MaskReport counts `ignored_by_profile`, and the CLI prints "N findings ignored by profile (not masked)".<br>- Restore applies the same profile when it reports new secrets and gives `ignored_new_secrets` as a separate count.<br>- Entries are location- or key-based, **never value-based**: there are no hashes of secret values, because a hash would be an offline guessing oracle for short secrets. | ACCEPTED |
| D79 | **Profile safety.** Read only if `symlink_metadata` shows a regular file of at most 1 MiB (as D44). Strict TOML (`deny_unknown_fields`). Key names must match `[A-Za-z0-9_.\- ]{1,64}`, and `rel_path` must pass `RelPath::parse`. Any violation is a clear error, never silently ignored. Saves are atomic (tmp + rename). Edits are idempotent: adding an existing key or removing an absent one is a no-op that reports so. | ACCEPTED |
| D80 | **Review before mask.**<br>- Core: `scan(input, opts, &Profile)` and a `Profile` API (`load`, `save`, `add_extra_key`, `remove_extra_key`, `ignore_key`, `unignore_key`, `ignore_finding(&Finding, Scope::{ThisFile, Everywhere})`, `unignore_finding`, `list`).<br>- CLI (P4): `veilcode profile list \| add-key K \| remove-key K \| ignore-key K \| unignore-key K \| ignore --path P (--key K \| --rule R) \| unignore --path P (--key K \| --rule R)`, and `--profile` on scan, mask and restore. Deselecting one finding for a single run stays the existing `--findings` file.<br>- GUI (P6): a mandatory **Review** dialog before every mask. Findings are grouped by key name or rule, with file, line and preview. Ticked means masked, and everything non-ignored starts ticked. Unticking offers "remember as false positive" for this file or everywhere; "everywhere" asks for confirmation. A collapsed "Ignored (false positives)" section has a "Unignore" action. An "Add key name" field adds the key and re-scans. The confirm button reads "Mask N secrets". | ACCEPTED |
