# Veilcode — Architecture (implements SPEC v1.1)

This document says **where code goes and which invariants each type enforces**. SPEC says *what* the program does; this says *how it is laid out*. If they conflict, SPEC wins: stop and ask.

## 1. System context
```
                 ┌──────────────────────── user's machine (no network) ───────────────────────┐
                 │                                                                            │
  user ──► veilcode (CLI) ──┐                                                                 │
                            ├──► veilcode-core ──► reads   input folder        (read-only)    │
  user ──► veilcode-gui ────┘         │        ──► writes  new output folder   (empty, outside input)
          (egui, in-process)          │        ──► r/w     vault.vc            (Argon2id + XChaCha20-Poly1305)
                                      │        ──► reads   rules/gitleaks.toml (embedded at compile time)
                                      ▼
                         reports with previews only (no secret values)
                 └────────────────────────────────────────────────────────────────────────────┘
  AI assistant: the user moves the masked folder to the AI and back by hand. Veilcode never talks to it.
```

## 2. Trust boundaries (treat everything crossing them as hostile)
| Input | Why it is untrusted | Guard (module) |
|---|---|---|
| Input folder content | Arbitrary or AI-modified files: huge, binary, symlinks, odd encodings | `scan::walk` classification, `regex::bytes`, size caps |
| Findings / ScanReport file (CLI `--findings`) | User-editable JSON: path traversal, bogus offsets | `paths::RelPath::parse`, offset bounds checks, `scanned_files` hashes |
| Vault file | Tampered or corrupted header and ciphertext | `vault::format` bounds before the KDF; AEAD with header AAD; generic error |
| Output dir path | May overlap the input, be non-empty, or be a symlinked parent | `paths::OutputDir::prepare` (canonicalised checks) |
| Passphrase | User input | Length check (scalar values); held in `SecretString`, zeroized |

## 3. Workspace layout
```
Veilcode/
├── Cargo.toml                 # [workspace] members, [workspace.package] edition = "2024", license
│                              # [profile.dev.package.<argon2 crates>] opt-level = 3   (SPEC §8)
├── Cargo.lock                 # committed
├── rust-toolchain.toml        # pinned stable (VERIFY_LOG)
├── deny.toml                  # bans per SPEC §10.1, licenses, advisories
├── rules/
│   ├── gitleaks.toml          # vendored, pinned release-tag commit
│   └── README.md              # tag, commit, sha256, how to update
├── THIRD_PARTY_NOTICES        # gitleaks MIT text + commit
├── scripts/
│   ├── check-offline.sh       # static network/launch bans (SPEC §10.2)
│   ├── net-audit.sh           # strace runtime socket audit (SPEC §10.3)
│   └── check-test-ids.sh      # TEST_CASES ↔ test fn traceability
├── .github/workflows/
│   ├── ci.yml                 # standard checks ×3 OS + Linux net-audit job
│   └── release.yml            # P5/P7: build, SHA256SUMS, SBOM, attestations, packages
├── .claude/agents/            # developer, security-reviewer, infra-engineer, qa, fact-checker
├── docs/                      # SPEC, PLAN, TEST_CASES, DECISIONS, VERIFY_LOG, ARCHITECTURE, AGENTS,
│                              # ACTION_PLAN; later THREAT_MODEL, VERIFY_OFFLINE
└── crates/
    ├── veilcode-core/         # ALL logic; no printing, no prompts, no process launching
    ├── veilcode-cli/          # thin clap wrapper → binary `veilcode`
    └── veilcode-gui/          # thin eframe wrapper → binary `veilcode-gui`
```

## 4. `veilcode-core` modules
```
crates/veilcode-core/src/
├── lib.rs            #![forbid(unsafe_code)]; re-exports the public API (§6); nothing else public
├── error.rs          # CoreError (thiserror). Variants carry paths/ids/counts, NEVER values.
│                     #   VaultOpen  → "wrong passphrase or corrupted vault"   (single variant, SPEC §7)
│                     #   VaultChanged, Rescan, OutputNotEmpty, OutputInsideInput, BadRelPath, Locked, Io{path,kind}
├── secret.rs         # SecretBytes(Vec<u8>) + SecretString: Zeroize + ZeroizeOnDrop,
│                     #   Debug prints "SecretBytes(<redacted>, len=N)", no Display, no Serialize.
│                     #   fn preview(&self) -> String  → "abcd…(40)" (lossy UTF-8, first 4 chars)
├── hex.rs            # hand-written lower-hex encode/decode (no dependency)  — for value_hex
├── rng.rs            # trait RandomSource { fn fill(&mut self, buf: &mut [u8]) -> Result<…> }
│                     #   OsRandom (getrandom) in prod; SeqRandom (scripted bytes) in tests (T5, T7)
├── token.rs          # TOKEN_PATTERN (default prefix, SPEC §4), TokenPrefix (D138 rule), sanitize_name(),
│                     #   TokenGen<R: RandomSource>::generate(name, &prefix, &existing_vault_tokens, &input_haystacks) → Token
│                     #   Token = <PREFIX><NAME>_<HEX8>; the vault entry stores its prefix (D138)
├── paths.rs          # RelPath (validated: relative, '/'-separated, no ./../empty/root/drive/UNC)
│                     # OutputDir::prepare(out, input) → checks empty + not inside input (canonicalised)
│                     # safe_join(&OutputDir, &RelPath) → PathBuf  (the ONLY way to build a write path)
├── vault/
│   ├── mod.rs        # Vault { header, key: Key, data: VaultData, file_hash }  (no Debug of data)
│   │                 #   create(path, &SecretString) / open(path, &SecretString) / save()
│   │                 #   get_or_create_token_with(&SecretBytes, name, rule_id, &TokenPrefix, haystacks) → Token (dedupe per value+prefix); get_or_create_token = default prefix
│   │                 #   pub(crate) fn value(&Token) → Option<&SecretBytes>   (restore/text only)
│   │                 #   sessions(): list / add / delete (SPEC §6.4); open() purges expired sessions (D61)
│   ├── format.rs     # Header parse/serialise (magic, format, params, salt, nonce); bounds check
│   ├── crypto.rs     # derive_key(params, pass, salt) → Key (Zeroize); seal / open (AAD = header)
│   │                 #   #[cfg(test)] KDF call counter (V9), zeroize counter hook (G3)
│   └── model.rs      # VaultData { version, sessions, entries: BTreeMap<Token, Entry{value_hex,name,rule_id,prefix}> }
│                     #   prefix written only when not VEILCODE_; absent reads as VEILCODE_ (D138)
│                     #   Session { id, created, expires_at (validated, D61), source_label, scan_options (D57r), tokens }
├── scan/
│   ├── mod.rs        # pub fn scan(input, &ScanOptions, &Profile) → Result<ScanReport>
│   ├── walk.rs       # walkdir (no follow), .git hard-exclude, default excludes, .veilcodeignore (globset),
│   │                 #   classify: Text | Binary | Oversized | Symlink; sha256 per text file
│   ├── finding.rs    # Finding, ScanReport{findings, scanned_files, skipped, warnings}, finding id, preview
│   ├── resolve.rs    # drop token-containing spans; deterministic overlap resolution (SPEC §5)
│   └── detect/
│       ├── mod.rs    # Candidate{start,end,detector,rule_idx,key_name}; runs D1→D4 per file
│       ├── gitleaks.rs # include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/gitleaks.toml")); parse → Vec<Rule>;
│       │             #   keyword prefilter, secretGroup, entropy (ported from pinned detect.go)
│       ├── env.rs    # D2 (+ value trimming rules)
│       ├── php.rs    # D3
│       ├── url.rs    # D4
│       └── custom.rs # D5 custom-key assignment, only for profile extra_keys (D77)
├── profile.rs        # Profile { extra_keys, ignored_keys, ignored[] }: load (D79 safety) / save (atomic) / edit API (D80); normalise_key (D76); never read from input (D75)
├── mask.rs           # pub fn mask(&ScanReport, selection, input, out, &mut Vault, opts) → MaskReport (default selection excludes ignored, D78)
├── restore.rs        # pub fn restore(input, out, &mut Vault, session, keep) → RestoreReport; forget step last (D60)
├── vault/session.rs  # retention (child of vault, so it can reach private fields): forget(session), purge_expired(now), delete, status, purge; empty vault → file removed (D60–D63)
├── clock.rs          # trait Clock { now_unix() }; SystemClock; ManualClock is #[cfg(test)] and open_with_clock is pub(crate) (D70). Used by expiry (D61) and GUI auto-lock
├── text.rs           # mask_text / restore_text (GUI Text Mode)
├── view.rs           # view_finding(root, &ScanReport, id) → FindingView (D137): read-only, path-checked like the
│                     #   scanner, 2 MiB cap, sha256 must match the scan; text in Zeroizing buffers, redacting Debug
├── report.rs         # MaskReport, RestoreReport (Serialize; previews/ids/counts only)
└── test_support.rs   # #[cfg(test)] helpers from TEST_CASES.md (random_alnum, fake_github_pat, assert_no_secret…)
```

### Invariants enforced by types (not by discipline)
1. **Secret values can't leak through formatting.** Values live only in `SecretBytes`/`SecretString`, which have no `Display`, no `Serialize`, and a redacting `Debug`. `Finding`, reports and errors have no field that can hold one.
2. **Writes are contained.** Every file write goes through `safe_join(&OutputDir, &RelPath)`, and there is no other constructor of output paths. `RelPath` can only be built through validation.
3. **The input is read-only.** Core opens input files with `File::open` (read) only; write APIs appear only behind `safe_join` paths. The security reviewer checks this on every PR, and M1 proves it with before/after hashes.
4. **Vault values are read only by restore.** `Vault::value` is `pub(crate)` and used only by `restore.rs` and `text.rs`.
5. **Randomness and time are injected.** `RandomSource` (tokens, nonces, salts) and `Clock` (session expiry in core, GUI auto-lock) make tests deterministic without test backdoors in release builds.

## 5. Data flows
**Scan:** `walk` → for each Text file: read bytes → sha256 → `detect::run(D1..D4)` → candidates → `resolve` → `Finding`s (preview computed, value dropped immediately) → `ScanReport`.

**Mask:**
1. `OutputDir::prepare`
2. Validate every `RelPath`
3. Re-walk the input and compare against `scanned_files` (Rescan on mismatch)
4. For each selected finding: read the span → `SecretBytes` → `vault.get_or_create_token`
5. Write each text file with spans replaced right-to-left via `safe_join`
6. Copy binary and oversized files if opted in; never symlinks
7. `vault.save()` (with the concurrent-writer check)
8. Return `MaskReport`

**Restore:**
1. `OutputDir::prepare`
2. Walk the input
3. Scan → `new_secrets` (previews)
4. For each text file: every offset where a vault prefix starts (D29, D138) → vault lookup → replace; other token shapes → unknown
5. Compute missing (session tokens never seen)
6. Fsync the outputs; if clean and not keep, forget the session (D60), or remove the vault file if it was the last session (D62)
6. Copy the other non-symlink files
7. Return `RestoreReport`

## 6. Public core API (the only surface the CLI and GUI may use)
```rust
pub fn scan(input: &Path, opts: &ScanOptions, profile: &Profile) -> Result<ScanReport, CoreError>;
pub struct Profile; // load / save / add_extra_key / remove_extra_key / ignore_key / unignore_key / ignore_finding(&Finding, Scope) / unignore_finding / list
pub fn mask(report: &ScanReport, selection: &Selection, input: &Path, out: &Path,
            vault: &mut Vault, opts: &MaskOptions) -> Result<MaskReport, CoreError>;
pub fn restore(input: &Path, out: &Path, vault: &mut Vault, session: Option<&SessionId>, keep: bool)
            -> Result<RestoreReport, CoreError>;
pub fn mask_text(text: &str, vault: &mut Vault) -> Result<(String, SessionId), CoreError>;
pub fn restore_text(text: &str, vault: &mut Vault, session: Option<&SessionId>, keep: bool) -> Result<(String, RestoreReport), CoreError>;
pub struct Vault; // create / open (→ expired_removed) / save / sessions / delete_session / status / purge
pub fn default_vault_path() -> Option<PathBuf>; // directories::ProjectDirs
pub struct TokenPrefix; // parse(&str) (D138 rule) / as_str; MaskOptions.token_prefix (default VEILCODE_)
pub fn view_finding(root: &Path, report: &ScanReport, id: &str) -> Result<FindingView, CoreError>; // D137, offsets only
pub fn reveal_finding(root: &Path, report: &ScanReport, id: &str) -> Result<FindingView, CoreError>; // after Reveal
```
The exact signatures are settled in P1–P3 tests. Changing this surface after P3 needs a DECISIONS entry.

## 7. `veilcode-cli`
```
crates/veilcode-cli/
├── src/main.rs        # parse → dispatch → map CoreError to exit 2 + message (anyhow context, no values)
├── src/args.rs        # clap derive: scan | mask (--ttl-days) | restore (--keep) | session {list,delete} | vault {status,purge [--yes]} | profile {list,add-key,remove-key,ignore-key,unignore-key,ignore,unignore}; global flags incl. --profile
├── src/passphrase.rs  # rpassword prompt (twice on create) or one stdin line
├── src/output.rs      # human summary to stderr, JSON report to --report/--json files
└── tests/
    ├── common/mod.rs  # small copies of the random-secret + assert_no_secret helpers (core's are cfg(test))
    └── cli.rs         # c1_…c7_  via env!("CARGO_BIN_EXE_veilcode") + std::process::Command
```

## 8. `veilcode-gui` (eframe/egui, P6)
```
crates/veilcode-gui/src/
├── main.rs        # eframe::run_native; NativeOptions; no persistence
├── state.rs       # AppState { Locked | Unlocked{vault} }, Screen, actions → Result; NO egui types here (testable: G1–G3)
├── viewmodel.rs   # FindingRow{preview, path, line, rule, selected}, ReportView…, WorkflowRail, ResultCard (D131) (previews only: G2, G14)
├── idle.rs        # idle timer (10 min) → lock(), driven by veilcode_core::Clock (the trait moved to core)
├── worker.rs      # one background thread + std::sync::mpsc: Argon2 and file I/O never block the UI
├── theme.rs       # palette (light + dark), spacing, radii → egui Visuals/Style (D132); WCAG contrast test G13 (D133)
├── app.rs         # impl eframe::App: route to views, feed input events to idle timer, poll worker
└── views/         # viewer.rs: the read-only finding window (D137; never launches a program)
                   # unlock.rs, help.rs (always enabled, D127), scan.rs, review.rs (mandatory before mask, D80), mask.rs, restore.rs, sessions.rs, text_mode.rs
                   # chrome.rs: header + veil emblem, step rail, result cards, veil chips (D131, D132), painter only
                   # pickers via egui-file-dialog; no hyperlinks; Text Mode warning on restored text
crates/veilcode-gui/tests/features.rs   # g4_: cargo metadata feature audit
```

## 9. Cross-cutting policies
- **Errors:** core returns `CoreError`; the CLI adds context with anyhow; the GUI shows `to_string()`. No message ever interpolates file contents.
- **Logging:** none. No logging crate, and no `println!`/`eprintln!` in core. The CLI and GUI print reports only.
- **Panics:** none expected (no `unwrap` or `expect` in `src/`). Release profile `panic = "abort"` is optional and decided in P0 by infra.
- **Concurrency:** core is synchronous and single-threaded. The GUI owns a single worker thread. Vault cross-process safety comes from the file-hash check (SPEC §7).
- **Performance budget (v1):** a 10k-file repo scans in under 30 s on a laptop. Not a gate; a QA note.

## 10. Ownership
| Area | Owner agent | Reviewers |
|---|---|---|
| `crates/*/src`, tests | veilcode-developer | veilcode-qa, veilcode-security-reviewer |
| `.github/`, `scripts/`, `deny.toml`, toolchain, profiles, release | veilcode-infra-engineer | veilcode-security-reviewer |
| `docs/VERIFY_LOG.md` rows | veilcode-fact-checker (anyone may append) | maintainer |
| `docs/SPEC.md`, `docs/DECISIONS.md` status | **maintainer only** | — |
