# Veilcode — Execution Plan (for SPEC v1.1)

**Current phase: P7** (set to PN as the first commit of phase N; read by scripts/check-test-ids.sh)

Rules:
- One phase per branch and PR.
- Write the tests first. The exact cases are in TEST_CASES.md.
- A phase is done only when every acceptance command passes.
- Standard checks are listed in CLAUDE.md. Spec references look like "SPEC §n".

All decisions D0–D23 are ACCEPTED and folded into SPEC. Phase-time choices are listed under "Open" in DECISIONS.md.

---

## P0 — Bootstrap
Tasks:
- [x] Cargo workspace with `crates/veilcode-core` (lib) and `crates/veilcode-cli` (bin `veilcode`); `crates/veilcode-gui` is added in P6. Each crate has `#![forbid(unsafe_code)]`. `edition = "2024"` goes in `[workspace.package]`.
- [x] `rust-toolchain.toml` pinned to the current stable version (check with `rustup check`; must be ≥ 1.85; log it in VERIFY_LOG).
- [x] Dev-profile override `opt-level = 3` for the argon2 crates (SPEC §8). Take the crate names from Cargo.lock once P1 adds argon2. In P0, add only a commented placeholder.
- [x] `LICENSE-MIT`, `LICENSE-APACHE`, `README.md` (problem, status "pre-alpha", the offline claim worded exactly as SPEC §2.1, prior-art credits only after verification per D21), `SECURITY.md` (private reporting via GitHub Security Advisories).
- [x] `deny.toml` with the bans from SPEC §10.1, plus a license allow-list (built from `cargo deny check licenses` output, not memory) and advisories checks.
- [x] `scripts/check-offline.sh` (SPEC §10.2).
- [x] `scripts/net-audit.sh` (SPEC §10.3). In P0 it covers the CLI only, running `veilcode --help` under strace. P4 extends it to the full end-to-end run, and P6 adds the GUI.
- [x] `.github/workflows/ci.yml`:
  - Runs the standard checks on ubuntu, windows and macos, with `shell: bash` for `.sh` steps.
  - A Linux-only job runs `net-audit.sh`.
  - Actions are pinned by commit SHA, looked up on each action's releases page and logged in VERIFY_LOG.
- [x] `.gitignore`: `target/`, `*.vc`, `*.vc.tmp`, `proptest-regressions/`.
- [x] Run tests O1–O4 (TEST_CASES.md) and paste their output in the PR.

Acceptance: `cargo build --workspace` ✔ · standard checks ✔ · CI green on all 3 OS.

## P1 — Vault and tokens (core)
Implement `vault.rs` (SPEC §7), `token.rs` (SPEC §4), and the `test_support.rs` helpers (TEST_CASES.md).
Tests: V1–V11, T1–T7.
Note: tests use low Argon2 params via a `pub(crate)` constructor; production params are fixed.
Acceptance: standard checks ✔.

## P2 — Scanner (core)
Implement the walk and detectors D1–D4 (SPEC §5).
- Vendor `rules/gitleaks.toml` from the latest gitleaks release-tag commit.
- Record the tag, commit and file sha256 in VERIFY_LOG and `THIRD_PARTY_NOTICES`, with the MIT text.

Tests: S1–S19.
Acceptance: standard checks ✔ · `cargo test -p veilcode-core s1_` etc. all pass.

## P3 — Mask and restore (core)
Implement SPEC §6.1, §6.2 (including step 6, forget by default), §6.4 (sessions and retention: expiry, delete, status, purge, empty-vault removal), the text functions from §6.3, and §7 open-time expiry. The core `Clock` trait lives in `clock.rs`.
Tests: M1–M11 (including M4b and M6b), R1–R13, X1, SE1, SE2, PROP1, and the lifecycle tests LF1–LF7, LF2b, LF9 (SPEC v1.2 §6.2 step 6, §6.4, §7; D57r, D60–D63, D66).
Acceptance: standard checks ✔.

## P4 — CLI
Commands:
- `veilcode scan <DIR> [--json FILE]` (no vault needed)
- `veilcode mask <DIR> --out DIR [--findings FILE] [--include-unscanned] [--no-default-excludes]` (creates the vault if missing)
- `veilcode restore <DIR> --out DIR [--session ID]`
- `veilcode session list`
- `veilcode session delete <ID>`
- `veilcode vault status` (D63: counts and times only)
- `veilcode vault purge [--yes]` (D63: asks for confirmation unless --yes)
- `mask` also takes `--ttl-days N` (1–365, default 30); `restore` also takes `--keep` (D60, D61). Every vault-opening command prints "N expired sessions removed" when N > 0. The `--help` text recommends per-project `--vault <project>.vc` (D64).

Global flags: `--vault FILE`, `--passphrase-stdin`, `--report FILE`.
- The passphrase is prompted with `rpassword` unless `--passphrase-stdin` is given. When the vault is created interactively, the passphrase is asked twice and both entries must match.
- Exit codes: 0 ok, 2 error. Scan and restore warnings do not change the exit code; restore prints a summary to stderr.
- `net-audit.sh` is extended to run the full scan → mask → restore under strace.

Tests: C1–C9, LF8, PF1–PF7.

Also in P4, the detection profile (SPEC v1.3 §5.1, D74–D80), in core first and then the CLI:
- core: `profile.rs` (load/save/validate/edit), `scan/detect/custom.rs` (D5), extra_keys in the D2/D3 key filter, `ignored` marking, default selection excluding ignored, `ignored_by_profile` and `ignored_new_secrets` counts;
- CLI: `veilcode profile list | add-key | remove-key | ignore-key | unignore-key | ignore | unignore`, and `--profile FILE` on scan, mask and restore.
Acceptance: standard checks ✔ · net-audit ✔ · manual run on a sample WordPress-style folder (C8, documented in the PR).

## P5 — CLI release v0.1.0
- [x] `.github/workflows/release.yml` triggers on a `v*` tag and builds `veilcode` for **linux-x86_64 and windows-x86_64** (macOS is not released; SPEC §13).
- [x] Each release includes SHA256SUMS, an SBOM (`cargo cyclonedx`), and build-provenance attestations (`actions/attest`, D90). Linux is a static musl binary, Windows is MSVC, and the release is created as a draft for the maintainer to publish (D91–D93).
- [x] `docs/THREAT_MODEL.md` (expanded SPEC §11, including the D65 retention limits) and `docs/VERIFY_OFFLINE.md`. The latter covers:
  - Linux: `unshare -rn veilcode ...` and `strace`.
  - Windows: a Firewall outbound-block rule plus Resource Monitor / Wireshark.
  - Verifying checksums and attestations with `gh attestation verify`.
- [x] README: install, 60-second demo, honest limitations (detection is best-effort, binaries are unsigned for now, D3 quote limitation), and the D65 retention section: keep retention short, exclude the data dir from sync and backup, passphrase strength, and malware while unlocked. Also the per-project vault pattern (D64).

Tests: REL1–REL3.
Acceptance: tag `v0.1.0-rc1` on a fork produces the artifacts and the attestation verifies. **Met 2026-10-14** on the main repo with `v0.1.0-rc2` (draft pre-release; REL1–REL3 evidence in VERIFY_LOG). `rc1` failed at the musl target install, fixed in #9.

## P6 — Desktop app (eframe/egui, native)
- Create `crates/veilcode-gui` (bin `veilcode-gui`). Add `eframe` with `default-features = false` and only the SPEC §9 features, plus `egui-file-dialog`.
- Choose the renderer per DECISIONS "Open" and log it.
- App state: `Locked | Unlocked(Vault)` plus view models that hold **previews only**. Argon2 and file I/O run on a worker thread, so the UI never freezes.

Screens:
1. Unlock or create vault
2. Scan: folder picker, findings list with checkboxes and previews
3. Review (mandatory before mask, D80): findings grouped by key or rule with file, line and preview; tick or untick; "remember as false positive" (this file / everywhere with confirmation); collapsed "Ignored" section with Unignore; "Add key name" field with re-scan; "Mask N secrets" confirm. Per-project profile option next to the per-project vault.
4. Mask: output folder, TTL selector (1–365, default 30), "separate vault for this project" option (D64), report
5. Restore: input and output folders, "keep session" checkbox (default off), report (new, unknown, missing, plus "session forgotten" or the kept reason)
6. Sessions: age and expiry columns, delete, "Purge all" with confirmation (D63)
7. Text Mode: two text areas, plus the warning on restored text

Auto-lock after 10 minutes without input. A "Lock now" button is always visible.
Linux CI installs the eframe system libraries (from the eframe/winit docs, logged in VERIFY_LOG). `net-audit.sh` adds the GUI under `xvfb-run`.
Tests: G1–G10 (incl. G9b).
Acceptance: standard checks ✔ · net-audit (CLI + GUI) ✔ · `cargo build --release -p veilcode-gui` succeeds on all 3 OS in CI.

## P7 — App release v0.2.0
- [x] Choose the packager per DECISIONS "Open" and log it (D111: cargo-deb + WiX 3; GUI on glibc, D112). Deliverables: Windows `.msi` plus portable `.zip`; Linux `.deb` plus `.tar.gz` (AppImage optional). Same checksums, SBOM and attestations as P5.
- [ ] README gets screenshots and a demo GIF; CONTRIBUTING.md; good-first-issue labels (new detector rules).

Tests: PKG1–PKG3, REL4.
Acceptance: the release artifacts install and run offline (verified per VERIFY_OFFLINE.md on Windows **and** Linux).

## Backlog (not scheduled)
Code signing (SignPath for Windows OSS), macOS releases and notarization, `cargo-fuzz` targets for the scanner and vault open, Flatpak, zip input, pre-commit hook, `restore --strict`.
