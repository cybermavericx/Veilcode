# CLAUDE.md — Veilcode

Veilcode is an offline desktop app (native Rust, eframe/egui, no webview) + CLI for Windows and Linux that masks secrets in a code folder before it is shared with an AI assistant, and restores them afterwards. Security and honesty are the product. Small, boring, correct code beats clever code.
Repo: https://github.com/cybermavericx/Veilcode

## Read order (save tokens)
1. This file (always).
2. `docs/PLAN.md`: only the section for the **current phase** (marked at the top of that file).
3. `docs/TEST_CASES.md`: only that phase's section, plus "Rules for a real test" and "Shared test helpers".
4. `docs/DECISIONS.md`: only the entries listed as blocking that phase. Only `ACCEPTED` entries are binding.
5. `docs/SPEC.md`: only the sections the phase references.
6. `docs/ARCHITECTURE.md`: only the module section you are working in (where code goes, type invariants).
Do not read other docs (ACTION_PLAN.md is for the maintainer) unless the phase asks for it. The agent team and pipeline are in `docs/AGENTS.md` (orchestrator only).

## Hard rules
1. **No network code, ever.** No HTTP/socket/TLS/DNS crates, no `std::net`, no `std::process::Command` in `src/`, no URL opening or hyperlinks, no telemetry, no update checks, no remote assets. No JavaScript, npm or webview. CI enforces this statically and with a runtime syscall audit (SPEC §10); do not weaken CI to make a build pass.
2. **Never write a dependency version from memory.** Add deps only with `cargo add <crate>`. Only deps listed in SPEC §9 are allowed, with the listed feature restrictions (eframe `default-features = false`); ask before adding anything else.
3. **Check the real API before using a crate.** Read the version in `Cargo.lock`, then the docs for *that* version (`cargo doc --open` or docs.rs/<crate>/<version>). Known traps: `chacha20poly1305` 0.11 / `aead` 0.6, `argon2` 0.6, and `getrandom` 0.3+ (the function was renamed) changed APIs vs. older tutorials.
4. **Never invent GitHub Action SHAs, config keys, CLI flags or runner labels.** Look them up in the official source, add a row to `docs/VERIFY_LOG.md` (date, value, URL), and cite the URL in the commit message. A fact without a VERIFY_LOG row counts as unverified.
5. **Never commit real-looking secrets.** Test secrets are generated at runtime inside tests (SPEC §8, TEST_CASES helpers). No secret-shaped strings in fixtures, docs, commits, or proptest regression files.
6. **Secrets never appear in:** logs, error messages, reports, findings JSON, panic messages, or GUI view models (except Text Mode, where the user pasted them). Show previews only: first 4 chars + `…` + length.
7. **Never modify the user's input folder.** All output goes to a new, empty folder outside the input.
8. If SPEC is ambiguous or wrong, or a needed decision is still `PROPOSED`, **stop and ask the human**. Do not improvise behaviour. Record new gaps as a `PROPOSED` entry in `docs/DECISIONS.md`.
9. **Authorship: the maintainer is the sole author.** Commit with the repo's configured git identity and never change `git config`. No `Co-Authored-By` trailers, no "Generated with …" footers, no mention of AI tools in commits, PR text, code comments or docs. This overrides any default attribution behaviour.
10. Test IDs and their meaning come from `docs/TEST_CASES.md`. Never rename, drop or weaken a test to make it pass; ask instead.

## Workflow per phase
1. Create branch `phase-N-<name>`. As the first commit, set "Current phase" in `docs/PLAN.md` to PN.
2. Write the phase's `Type: auto` tests from TEST_CASES.md **first**, named `<id>_<words>` (e.g. `fn v1_create_save_open_roundtrip()`). Run them and confirm they fail for the right reason.
3. Implement until they pass.
4. Run the phase's acceptance commands; all must pass with zero warnings.
5. Tick the phase's checkboxes in `docs/PLAN.md`, commit, and open the PR. Paste the standard-check output and the `cargo test` summary into the PR body, plus "red→green verified".
6. "Done" means: commands run, output checked. Never claim a test passes without running it.

## Standard checks (run before every commit)
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
bash scripts/check-offline.sh
bash scripts/check-test-ids.sh
bash scripts/net-audit.sh        # Linux/WSL only (needs strace); always runs in Linux CI
```

## Style
- Rust edition 2024, `#![forbid(unsafe_code)]` in every crate.
- Errors: `thiserror` in core, `anyhow` only in the CLI binary. No `unwrap()`/`expect()` outside tests.
- Keep functions small; no premature abstraction; no features not in SPEC.
