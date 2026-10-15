# Veilcode — Plan of action

This is for the maintainer. Claude Code does not need to read it each session.

## Document map
| File | Purpose | Who reads it |
|---|---|---|
| `CLAUDE.md` | Rules, read every session | Claude Code |
| `docs/SPEC.md` (v1.1) | Frozen behaviour, all decisions folded in | Claude Code (sections the phase cites) |
| `docs/PLAN.md` | Phases, tasks, acceptance | Claude Code (current phase only) |
| `docs/TEST_CASES.md` | Exact Given/When/Then per test ID | Claude Code (current phase only) |
| `docs/DECISIONS.md` | Why SPEC says what it says; new gaps go here as PROPOSED | Maintainer, plus Claude Code when blocked |
| `docs/VERIFY_LOG.md` | Every external fact with its URL and date | Claude Code writes, maintainer audits |
| `scripts/check-test-ids.sh` | Fails if a listed test does not exist | CI and standard checks |

## Platform and environment (D1)
- **Targets:** Windows 10/11 x86_64 and Linux x86_64. macOS is built and tested in CI only.
- **Your dev machine:** Windows 11 natively. You build and run the GUI there, which is where most users will be.
- **Linux checks:** WSL Ubuntu, for `strace` / `net-audit.sh`, `.deb` testing and a quick GUI check via WSLg. CI runs the authoritative Linux checks on every PR.

## Security design in one paragraph (D22, D23)
- There is no web engine: the GUI is native Rust (egui), so there is no JavaScript, no npm and no browser component that could fetch anything. The whole program is a single Rust dependency graph that `cargo deny` audits.
- HTTP, TLS, DNS and browser-launch crates are banned.
- Our own code can't open sockets or launch programs; a grep in CI enforces this.
- On every PR, Linux CI runs defined CLI and GUI scenarios under `strace` in an empty network namespace and fails if any non-local socket is opened. This tests those scenarios; it does not prove every code path (D107).
- Secrets live only in an Argon2id + XChaCha20-Poly1305 vault. Reports, logs and the GUI show 4-character previews only.

## Anti-hallucination layers
1. **Facts:** versions, SHAs, flags, features and config keys are verified and logged in VERIFY_LOG before use, and the commit message cites the URL.
2. **Behaviour:** anything not in SPEC v1.1 means stop and ask (a new PROPOSED entry in DECISIONS).
3. **Tests:** IDs are fixed in TEST_CASES.md; `check-test-ids.sh` proves each test function exists; red→green is required; assertions must be concrete.
4. **Completion:** a phase is done only with pasted command output in the PR.
5. **Review:** prompt "List every external fact this PR relies on and its VERIFY_LOG row."

## Step 0 — Before any code (you, about 45 min)
1. **Install on Windows:**
   - Visual Studio Build Tools, with the "Desktop development with C++" workload
   - `rustup` (stable, MSVC)
   - GitHub CLI `gh`, then run `gh auth login`

   Then:
   ```bash
   cargo install --locked cargo-deny
   ```
2. **Install in WSL Ubuntu:**
   ```bash
   sudo apt install build-essential strace xvfb
   ```
   Also install `rustup` there.
3. **GitHub repo settings:** turn on secret scanning plus push protection, private vulnerability reporting, and branch protection on `main` (PR required, CI required).
4. **Clone and add the plan files.** First:
   ```bash
   git clone https://github.com/cybermavericx/Veilcode.git
   ```
   Copy `CLAUDE.md`, `.claude/agents/`, `docs/` and `scripts/` into the clone. Then, inside it, set your identity for this repo only:
   ```bash
   git config user.name "Muhammed Noufal"
   ```
   ```bash
   git config user.email "muhammednoufal7@gmail.com"
   ```
   Commit as `docs: add spec v1.1, plan, test cases, decisions and verify log` (no trailer), then push to `main`. This is the only direct push.

## Step 1 — Phase loop (one Claude Code session per phase)
Prompt (single agent; for the full agent team use the prompt in docs/AGENTS.md):
> Read CLAUDE.md, then do the current phase in docs/PLAN.md. Use docs/TEST_CASES.md for that phase only. Log every looked-up fact in docs/VERIFY_LOG.md.

Review checklist for each PR:
- [ ] Commits show only you (`git log --format='%an <%ae>%n%b' main..`): no Co-Authored-By trailer and no AI footer
- [ ] `check-test-ids.sh` passes and the PR shows red→green
- [ ] `net-audit.sh` passes in Linux CI (from P0 on)
- [ ] New external facts have VERIFY_LOG rows with URLs
- [ ] No new dependency outside SPEC §9; eframe still has `default-features = false`
- [ ] No secret-shaped literal added (push protection plus a skim of the test files)
- [ ] The acceptance output is pasted

## Phase order and risk focus
| Phase | Highest risk | Mitigation |
|---|---|---|
| P0 | Invented Action SHAs, cargo-deny keys, strace parsing | VERIFY_LOG; tests O1–O4 |
| P1 | New chacha20poly1305/argon2/getrandom APIs written from old memory | docs.rs for the exact locked version; V1–V11 |
| P2 | gitleaks schema drift; Go regex vs Rust regex | Pin a release tag; S15 compile rate |
| P3 | Path traversal; TOCTOU; round-trip breakage | M4b, M10, R6, PROP1 |
| P4 | Slow debug Argon2; secrets on stderr | Profile override; C5; C9 audit |
| P5 | Attestation flags | REL1–REL3 |
| P6 | eframe defaults re-enabling `links`; renderer failing over RDP or Wayland | G4 feature test; G5 QA matrix; G6 audit |
| P7 | Packager downloading unpinned tools at build time | Pin and checksum per VERIFY_LOG; REL4 on both OS |

## Out of scope reminders
No zip input, dummies, vault export, auto-update, signing, fuzzing or macOS releases in v1. Requests for these go to the PLAN backlog.
