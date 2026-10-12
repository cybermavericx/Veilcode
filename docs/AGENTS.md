# Veilcode — Agent team and workflow

The agents are defined in `.claude/agents/`. The **main Claude Code session is the orchestrator**: subagents cannot call each other, so the main session runs them in order and passes the reports along. Every agent reads `CLAUDE.md` first and obeys it.

| Agent | Persona | Can edit | Model |
|---|---|---|---|
| `veilcode-developer` | Senior Rust engineer (10+ years) | `crates/`, test files, VERIFY_LOG rows, PROPOSED decisions | inherit |
| `veilcode-infra-engineer` | DevSecOps / supply-chain engineer | `.github/`, `scripts/`, `deny.toml`, toolchain, profiles, release | inherit |
| `veilcode-security-reviewer` | AppSec + crypto reviewer, red-team mindset | nothing (read-only) | inherit |
| `veilcode-qa` | QA lead; re-runs everything and traces tests to the spec | nothing (read-only, scratch copies only) | sonnet |
| `veilcode-fact-checker` | Primary-source researcher | VERIFY_LOG (append only) | sonnet |

The maintainer (you) owns SPEC.md, the DECISIONS status, merges and pushes.

## Per-phase pipeline
```
 0. orchestrator: create branch development/phase-N-<name> from main, set "Current phase: PN"
 1. fact-checker  : verify every "To verify" item for PN in VERIFY_LOG          (before code)
 2. infra-engineer: CI/scripts parts of PN (all of P0, P5, P7; the CI part of P6)
 3. developer     : tests first (red) → implement (green) → standard checks → commit
 4. qa            : re-run, trace tests to TEST_CASES, red-check samples, edge cases → PASS/FAIL
 5. security      : review the diff → findings by severity
 6. orchestrator  : if QA FAIL or any Critical/High finding → back to step 3 (or 2) with the report
 7. orchestrator  : push the branch, open a PR (no AI footer), paste the QA verdict and security summary
 8. maintainer    : read the PR, merge
```
Steps 4 and 5 can run in parallel. At most **2 fix loops** per phase; after that, stop and ask the maintainer.

## Phase leads
| Phase | Lead | Also runs |
|---|---|---|
| P0 Bootstrap | infra-engineer | developer (workspace skeleton), qa (O1–O4), security |
| P1–P3 Core | developer | qa, security (crypto focus on P1, filesystem focus on P3) |
| P4 CLI | developer | infra (net-audit extension), qa, security |
| P5 CLI release | infra-engineer | fact-checker (Action SHAs, flags), security |
| P6 GUI | developer | infra (Linux deps, GUI net-audit), qa (G5 checklist), security (feature audit) |
| P7 App release | infra-engineer | qa (REL4 on Windows and Linux), security |

## Prompt to start a phase (paste into Claude Code)
> Read CLAUDE.md and docs/AGENTS.md. Run the per-phase pipeline for the current phase in docs/PLAN.md: start with veilcode-fact-checker, then the phase lead, then veilcode-qa and veilcode-security-reviewer in parallel. Fix loops at most 2. Do not merge. Report the QA verdict, the security findings and the PR link.

## Token budget
- Agents read only the current phase's sections (CLAUDE.md read order).
- Reviewers read the diff, not the whole repo.
- The fact-checker and QA run on sonnet.
- Reports are capped at their "Report format" sections; there are no narrated logs.
