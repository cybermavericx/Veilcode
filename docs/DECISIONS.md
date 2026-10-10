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
