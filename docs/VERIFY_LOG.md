# Verify log

Each external fact the code depends on gets a row here **before** it is used: a crate version, API or feature; an Action SHA; a config key; a CLI flag; a runner label; system packages; or a gitleaks commit. Each row gives the source URL and the date checked. A fact with no row has not been verified. Append rows; never edit old ones, and add a new row if a fact changes.

| Date | Fact | Value | Source (URL or command) | Used in |
|---|---|---|---|---|
| 2026-10-09 | Repo exists, public, README only, default branch | `cybermavericx/Veilcode`, `main` | api.github.com/repos/cybermavericx/Veilcode | SPEC header |
| 2026-10-09 | Rust/cargo/gh installed on dev PC | **none** (Windows and WSL) | `rustc --version` → not found | ACTION_PLAN step 0 |
| 2026-10-09 | eframe latest stable, licence | 0.36.2, MIT OR Apache-2.0 | crates.io/api/v1/crates/eframe | SPEC §9 (D22) |
| 2026-10-09 | eframe 0.36.2 default features | accesskit, default_fonts, **links**, wayland, web_screen_reader, wgpu, winit/default, x11; optional: glow, persistence | crates.io/api/v1/crates/eframe/0.36.2 | SPEC §9: `default-features = false` |
| 2026-10-09 | egui-file-dialog latest, licence | 0.15.0, MIT | crates.io/api/v1/crates/egui-file-dialog | SPEC §9 |
| 2026-10-09 | iced latest, licence (rejected alternative) | 0.14.0, MIT | crates.io/api/v1/crates/iced | DECISIONS D22 |
| 2026-10-09 | rfd latest, licence (rejected: Linux portal over D-Bus) | 0.17.2, MIT | crates.io/api/v1/crates/rfd | DECISIONS D22 |
| 2026-10-09 | Packager candidates | cargo-packager 0.11.8 (Apache-2.0 OR MIT), cargo-deb 3.8.0 (MIT), cargo-wix 0.3.9 (MIT/Apache-2.0) | crates.io API | P7 choice |
| (carried) | chacha20poly1305 0.11 / aead 0.6 / argon2 0.6, MSRV 1.85 | re-check at P1 against Cargo.lock | docs.rs | SPEC §9 |
| (carried) | cargo-deny `[bans] deny` entry syntax | re-check at P0 | embarkstudios.github.io/cargo-deny | deny.toml |
| (carried) | gitleaks rules path `config/gitleaks.toml`, MIT | re-check at P2 at the pinned tag | github.com/gitleaks/gitleaks | rules/ |

## To verify, by phase (fill in a row when done)
- **P0:**
  - The stable Rust version (`rustup check`).
  - SHAs for `actions/checkout`, the Rust toolchain action and `EmbarkStudios/cargo-deny-action`, from each one's releases page.
  - The cargo-deny license allow-list, from `cargo deny check licenses` output, not memory.
  - `shell: bash` on Windows runners.
  - strace output format for `socket(AF_INET…` lines on ubuntu-latest, from a real run.
- **P1:**
  - The getrandom version in Cargo.lock and its fill function name (it changed in 0.3).
  - The AEAD nonce generation and key-init API for the locked chacha20poly1305.
  - The `argon2::Params::new` signature and `hash_password_into`.
  - zeroize derive features.
  - The Cargo profile override syntax and the argon2-related crate names in Cargo.lock (D18).
- **P2:**
  - The gitleaks release tag, commit SHA and file sha256.
  - The allowlist schema at that commit.
  - The secretGroup and entropy logic in `detect/detect.go`.
  - The `regex` size-limit API.
- **P3:** the proptest config field for failure persistence.
- **P4:** clap derive attribute names for the locked version; rpassword's function name.
- **P5:**
  - Runner labels for ubuntu and windows.
  - The `cargo-cyclonedx` install and flags.
  - The inputs and permissions of `actions/attest-build-provenance`.
  - The `gh attestation verify` flags.
- **P6:**
  - The eframe MSRV and exact feature names at the locked version: the renderer, and clipboard if it is separate.
  - The `NativeOptions`/`run_native` API.
  - The egui-file-dialog API at the locked version.
  - Linux system packages for eframe on ubuntu-latest, and `xvfb-run` availability.
  - A renderer smoke test on Windows over RDP.
- **P7:**
  - The packager chosen and its version.
  - Whether it downloads WiX/NSIS at build time; if so, pin and checksum those tools.
