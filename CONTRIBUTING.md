# Contributing to Veilcode

Thank you for helping. Veilcode handles other people's secrets, so the rules
below are strict. They come from [CLAUDE.md](CLAUDE.md), which is binding for
every change.

## Build and test

Build and test on Linux (or WSL). The toolchain is pinned in
`rust-toolchain.toml`; install it with `rustup toolchain install` (run in the
repo, as CI does).

Run these before every commit; CI runs them too and they must pass with zero
warnings:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
bash scripts/check-offline.sh
bash scripts/check-test-ids.sh
bash scripts/net-audit.sh
```

- `cargo deny check` needs cargo-deny; CI installs it with
  `cargo install --locked cargo-deny@0.20.2`.
- `scripts/net-audit.sh` is Linux only. It needs `strace`, `util-linux` and
  `xvfb`, plus the GUI runtime libraries that `.github/workflows/ci.yml`
  installs (the "install strace, xvfb and GUI runtime libraries" step).

## Rules

- **Tests first.** Every behaviour has a test ID in
  [docs/TEST_CASES.md](docs/TEST_CASES.md). Write the test first, named
  `<id>_<words>` (for example `fn v1_create_save_open_roundtrip()`), see it
  fail for the right reason, then implement. Follow "Rules for a real test" in
  that file. Never rename, drop or weaken a test to make it pass.
- **No secret-shaped literals** anywhere in the repo: not in code, fixtures,
  docs, commit messages or proptest regression files. Tests generate secrets at
  runtime with the helpers in `crates/veilcode-core/src/test_support.rs`.
- **Secret values never appear** in logs, errors, reports, JSON or panic
  messages. Show previews only (first 4 characters, `…`, length).
- **No network or process code.** No HTTP, socket, TLS or DNS crates, no
  `std::net`, no `std::process::Command` in `crates/*/src`, no URL opening, no
  telemetry. `scripts/check-offline.sh` and the crate bans in `deny.toml`
  enforce part of this; reviewers check the rest.
- **Dependencies:** only the crates listed in [SPEC §9](docs/SPEC.md), added
  with `cargo add`. Never type a version by hand. Ask in an issue before
  proposing any other dependency.
- **Verify external facts.** A crate API, CLI flag, config key or GitHub Action
  SHA must be checked against its official source for the exact version used,
  and recorded in [docs/VERIFY_LOG.md](docs/VERIFY_LOG.md) with the date and
  URL. Do not write from memory.
- **No unverified claims** in docs, comments or PR text. Say "enforced" only
  for what a check fails on, "tested" for what a run exercised, and
  "unverified" for everything else.
- Never modify the user's input folder; all output goes to a new folder.
- If the spec is unclear, open an issue instead of guessing.

## Branches and pull requests

1. Branch from an up-to-date `main`.
2. Make one focused change, with its tests.
3. Open a pull request against `main`. Paste the output of the checks above
   and the final `cargo test` summary line into the description.
4. The maintainer reviews and merges. CI must be green.

## Proposing a new detection rule

- **For a key name only you use**, you probably do not need a code change: add
  it to your detection profile's `extra_keys`
  (`veilcode profile add-key <name> --profile <file>`). See "Detection
  profile" in the [README](README.md#detection-profile).
- **For a built-in detector**, open an issue with:
  - the key name or value format, and where it occurs (file types, config
    syntax);
  - how to generate an example at runtime, **never a real or real-looking
    value** pasted into the issue;
  - false-positive considerations: what similar-looking non-secrets exist and
    how the rule avoids them.
- **gitleaks rules** in `rules/gitleaks.toml` are vendored byte for byte from a
  pinned upstream gitleaks release (see [rules/README.md](rules/README.md)).
  Do not edit that file. Changes to those rules go to
  [gitleaks](https://github.com/gitleaks/gitleaks) first and arrive here with
  the next vendored update.

## Security issues

Do not report vulnerabilities in public issues or pull requests. Follow
[SECURITY.md](SECURITY.md).

## Licence

Veilcode is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. Unless you state otherwise, any
contribution you submit is licensed under the same terms, without additional
conditions.
