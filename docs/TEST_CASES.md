# Veilcode — Test cases (source of truth for test IDs)

Read only the section for the current phase. Every `Type: auto` ID must have a Rust test function named `<id lowercase>_<words>` (for example `fn v1_create_save_open_roundtrip()`). `scripts/check-test-ids.sh` enforces this for every phase up to the current one.
All decisions are folded into SPEC v1.1. If a new decision is pending, its tests are marked `Type: pending` and skipped by the guard.

## Rules for a real test (anti-hallucination)
1. **Red first.** Write the test, run it, and see it fail for the right reason before implementing. The PR body says "red→green verified" and pastes the final `cargo test` summary line.
2. **Assert concrete values**: exact bytes, counts, error variants or messages. `assert!(x.is_ok())` alone is not a test.
3. No `#[ignore]`, no `#[should_panic]` without `expected = "…"`, and no sleeping on timing (inject a clock instead).
4. **Secrets are generated at runtime** with the helpers below. A literal that looks like a secret anywhere in the repo is a bug.
5. Every test that handles secrets ends with `assert_no_secret(&output_bytes, &secrets)` on every report, log, error string or JSON it produced.
6. Tests use `tempfile::TempDir` only. Never touch the real vault path or `$HOME`.
7. If a test cannot be written as specified, **stop and ask**. Do not weaken it quietly.

## Shared test helpers (written in P1, module `veilcode-core/src/test_support.rs`, `#[cfg(test)]`)
| Helper | Behaviour |
|---|---|
| `random_alnum(n) -> String` | `[A-Za-z0-9]` from getrandom |
| `fake_github_pat() -> String` | `"ghp_"` + `random_alnum(36)`; the prefix is assembled at runtime as `["gh","p_"].concat()` so the source contains no scannable literal |
| `fake_password() -> String` | 20 random alnum characters plus at least one symbol from `!%^*` |
| `write_tree(dir, &[(rel, bytes)])` | creates parent directories and writes the files |
| `tree_hashes(dir) -> BTreeMap<String, [u8;32]>` | sha256 of every file, with rel paths using `/` |
| `assert_no_secret(haystack: &[u8], secrets: &[impl AsRef<[u8]>])` | fails with the secret's **preview** only, never the value |
| `test_vault(dir) -> Vault` | low Argon2 params (m=8 KiB, t=1, p=1) via a `pub(crate)` constructor |

Core tests live in-crate (`#[cfg(test)]`) so they can use `pub(crate)` test constructors. CLI tests live in `crates/veilcode-cli/tests/` and run the real binary.

---

## P0 — Bootstrap
### O1 — the offline script catches network code
Type: command
Steps:
1. Temporarily create `crates/veilcode-core/src/_probe.rs` containing `use std::net::TcpStream;`.
2. Run `bash scripts/check-offline.sh`.
3. Delete the probe.

Pass when it exits non-zero naming the file, then exits 0 after the probe is removed. The PR body shows both runs.
### O2 — cargo-deny catches a banned crate
Type: command
Steps:
1. On a scratch branch, run `cargo add -p veilcode-core ureq`.
2. Run `cargo deny check bans` and confirm it fails naming `ureq`.
3. Revert.

Pass when the failure output is pasted in the PR and the revert is confirmed with `git diff --stat` (empty).
### O3 — the test-ID guard catches a missing test
Type: command
Steps: temporarily change "Current phase" to P1 and run `bash scripts/check-test-ids.sh`. It must list V1… as MISSING. Revert.
### O4 — the network audit catches a socket
Type: command
Steps (Linux / WSL):
1. Run `bash scripts/net-audit.sh` against a throwaway probe binary that opens a TCP socket. A scratch Rust bin outside the workspace works, e.g. `cargo new` in a temp dir with `std::net::TcpStream::connect("127.0.0.1:9")`.
2. Run it again against `veilcode --help`.

Pass when the first run fails naming `AF_INET` and the second passes. Paste both in the PR. The audit script must accept the binary and arguments to audit, so it can be tested this way.

---

## P1 — Vault and tokens
### V1 — create, save and open round trip
Type: auto
Given a test vault holding 2 sessions and 3 entries (one value with non-ASCII bytes), when it is saved and reopened with the same passphrase, the entries and sessions are equal (`==`).
### V2 — wrong passphrase
Type: auto
Opening with a different passphrase gives an error whose `to_string()` is exactly "wrong passphrase or corrupted vault".
### V3 — single-byte tamper
Type: auto
For every byte offset of a saved vault (a small vault keeps this loop fast), flipping one bit makes `open` fail. Every offset fails with the generic error, including header offsets caught by the bounds check.
### V4 — fresh nonce per save
Type: auto
Two saves of identical content give different xnonce bytes and different ciphertext.
### V5 — atomic save leaves no temp file
Type: auto
After save, `vault.vc.tmp` does not exist and the first 8 bytes are `VEILCODE`.
### V6 — KDF params come from the header
Type: auto
Write a vault with m=8 KiB, t=1, p=1. Reading the header bytes gives those values (`u32` LE at the offsets in SPEC §7), and open succeeds.
### V7 — minimum passphrase length
Type: auto
11 characters is rejected on create. 12 characters is accepted, and that includes a 12-character string of multi-byte characters such as `"ééééééééééé"` plus one more.
### V8 — Debug never prints secrets
Type: auto
`format!("{:?}", vault)` and `format!("{:?}", entry)` contain neither the value nor the passphrase (checked with `assert_no_secret`).
### V9 — absurd header params are rejected before the KDF
Type: auto
Patch `m_cost` to `u32::MAX` in a saved file. `open` returns the generic error within 1 s, and the KDF is not called (test this with a call counter on the KDF wrapper). Repeat for `t_cost = 0` and `p_cost = 5`.
### V10 — non-UTF-8 value round trip
Type: auto
The value `[0xff, 0xfe, b'a']` survives save and open byte for byte.
### V11 — concurrent-writer detection
Type: auto
Open A, then open B. Save B. Saving A then fails with the "changed by another Veilcode process" error, and the file still holds B's content.
### T1 — token format
Type: auto
1,000 tokens all match the SPEC §4 regex (the D4 version once accepted) over their **whole** length.
### T2 — uniqueness
Type: auto
10,000 tokens produced by the generator through a vault are all distinct.
### T3 — dedupe
Type: auto
`get_or_create(value)` called twice returns the same token, and the vault holds 1 entry.
### T4 — name sanitisation
Type: auto
| Input | Expected NAME |
|---|---|
| `db.password-1` | `DB_PASSWORD_1` |
| `__a__b__` | `A_B` |
| `$$$` | `SECRET` |
| 40×`a` | 24×`A` |
### T5 — HEX8 always contains a letter
Type: auto
Using an injected RNG that returns `00000000` and then `0a000000`, the generator rejects the first value and returns a token ending in the second.
### T6 — tokens adjacent to word characters
Type: auto
For token `t`, the strings `"x" + t + "yz"`, `"_" + t + "_"`, `t + "9abcdef0"` and `t + "_1a2b3c4d"` each yield exactly one match, equal to `t`.
### T7 — token collision with the input
Type: auto
Using an injected RNG whose first token already appears in a given input byte slice, the generator returns the second candidate.

### T8 — empty secret rejected
Type: auto
`get_or_create_token` with an empty value returns an error and adds no entry (D30).
### V12 — malformed files never panic
Type: auto
A 0-byte file, the 8-byte magic alone, the header alone, and header + 15 bytes each give the generic error, with no panic. A directory given as the vault path gives an `Io` error (D30).
### V13 — save lock and file mode
Type: auto
If `vault.vc.tmp` already exists, save fails with the D28 error and leaves both files untouched. On Unix (`#[cfg(unix)]`) the saved `vault.vc` has mode `0600`.

---

## P2 — Scanner
### S1 — D2 env detection
Type: auto
A `.env` file holding `DB_PASSWORD=<pw>` and `APP_NAME=demo` gives 1 finding (detector D2, key `DB_PASSWORD`), and its span bytes equal `<pw>`.
### S2 — D3 PHP define
Type: auto
`wp-config.php` holding `define('DB_PASSWORD','<pw>');` and `define( "AUTH_KEY" , "<k>" );` gives 2 D3 findings with the correct spans.
### S3 — D4 URL credentials
Type: auto
`postgres://u:<pw>@h/db`: the span is exactly `<pw>`.
### S4 — D1 GitHub PAT
Type: auto
A `config.js` file containing `fake_github_pat()` gives a D1 finding whose `rule_id` is the gitleaks GitHub-PAT rule id. Take the id from the vendored file; do not write it from memory.
### S5 — entropy gate
Type: auto
For a rule with `entropy` set, a low-entropy value (one character repeated) gives no finding, and a random value gives one.
### S6 — keyword pre-filter
Type: auto
For a file that contains no keyword of rule R, the evaluation counter for R stays at 0.
### S7 — overlap resolution
Type: auto
Synthetic overlapping candidates (longer vs shorter, a same-length tie across detectors, a chain A⊃B, B∩C, a partial overlap) give exactly the expected set **per D48**: overlapping candidates are merged into their union span, credited to the D10 winner; output sorted by (rel_path, start).
### S8 — existing tokens ignored
Type: auto
A `.env` file holding `API_KEY=<a valid token>` gives 0 findings.
### S9 — binary skipped
Type: auto
A file with a NUL in its first 8 KiB, containing a PAT after the NUL, gives 0 findings and is listed under `skipped.binary`.
### S10 — oversized skipped
Type: auto
A 5 MiB + 1 byte file is listed under `skipped.oversized`. A file of exactly 5 MiB is scanned.
### S11 — `.git` always excluded
Type: auto
`.git/config` containing a PAT gives 0 findings even with `no_default_excludes=true`.
### S12 — `.veilcodeignore`
Type: auto
The pattern `secrets/**` (plus a `# comment` line) excludes `secrets/a.env`, and `other.env` is still scanned.
### S13 — symlinks not followed
Type: auto
A symlink to a file with a PAT gives 0 findings and is listed under `skipped.symlink`. This is Unix-only, gated with `#[cfg(unix)]`, because creating symlinks on Windows needs Developer Mode. Note the gating in the PR.
### S14 — findings JSON holds no secrets
Type: auto
`serde_json::to_vec(&report)` passes `assert_no_secret` for every planted secret.
### S15 — gitleaks rule compile rate
Type: auto
Loading the vendored rules gives `compiled / supported ≥ 0.95`, and the skipped count equals `warnings.len()`.
### S16 — non-UTF-8 file
Type: auto
A `.env` file with Latin-1 bytes before `DB_PASSWORD=<pw>` is scanned without error and the span is correct.
### S17 — CRLF `.env`
Type: auto
`DB_PASSWORD=<pw>\r\n`: the span excludes `\r`.
### S18 — D2 value forms
Type: auto
| Line | Expected span |
|---|---|
| `export TOKEN="<v>"` | `<v>` |
| `SECRET='<v>'` | `<v>` |
| `KEY=<v> # note` | `<v>` |
| `PASS=` | no finding |
| `AUTH=${FROM_ENV}` | no finding |
| `AUTH=$(cmd)` | no finding |
### S19 — position format
Type: auto
For a secret at line 3, byte column 5, the finding has `line == 3`, `column == 5`, and a `rel_path` with `/` separators.

### S2b — PHP define with a space before the bracket (D49)
Type: auto
`define ("DB_PASSWORD" , "<pw>") ;` gives 1 D3 finding with the exact span.
### S3c — raw `@` in a URL password (D50)
Type: auto
`mysql://u:pa@ss<pw>@h/db`: the span is exactly `pa@ss<pw>`.
### S8b — span containing a token plus other bytes is kept (D48a)
Type: auto
`TOKEN=VEILCODE_X_abcdef12<rest>`: one finding whose span covers the whole value. A value that is exactly a token gives no finding (as S8).
### S16b — invalid UTF-8 inside the secret (D41)
Type: auto
A `.env` value, a PHP define value and a URL password, each containing byte `0xE9`, are each detected, and each span includes that byte.
### S20 — hostile input stays fast (D42)
Type: auto
A 5 MiB file of repeated `a://b:c@` and a 4 MiB single line of repeated PATs each scan in under 30 s in the debug test build. Assert the elapsed time; the finding counts must be consistent.
### S21 — `.git` case and trailing-dot variants (D43)
Type: auto
`.GIT/config`, `sub/.Git/config` and `.git./config` (Unix only for the trailing dot) each containing a PAT give 0 findings, even with `no_default_excludes`.
### S22 — unsafe `.veilcodeignore` (D44)
Type: auto
A `.veilcodeignore` of 1 MiB + 1 byte makes the scan fail with the D44 error. On Unix, a `.veilcodeignore` that is a symlink, or a FIFO created via `mkfifo`, also gives the D44 error without blocking. The FIFO case is skipped if mkfifo is unavailable; never use libc for it.
### S23 — non-UTF-8 file name (D46, Unix except macOS, whose APFS rejects such names)
Type: auto
A file named with byte `0xFF` holding a PAT is not scanned and is listed under `skipped.non_utf8_name`, and no `rel_path` collides.
### S24 — line-target allowlists are ignored (D47)
Type: auto
A line holding a `generic-api-key`-style secret plus the upstream line-allowlist text (`--mount=type=secret,`) is still reported. The warning count includes the dropped line-target entries.
---

## P3 — Mask and restore
### M1 — masking leaves the input untouched
Type: auto
`tree_hashes(input)` before and after mask are equal. The output contains a token in place of each secret, and `assert_no_secret(output files)` passes.
### M2 — output inside input
Type: auto
Error. Nothing is written.
### M3 — non-empty output
Type: auto
Error. The existing output files are unchanged.
### M4 — file changed after scan
Type: auto
Edit a file that has a finding, then mask. Error "file changed since scan — rescan". The output dir is still empty.
### M4b — clean file changed after scan
Type: auto
Add a secret to a file that had no findings at scan time, then mask. Same rescan error.
### M5 — deselected finding
Type: auto
Select all findings except one. That secret's bytes are present in the output and the others are absent.
### M6 — unscanned files
Type: auto
Binary and oversized files are absent by default, and present and byte-identical with `include_unscanned=true`.
### M6b — symlinks never copied
Type: auto
A symlink is absent even with `include_unscanned=true` (Unix only).
### M7 — byte preservation
Type: auto
A CRLF file with Latin-1 bytes outside the secret span: the output equals the input with only the span replaced, checked byte for byte.
### M8 — vault state after mask
Type: auto
The vault has 1 new session, with token count equal to the number of distinct secrets, and entry values equal to the secrets.
### M9 — non-UTF-8 secret masked and restored
Type: auto
A `.env` file whose `DB_PASSWORD` value contains the bytes `0xff 0xfe` is masked, and the vault entry's `value_hex` holds those bytes. Restoring gives the original file byte for byte.
### M10 — malicious findings-file paths
Type: auto
Each `rel_path` in `../x`, `a/../../x`, `/etc/x`, `C:\x`, `\\srv\x` and `a//b` is rejected before any write, and the output dir stays empty.
### M11 — output dir must be new and private (D68)
Type: auto
An existing empty output dir is refused for both mask and restore, and nothing is written. A non-existent output dir with missing parents is created. On Unix: the created output root has mode `0700`, and a parent with mode `0777` without the sticky bit is refused, while `/tmp`-style `1777` is accepted.
### R1 — round trip
Type: auto
Mask, then restore. The restored tree equals the input tree, excluding `.git` and not-copied files.
### R2 — survives AI edits
Type: auto
Before restoring the masked tree:
- rename a file
- reverse its line order
- duplicate a token into a second file
- add a new file containing an existing token

Then restore. Every token is replaced, and the edited content is restored correctly.
### R3 — unknown token
Type: auto
`VEILCODE_FAKE_1a2b3c4d` (not in the vault) is left as is and appears in `report.unknown`.
### R4 — missing token
Type: auto
Delete one token from the masked tree. It appears in `report.missing`.
### R5 — new secret introduced by the AI
Type: auto
Add `fake_github_pat()` to the masked tree. It is in `report.new_secrets` as a preview only, and the report JSON passes `assert_no_secret`.
### R6 — write containment
Type: auto
The output-path join helper rejects `..` and absolute paths, and every written path canonicalises under the output dir (assert over all writes).
### R7 — reports hold no secrets
Type: auto
MaskReport and RestoreReport JSON pass `assert_no_secret`.
### R8 — tokens are not re-detected
Type: auto
When restoring a masked `.env` file or URL (`postgres://u:VEILCODE_…@h`), `report.new_secrets` is empty.
### R9 — token after a `VEILCODE_` prefix (D29)
Type: auto
The text `VEILCODE_` + token (and `VEILCODE_X_` + token) restores the token to its secret, leaving the prefix bytes untouched.
### R10 — permissions kept, restored secrets owner-only (D55, Unix)
Type: auto
An executable script (`0o755`) holding a secret is masked to `0o755`. After restore, a file with a replaced token is `0o700`; an untouched file keeps its mode.
### R11 — output never overwrites (D54)
Type: auto
The write helper refuses an existing path, including a pre-planted symlink inside the output dir (Unix), and never follows it.
### R12 — restore needs a session (D73)
Type: auto
On a vault with no sessions, `restore(…, None, …)` and `restore_text(…, None, …)` both return the D73 error, and the output dir is not created.
### R13 — failed run removes its partial output (D69)
Type: auto
Use the paths.rs write-failure hook to fail after 2 files, once in mask and once in restore. Pass when each returns `PartialOutput { cleaned: true, .. }`, the output dir no longer exists, and the vault is unchanged (file sha256 equal).
### X1 — text mode round trip
Type: auto
`restore_text(mask_text(s).0) == s` for a string holding a PAT, a URL password and an env line.
### SE1 — sessions
Type: auto
Two sessions share one secret. Deleting session 1 keeps the shared entry and drops entries unique to session 1. `list` shows the right counts. Deleting an unknown id gives an error.
### PROP1 — property round trip
Type: auto
proptest generates trees of 1–5 files with random bytes (including CRLF, NUL-free text and adjacent word characters), with planted D2, D4 and PAT secrets. Then `restore(mask(x)) == x` holds. Use `failure_persistence: None` and low vault params.
### SE2 — session records scan options; restore uses them (D57r)
Type: auto
Mask with `no_default_excludes = true` on a tree that has `node_modules/x.js`. Restore round-trips that file. The session JSON holds `scan_options`.
### LF1 — clean restore forgets the session (D60)
Type: auto
Sessions A and B share a secret, and A also has a secret of its own.

Pass when, after a clean restore of A (keep = false):
- the report has `session_forgotten == true`;
- session A is gone;
- the entry unique to A is gone;
- the shared entry still exists and B still lists it;
- the vault reopens with the same passphrase.
### LF2 — non-clean restore keeps the session (D60)
Type: auto
Delete one token from the masked tree, then restore. Pass when `session_forgotten == false`, `kept_reason` reports `missing = 1`, and the session and all its entries are still in the reopened vault. Repeat once with an unknown token and once with an added secret; each must keep the session.
### LF2b — not clean when files were not copied or tokens remain in unscanned files (D71)
Type: auto
Run two restores. In the first, a vault token is in a copied binary file and also in a text file. In the second, a text file is `changed_during_scan` or has a non-UTF-8 name (Unix except macOS, whose APFS rejects such names). Pass when both keep the session, with `kept_reason` naming `tokens_in_unscanned` and `not_copied` respectively. A token from another session gives `foreign_session_tokens == 1` and does not by itself block forgetting.
### LF3 — keep retains the session (D60)
Type: auto
A clean restore with `keep = true` gives `session_forgotten == false`, `kept_reason == KeepRequested`, and the session and entries unchanged.
### LF4 — expiry on open (D61)
Type: auto
Use a manual clock. Mask session X with `ttl_days = 1` and session Y with `ttl_days = 30` at time T. Open at T + 86400 + 1.

Pass when:
- `expired_removed == 1`;
- X and its unique entries are gone, and Y is kept;
- the file on disk was rewritten: the file sha256 changed, and a fresh open sees X absent;
- opening at T + 10 s removes nothing;
- opening at exactly X's `expires_at` removes X, while a session whose `expires_at` is 1 s later stays (D61: `expires_at <= now` is expired). Changing `<=` to `<` must make this test fail.

Also check that `ttl_days` values 0 and 366 are rejected, and that a tampered `expires_at` beyond `created + 365 days` gives the generic error (build it with the test-only constructor + re-seal).
### LF5 — last session removal deletes the file (D62)
Type: auto
Run each of the four paths: forget via a clean restore, expiry on open, `delete_session`, and `purge`. Each leaves zero sessions.

Pass when, for each path:
- `vault.vc` no longer exists;
- `vault.vc.tmp` does not exist either;
- a new mask afterwards creates a new file that opens normally.
### LF6 — purge and status hold no secrets (D63)
Type: auto
With 3 sessions, `status()` reports `sessions == 3`, the correct `oldest_created` and the correct `next_expiry`. `purge()` removes everything and deletes the file. `assert_no_secret` passes on the JSON and Debug of `VaultStatus`, the purge result, the open result (`expired_removed`) and every report.
### LF7 — forget only after output is written (D60)
Type: auto
Inject an output write failure, either with a test-only write-failure hook in the `paths.rs` write helpers or by making the output dir read-only (Unix). Pass when restore returns an error, the session and all entries are still in the reopened vault, and nothing was forgotten.

---

### LF9 — failed persist leaves memory equal to disk (D72)
Type: auto
Make persist fail: modify `vault.vc` from a second handle, or hold the D28 tmp lock, after the outputs are written. Then run each of forget (clean restore), delete_session and purge. Pass when, after each, the in-memory vault lists exactly the sessions a fresh open of the file lists, and the error is returned.

## P4 — CLI (runs the real binary, `env!("CARGO_BIN_EXE_veilcode")`)
### C1 — end-to-end
Type: auto
`scan --json`, then `mask --passphrase-stdin --vault <tmp>`, then `restore` gives a byte-identical tree. All three exit 0.
### C2 — bad path
Type: auto
`mask /no/such --out <tmp>` exits 2, and stderr passes `assert_no_secret`.
### C3 — help
Type: auto
`--help` stdout contains `scan`, `mask`, `restore` and `session`.
### C4 — findings file deselect
Type: auto
Remove one finding from the JSON, then mask. That secret is present in the output and the others are absent.
### C5 — no secrets on any stream
Type: auto
For every invocation in C1, C2 and C4, stdout and stderr pass `assert_no_secret`.
### C6 — wrong passphrase
Type: auto
Restore with a different passphrase exits 2 with the generic message, and stderr passes `assert_no_secret`.
### C7 — scan exit code
Type: auto
Scanning a folder with findings and a folder without findings both exit 0.
### C8 — manual WordPress-style run
Type: manual
Documented in the PR: the folder layout, the commands and the report excerpts (previews only).
### C9 — CLI network audit
Type: command
`bash scripts/net-audit.sh` runs scan → mask → restore under strace with no `AF_INET`, `AF_INET6`, `AF_PACKET` or `AF_NETLINK` socket. It runs in Linux CI, and locally in WSL. Paste the output in the PR.
### LF8 — CLI lifecycle end-to-end (D60–D63)
Type: auto
Run through the binary with `--passphrase-stdin --vault <tmp>`:
1. `mask --ttl-days 7`, then `vault status`, which shows 1 session and an expiry about 7 days ahead.
2. `restore --keep`, after which the session is kept.
3. `restore` again, which prints "session forgotten". After it, `vault.vc` is gone because it was the last session.
4. A new `mask`, then `vault purge --yes`, after which the file is gone.
5. `vault purge` without `--yes` and with stdin not confirming, which aborts with exit 2 and changes nothing.

Every command exits 0 except step 5. stdout and stderr of every invocation pass `assert_no_secret`.

---

### PF1 — extra keys are detected (D76, D77)
Type: auto
With `extra_keys = ["customapi-pass"]`, each of these gives exactly one finding whose span is exactly `<v>`, `rule_id` is `custom-key` (D5) or D2/D3 as applicable, and `key_name` is the original spelling:
- `.env`: `CUSTOMAPI_PASS=<v>`
- `config.yml`: `customapi-pass: <v>`
- `settings.json`: `"customapi_pass": "<v>"`
- `app.ini`: `CustomApi.Pass = <v>`
- `wp-config.php`: `define('CUSTOMAPI_PASS','<v>');`

Without the profile, the yml, json and ini lines give no finding.
### PF2 — D5 boundaries (D77)
Type: auto
- `my_customapi_pass_x: <v>`, `xcustomapi_pass: <v>` and `customapi_pass_x: <v>` give no finding (no boundary before or after the key), while `my.customapi-pass: <v>` and `(customapi-pass: <v>` give one finding each (`.` and `(` are boundaries). Removing either boundary check must make this test fail.
- `customapi-pass: ${ENV}` and `customapi-pass: $(cmd)` give none.
- `customapi-pass:` with an empty value gives none.
- `customapi-pass: <v>, other` and `customapi-pass: <v>;` give spans of exactly `<v>`.
- `customapi-pass = "<v> with space"` gives the full quoted content.
- A byte `0xE9` inside the value is included (D41).
### PF3 — ignored keys are reported, not auto-masked (D78)
Type: auto
With `extra_keys = ["DB_NAME"]` (so it is detected at all, D83) and `ignored_keys = ["DB_NAME"]`, a `.env` with `DB_NAME=<a>` and `DB_PASSWORD=<b>` gives 2 findings. The DB_NAME one has `ignored == Some(ProfileKey)`. Pass when:
- the default selection masks only `<b>`;
- the output still contains `<a>`;
- MaskReport `ignored_by_profile == 1`;
- explicitly selecting the ignored id masks `<a>` too (override).
### PF3b — ignore still applies when a gitleaks rule also matches (D86)
Type: auto
With `extra_keys` and `ignored_keys` both `["customapi-pass"]`, scan `config.yml` containing `customapi-pass: <28 random alnum>`, a value that also matches `generic-api-key`. Pass when there is exactly one finding, its `key_name` is `customapi-pass`, `ignored == Some(ProfileKey)`, and the default mask leaves the value unmasked. Without `ignored_keys`, the same finding is masked and still shows the key name.
### PF4 — per-file ignore entries (D74, D78)
Type: auto
`[[ignored]] {rel_path = "a/.env", key_name = "API_KEY"}` ignores API_KEY only in `a/.env`; the same key in `b/.env` is still selected. An entry with `rule_id` (a D1 rule) ignores that rule only in that file.
### PF5 — profile edits round trip and hold no secrets (D79, D80)
Type: auto
- `add_extra_key`, `ignore_key`, `ignore_finding(ThisFile)` and `ignore_finding(Everywhere)`, then `save`, `load` and re-scan reflect each change; their `remove`/`unignore` counterparts restore the original scan result.
- Adding a key that is already present, or removing one that is absent, is a no-op reported as such.
- After ignoring findings, `assert_no_secret` passes on the saved profile bytes.
### PF6 — profile safety (D75, D79)
Type: auto
- Each of these is a clear error (no panic, nothing ignored): a profile over 1 MiB, a symlinked profile (Unix), an unknown TOML field, `version = 2`, a key name of 65 chars or with `/`, an `[[ignored]]` entry with both or neither of key_name/rule_id, and a `rel_path` of `../x`.
- A missing default profile acts as an empty profile.
- A `profile.toml` or `.veilcode.toml` placed in the input folder root has no effect on the scan.
### PF8 — D5 stays linear on hostile lines (D87)
Type: auto
With `extra_keys = ["dbname"]`, scan one 5 MiB line of `dbname=` repeated and one of `dbname="dbname=` repeated, each in under 30 s in the debug test build. Assert the elapsed time; the finding count must be consistent and no larger than the number of non-overlapping values.
### PF7 — CLI profile commands end-to-end (D80)
Type: auto
Through the binary with `--profile <tmp>`:
- `profile add-key customapi-pass`, then `scan` finds the D5 secret.
- `profile add-key DB_NAME` and `profile ignore-key DB_NAME` (D83), then `scan` shows it as ignored and `mask` prints "1 findings ignored by profile (not masked)".
- `profile ignore --path a/.env --key API_KEY` and `unignore --path a/.env --key API_KEY` work, and `profile list` shows the state.
- `remove-key` and `unignore-key` restore the original state.
- A bad key name exits 2.

Every stdout and stderr passes `assert_no_secret`.

## P5 — CLI release
### REL1 — release artifacts
Type: manual
A test tag on a fork produces 2 binaries (linux-x86_64, windows-x86_64) plus SHA256SUMS plus an SBOM. `sha256sum -c SHA256SUMS` passes.
### REL2 — provenance
Type: manual
`gh attestation verify <file> --repo cybermavericx/Veilcode` succeeds for each binary. Check the exact flags with `gh attestation verify --help` first.
### REL3 — offline run
Type: manual
`unshare -rn veilcode scan <dir>` succeeds on Linux, following VERIFY_OFFLINE.md.

---

## P6 — Desktop app (eframe/egui)
Test the app-state layer (`AppState`, its actions and view models) without a window. Rendering is checked only by G5 and G6.
### G1 — lock state
Type: auto
Each action (scan, mask, restore, session list, mask_text) called while locked returns `Locked`. After unlock they succeed, and after `lock()` they fail again.
### G2 — view models hold previews only
Type: auto
After scan, mask and restore actions, `format!("{:?}", view_model)` for every non-Text-Mode view model passes `assert_no_secret`.
### G3 — auto-lock
Type: auto
With an injected clock, advancing it 10 min + 1 s with no input locks the vault and drops the key, and a zeroize call counter on the key wrapper is incremented. An input event at 9 min resets the timer.
### G4 — forbidden features absent
Type: auto
A test parses `cargo metadata --format-version 1 --filter-platform <target>` (via `std::process::Command` in `crates/veilcode-gui/tests/`) for the Linux and Windows targets. It asserts that the enabled features of `eframe` and `egui-winit` include neither `links` nor `persistence`, that no package named `webbrowser`, `open`, `opener` or any HTTP/TLS crate is in the resolved graph, and (D104, D108) that `zbus`, `atspi`, `accesskit_unix`, `async-io` and `async-process` are absent on Linux and `accesskit_windows` is present on Windows. The per-target check uses `cargo tree --target <t>`, because `cargo metadata` merges features across targets (cargo#7754).
### G5 — manual QA
Type: manual
Checklist in the PR: each screen, light and dark, on Windows 11 (local and over RDP) and on Ubuntu (X11 and Wayland). Keyboard-only navigation works. **Sessions screen (D63):** age and expiry columns are shown; "Purge all" asks for confirmation, and cancelling changes nothing. The restore screen has a "keep session" checkbox (default off) and shows "session forgotten" or the kept reason. The mask screen has "separate vault for this project" (D64) and a TTL selector (1–365, default 30).
### G7 — review dialog state (D80)
Type: auto
App-state tests, with no window:
- After scan, the review model lists every finding with key or rule, file, line and preview only (`assert_no_secret` on Debug); ignored findings sit in the ignored section, unticked.
- Unticking removes the id from the selection.
- "Remember: this file" and "Remember: everywhere" call the Profile API with the right scope. "Everywhere" requires the confirm flag.
- "Unignore" re-ticks the finding.
- "Add key name" adds to `extra_keys` and triggers a re-scan.
- Mask is impossible from the state machine until the review step has been confirmed, and the confirm label equals "Mask N secrets" with N the selected count.
### G8 — manual review dialog QA (D80)
Type: manual
In the PR, check:
- grouping by key and rule;
- untick plus remember (this file, and everywhere with confirmation);
- unignore from the collapsed ignored section;
- adding `customapi-pass` and seeing it detected after the re-scan;
- that the counts match the MaskReport.

Do this on Windows and Linux.
### G9 — Linux display guard (D105)
Type: auto
The display-validation function accepts unset, and `:0`, `:1.0`, `unix:0` only together with a passing preflight (D109; see G9b). It rejects path forms such as `/tmp/.X11-unix/X0`, and also `localhost:10`, `host:0`, `10.0.0.1:0`, `tcp/host:0`, `[::1]:0` and an empty string, with an error that names `DISPLAY` but does not contain the value.
### G9b — X11 preflight (D109, Linux)
Type: auto
The guard accepts `:N` only when the preflight connect to `/tmp/.X11-unix/XN` succeeds, or (Linux, D110) the connect to the abstract socket of the same name succeeds. Use a test listener bound with `std::os::unix::net::UnixListener` in a temp dir, through an injectable socket-path base, so the test never touches the real `/tmp/.X11-unix`.

Pass when:
- `:N` with no socket present is refused;
- `:N` with a socket file that refuses connections is refused;
- `:N` with a listening socket is accepted;
- `unix:N` follows the same rules;
- path forms and host forms are refused;
- the refusal message contains neither the value nor a suggested value.

A strace run of the release binary with `DISPLAY=:N` and no server makes no `AF_INET` or `AF_INET6` socket call.
### G10 — job result after lock is discarded (D106)
Type: auto
With a deferred runner: start a scan, a mask and a `restore_text`, lock, then deliver each result. Pass when no vault, view model or text comes back, every lock path ran the wipe (`key_wipes` and form wipes incremented), and the stale restored text was wiped.

### G6 — GUI network audit
Type: command
`bash scripts/net-audit.sh` in the Linux CI job runs `veilcode-gui` under `xvfb-run` for 10 s with no `AF_INET`, `AF_INET6`, `AF_PACKET` or `AF_NETLINK` socket. Paste the output in the PR.

## P7 — App release
### PKG1 — .deb contents and metadata (D114)
Type: command
In the packaging job, `dpkg-deb -I` shows Package `veilcode`, Architecture `amd64`, the D114 Maintainer and a Depends line with libc6 plus the GUI runtime libraries. `dpkg-deb -c` lists exactly `usr/bin/veilcode`, `usr/bin/veilcode-gui`, `usr/share/applications/veilcode.desktop` and the licence files. The job fails otherwise.
### PKG2 — .msi contents, per-user scope (D113)
Type: command
On the windows runner, an administrative extract of the `.msi` (`msiexec /a <msi> /qn TARGETDIR=<tmp>`, which does not install) contains `veilcode.exe` and `veilcode-gui.exe`, byte-identical to the build outputs, plus the licence files. The `.wxs` declares `InstallScope="perUser"` and the fixed UpgradeCode. The job fails otherwise.
### PKG3 — every shipped file is hashed and attested (D115)
Type: command
In the release job, the exact-file-set check lists every asset, SHA256SUMS covers all of them, and the attest `subject-path` matches all of them. Confirmed after the first tag run with `gh attestation verify` on each asset.
### REL4 — installers run offline
Type: manual
On Windows and on Linux, install from the release artifacts with the network blocked per VERIFY_OFFLINE.md, then mask and restore a sample folder through the GUI.
