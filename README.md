# Veilcode

Developers paste server code into AI assistants, often including `.env` files
and config secrets. Veilcode masks those secrets in a copy of a code folder with
unique placeholders, keeps the real values in a local encrypted vault, and
restores them after the AI work is done, even if the AI moved, renamed or edited
the code. It is a native desktop app and a CLI.

## Status

**Pre-alpha — not usable yet.** There is no release. Do not rely on it to
protect real secrets.

## Offline

**Offline by construction.** Veilcode's own code contains no network calls and
does not launch other programs. HTTP, TLS, DNS, WebSocket and browser-launch
crates are banned from the dependency graph. On Linux, CI proves at runtime that
neither the CLI nor the GUI opens an internet socket (§10).

(§10 refers to `docs/SPEC.md`.)

## Supported platforms

- Windows
- Linux

## Detection is best-effort

Veilcode cannot recognise every secret. Anything no detector matches stays in
the masked output. Review the report before sharing the masked folder, and use
`.veilcodeignore` to exclude files.

## Secret retention

The vault holds the real secrets of every project that has not finished its
round trip, so Veilcode keeps it as small as possible:

- After a clean restore, the project's session and its secrets are forgotten
  (use `--keep` to retain them).
- Sessions expire after 30 days by default (`--ttl-days`, 1–365).
- An empty vault file is deleted.
- A separate vault per project (`--vault <project>.vc`) is recommended.

Limits you should know about:

- Deleting rewrites or removes the encrypted file, but SSD wear-levelling,
  backups or cloud sync of the Veilcode data folder may keep older encrypted
  copies. Exclude that folder from sync and backup.
- Your passphrase is the last line of defence for any copy that survives.
- Malware running while the vault is unlocked defeats all of this.

## Prior art

Other projects already work on masking sensitive data before it reaches an
LLM. Veilcode builds on the same idea:

- [opsmask](https://github.com/ching-kuo/opsmask): a Go CLI that pseudonymizes
  secrets and identifiers in logs and supports a round trip back to the
  originals.
- [CodeMask OSS](https://github.com/codemasklab/codemask-oss): an open-source
  code and text masker for LLM safety, with Python and Text modes.
- [Carnaval](https://github.com/carnaval-ai/carnaval): reversible PII
  anonymization for LLM pipelines.
- [ragkit-redactor](https://pypi.org/project/ragkit-redactor/): reversible
  masking of PII and secrets in text.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
