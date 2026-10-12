//! P3 restore tests (TEST_CASES.md R1–R11, PROP1).

use super::*;
use crate::mask::{MaskOptions, Selection, mask};
use crate::report::MaskReport;
use crate::secret::SecretBytes;
use crate::test_support::*;
use crate::token::Token;
use std::path::PathBuf;

struct Run {
    tmp: tempfile::TempDir,
    input: PathBuf,
    masked: PathBuf,
    restored: PathBuf,
    vault: Vault,
}

/// A fresh input dir, vault and output paths.
fn setup() -> Run {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    std::fs::create_dir(&input).expect("mkdir");
    let vault = test_vault(tmp.path());
    Run {
        masked: tmp.path().join("masked"),
        restored: tmp.path().join("restored"),
        input,
        vault,
        tmp,
    }
}

impl Run {
    fn mask(&mut self) -> MaskReport {
        mask_all(&self.input, &self.masked, &mut self.vault)
    }

    fn restore(&mut self) -> RestoreReport {
        restore(
            &self.masked,
            &self.restored,
            &mut self.vault,
            None,
            false,
            &crate::Profile::default(),
        )
        .expect("restore")
    }

    fn tok(&self, secret: &str) -> String {
        token_for(&self.vault, secret.as_bytes())
            .as_str()
            .to_string()
    }
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("json")
}

#[test]
fn r1_round_trip() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    write_tree(
        &r.input,
        &[(".git/config", b"[core]\n"), ("bin.dat", b"a\0b")],
    );
    std::fs::create_dir(r.input.join("empty")).expect("mkdir");
    let m = r.mask();
    assert_eq!(
        m.not_copied,
        vec![".git".to_string(), "bin.dat".to_string()]
    );
    let rep = r.restore();
    let mut want = tree_hashes(&r.input);
    want.remove(".git/config");
    want.remove("bin.dat");
    assert_eq!(tree_hashes(&r.restored), want);
    assert!(r.restored.join("empty").is_dir());
    assert_eq!((rep.tokens_replaced, rep.files_written), (3, 3));
    assert_eq!(rep.session_id, Some(m.session_id));
    assert_eq!(rep.missing, Vec::<Token>::new());
    assert_no_secret(&json(&rep), &s.all());
}

fn reversed_lines(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).expect("utf8");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.reverse();
    let mut out = lines.join("\n");
    out.push('\n');
    out.into_bytes()
}

#[test]
fn r2_survives_ai_edits() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    r.mask();
    let (pw_tok, pat_tok) = (r.tok(&s.pw), r.tok(&s.pat));
    let masked_js = read(&r.masked, "src/app.js");
    std::fs::remove_file(r.masked.join("src/app.js")).expect("rm");
    std::fs::write(r.masked.join("src/b.js"), reversed_lines(&masked_js)).expect("write");
    let mut php = read(&r.masked, "wp-config.php");
    php.extend_from_slice(format!("// copy: {pw_tok}\n").as_bytes());
    std::fs::write(r.masked.join("wp-config.php"), &php).expect("write");
    write_tree(
        &r.masked,
        &[("new.txt", format!("tok={pat_tok}\n").as_bytes())],
    );
    let rep = r.restore();
    let original_js = read(&r.input, "src/app.js");
    assert!(read(&r.restored, "src/b.js") == reversed_lines(&original_js));
    let mut want_php = read(&r.input, "wp-config.php");
    want_php.extend_from_slice(format!("// copy: {}\n", s.pw).as_bytes());
    assert!(read(&r.restored, "wp-config.php") == want_php);
    let want_new = format!("tok={}\n", s.pat);
    assert!(read(&r.restored, "new.txt") == want_new.as_bytes());
    assert!(read(&r.restored, ".env") == read(&r.input, ".env"));
    assert_eq!(rep.tokens_replaced, 5);
    assert_eq!((rep.unknown.len(), rep.missing.len()), (0, 0));
    assert_no_secret(&all_bytes(&r.masked), &s.all());
}

#[test]
fn r3_unknown_token() {
    let mut r = setup();
    sample_tree(&r.input);
    r.mask();
    let fake = "VEILCODE_FAKE_1a2b3c4d";
    write_tree(&r.masked, &[("ai.txt", format!("x={fake};\n").as_bytes())]);
    let rep = r.restore();
    assert_eq!(
        read(&r.restored, "ai.txt"),
        format!("x={fake};\n").as_bytes()
    );
    assert_eq!(rep.unknown, vec![fake.to_string()]);
}

#[test]
fn r4_missing_token() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    r.mask();
    let pat_tok = r.tok(&s.pat);
    std::fs::write(r.masked.join("src/app.js"), b"let a = 1;\n").expect("write");
    let rep = r.restore();
    assert_eq!(rep.missing, vec![token_for(&r.vault, s.pat.as_bytes())]);
    assert_eq!(rep.missing[0].as_str(), pat_tok);
    assert_eq!(rep.tokens_replaced, 2);
}

#[test]
fn r5_new_secret_introduced_by_ai() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    r.mask();
    let pat = fake_github_pat();
    write_tree(
        &r.masked,
        &[("ai.js", format!("k = \"{pat}\";\n").as_bytes())],
    );
    let rep = r.restore();
    assert_eq!(rep.new_secrets.len(), 1);
    let f = &rep.new_secrets[0];
    assert_eq!(f.rel_path, "ai.js");
    assert_eq!(
        f.preview,
        SecretBytes::new(pat.as_bytes().to_vec()).preview()
    );
    assert_no_secret(&json(&rep), &[pat.as_str(), &s.pw, &s.key, &s.pat]);
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).expect("canonicalize")
}

#[test]
fn r6_write_containment() {
    for bad in [
        "..",
        "../x",
        "a/..",
        "/abs",
        "\\abs",
        "C:x",
        "C:\\x",
        "\\\\srv\\x",
    ] {
        assert!(crate::paths::RelPath::parse(bad).is_err(), "{bad} accepted");
    }
    let mut r = setup();
    sample_tree(&r.input);
    write_tree(&r.input, &[("deep/a/b/c.txt", b"c\n")]);
    crate::paths::take_write_log();
    r.mask();
    let masked_writes = crate::paths::take_write_log();
    r.restore();
    let restored_writes = crate::paths::take_write_log();
    assert_eq!((masked_writes.len(), restored_writes.len()), (8, 8));
    for (writes, root) in [(masked_writes, &r.masked), (restored_writes, &r.restored)] {
        let root = canonical(root);
        for w in writes {
            assert!(canonical(&w).starts_with(&root), "{} escapes", w.display());
        }
    }
}

#[test]
fn r7_reports_hold_no_secrets() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    let m = r.mask();
    let pat = fake_github_pat();
    write_tree(&r.masked, &[("ai.js", format!("k = {pat}\n").as_bytes())]);
    let rep = r.restore();
    let secrets = [pat.as_str(), &s.pw, &s.key, &s.pat];
    assert_no_secret(&json(&m), &secrets);
    assert_no_secret(&json(&rep), &secrets);
    assert_no_secret(format!("{m:?}{rep:?}").as_bytes(), &secrets);
}

#[test]
fn r8_tokens_not_redetected() {
    let mut r = setup();
    let (pw, url_pw) = (fake_password(), random_alnum(20));
    let url = format!("db: postgres://u:{url_pw}@h/db\n");
    write_tree(
        &r.input,
        &[
            (".env", format!("DB_PASSWORD={pw}\n").as_bytes()),
            ("db.txt", url.as_bytes()),
        ],
    );
    assert_eq!(r.mask().secrets_masked, 2);
    let masked_url = format!("db: postgres://u:{}@h/db\n", r.tok(&url_pw));
    assert_eq!(read(&r.masked, "db.txt"), masked_url.as_bytes());
    let rep = r.restore();
    assert_eq!(rep.new_secrets, vec![]);
    assert_eq!(rep.tokens_replaced, 2);
    assert!(read(&r.restored, "db.txt") == url.as_bytes());
}

#[test]
fn r9_token_after_veilcode_prefix() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    r.mask();
    let tok = r.tok(&s.pat);
    let body = format!("VEILCODE_{tok}\nVEILCODE_X_{tok}|{tok}VEILCODE_\n");
    write_tree(&r.masked, &[("ai.txt", body.as_bytes())]);
    let rep = r.restore();
    let p = &s.pat;
    let want = format!("VEILCODE_{p}\nVEILCODE_X_{p}|{p}VEILCODE_\n");
    assert!(
        read(&r.restored, "ai.txt") == want.as_bytes(),
        "prefix handling"
    );
    assert_eq!(rep.unknown, Vec::<String>::new());
    assert_eq!(rep.tokens_replaced, 6);
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn r10_permissions_kept_restored_secrets_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mut r = setup();
    let pat = fake_github_pat();
    let script = format!("#!/bin/sh\nTOKEN=\"{pat}\"\n");
    write_tree(
        &r.input,
        &[("run.sh", script.as_bytes()), ("plain.txt", b"hi\n")],
    );
    let set = |rel: &str, m: u32| {
        let perm = std::fs::Permissions::from_mode(m);
        std::fs::set_permissions(r.input.join(rel), perm).expect("chmod");
    };
    set("run.sh", 0o755);
    set("plain.txt", 0o640);
    assert_eq!(r.mask().secrets_masked, 1);
    assert_eq!(mode(&r.masked.join("run.sh")), 0o755);
    assert_eq!(mode(&r.masked.join("plain.txt")), 0o640);
    r.restore();
    assert_eq!(mode(&r.restored.join("run.sh")), 0o700);
    assert_eq!(mode(&r.restored.join("plain.txt")), 0o640);
    assert!(read(&r.restored, "run.sh") == script.as_bytes());
}

#[test]
fn r11_restore_output_never_overwrites() {
    let mut r = setup();
    sample_tree(&r.input);
    r.mask();
    write_tree(&r.restored, &[(".env", b"old")]);
    let err = restore(
        &r.masked,
        &r.restored,
        &mut r.vault,
        None,
        false,
        &crate::Profile::default(),
    )
    .expect_err("non-empty");
    assert!(
        matches!(err, crate::CoreError::OutputExists { .. }),
        "{err}"
    );
    assert_eq!(read(&r.restored, ".env"), b"old");
    let _ = &r.tmp;
}

#[test]
fn restore_unknown_session_is_error() {
    let mut r = setup();
    sample_tree(&r.input);
    r.mask();
    let id = crate::vault::SessionId::try_from("0000000000000000".to_string()).expect("id");
    let err = restore(
        &r.masked,
        &r.restored,
        &mut r.vault,
        Some(&id),
        false,
        &crate::Profile::default(),
    )
    .expect_err("unknown");
    assert!(
        matches!(err, crate::CoreError::UnknownSession { .. }),
        "{err}"
    );
    assert!(!r.restored.exists());
}

mod property {
    use super::*;
    use proptest::prelude::*;

    /// One generated file: is it a `.env`, filler before/after, which
    /// secrets to plant (bit 0 D2, bit 1 D4, bit 2 PAT), PAT glued to word chars.
    type FileSpec = (bool, Vec<u8>, u8, bool, Vec<u8>);

    fn filler() -> impl Strategy<Value = Vec<u8>> {
        let byte = prop_oneof![
            6 => 0x20u8..0x7f,
            1 => Just(b'\r'),
            1 => Just(b'\n'),
            1 => Just(b'_'),
            1 => 0x80u8..=0xff,
        ];
        prop::collection::vec(byte, 0..120)
    }

    fn file_spec() -> impl Strategy<Value = FileSpec> {
        (any::<bool>(), filler(), 0u8..8, any::<bool>(), filler())
    }

    /// Builds the file bytes; secrets are generated here, at runtime, so
    /// proptest never prints them. Returns the D2/D4 secrets that must be masked.
    fn build(spec: &FileSpec) -> (Vec<u8>, Vec<String>) {
        let (is_env, before, plant, glued, after) = spec;
        let mut body = before.clone();
        let mut must_mask = Vec::new();
        if *is_env && plant & 1 != 0 {
            let pw = fake_password();
            body.extend_from_slice(format!("\nDB_PASSWORD={pw}\r\n").as_bytes());
            must_mask.push(pw);
        }
        if plant & 2 != 0 {
            let pw = random_alnum(20);
            body.extend_from_slice(format!("\ndb postgres://u:{pw}@h/db\n").as_bytes());
            must_mask.push(pw);
        }
        if plant & 4 != 0 {
            let pat = fake_github_pat();
            let line = if *glued {
                format!("\nab{pat}cd\n")
            } else {
                format!("\nt {pat}\n")
            };
            body.extend_from_slice(line.as_bytes());
        }
        body.extend_from_slice(after);
        (body, must_mask)
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn prop1_restore_of_mask_is_identity(specs in prop::collection::vec(file_spec(), 1..=5)) {
            let mut r = setup();
            let mut must_mask = Vec::new();
            for (i, spec) in specs.iter().enumerate() {
                let (body, secrets) = build(spec);
                let name = if spec.0 { format!("d{}/f{i}.env", i % 2) } else { format!("f{i}.txt") };
                write_tree(&r.input, &[(name.as_str(), &body)]);
                must_mask.extend(secrets);
            }
            r.mask();
            let masked = all_bytes(&r.masked);
            let leaked = must_mask.iter().any(|s| masked.windows(s.len()).any(|w| w == s.as_bytes()));
            prop_assert!(!leaked, "a planted D2/D4 secret was not masked");
            r.restore();
            prop_assert_eq!(tree_hashes(&r.restored), tree_hashes(&r.input));
        }
    }
}

#[test]
fn r12_restore_needs_a_session() {
    let mut r = setup();
    write_tree(&r.input, &[("a.txt", b"x\n")]);
    let err = restore(
        &r.input,
        &r.restored,
        &mut r.vault,
        None,
        false,
        &crate::Profile::default(),
    )
    .expect_err("no session");
    assert!(matches!(err, crate::CoreError::NoSession), "{err}");
    assert_eq!(err.to_string(), "vault has no sessions to restore");
    assert!(!r.restored.exists());
    r.mask();
    let err = crate::restore_text("x", &mut r.vault, None, false).expect_err("no text session");
    assert!(matches!(err, crate::CoreError::NoSession), "{err}");
}

fn file_sha(p: &Path) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(std::fs::read(p).expect("read")).to_vec()
}

fn assert_cleaned(err: &crate::CoreError, out: &Path) {
    let crate::CoreError::PartialOutput { cleaned, .. } = err else {
        panic!("expected PartialOutput, got {err}");
    };
    assert!(*cleaned, "{err}");
    assert!(!out.exists(), "partial output left behind");
    assert!(
        err.to_string().ends_with("(partial output removed)"),
        "{err}"
    );
}

#[test]
fn r13_failed_run_removes_partial_output() {
    let mut r = setup();
    let s = sample_tree(&r.input);
    r.mask();
    let vault_file = r.tmp.path().join("vault.vc");
    let sha = file_sha(&vault_file);
    let again = r.tmp.path().join("masked2");
    crate::paths::fail_file_writes_after(Some(2));
    let report = scan_dir(&r.input);
    let opts = MaskOptions::default();
    let err = mask(
        &report,
        &Selection::All,
        &r.input,
        &again,
        &mut r.vault,
        &opts,
    );
    crate::paths::fail_file_writes_after(None);
    assert_cleaned(&err.expect_err("mask must fail"), &again);
    assert_eq!(file_sha(&vault_file), sha);
    crate::paths::fail_file_writes_after(Some(2));
    let err = restore(
        &r.masked,
        &r.restored,
        &mut r.vault,
        None,
        false,
        &crate::Profile::default(),
    );
    crate::paths::fail_file_writes_after(None);
    let err = err.expect_err("restore must fail");
    assert_cleaned(&err, &r.restored);
    assert_eq!(file_sha(&vault_file), sha);
    assert_no_secret(format!("{err} {err:?}").as_bytes(), &s.all());
}
