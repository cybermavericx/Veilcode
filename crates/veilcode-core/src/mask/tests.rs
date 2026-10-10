//! P3 mask tests (TEST_CASES.md M1–M10).

use super::*;
use crate::error::CoreError;
use crate::test_support::*;
use std::path::PathBuf;

struct Dirs {
    tmp: tempfile::TempDir,
    input: PathBuf,
    out: PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (input, out) = (tmp.path().join("in"), tmp.path().join("out"));
    std::fs::create_dir(&input).expect("mkdir");
    Dirs { tmp, input, out }
}

fn run(d: &Dirs, report: &ScanReport, sel: &Selection, opts: &MaskOptions) -> Result<MaskReport> {
    let mut vault = test_vault(d.tmp.path());
    mask(report, sel, &d.input, &d.out, &mut vault, opts)
}

fn include_unscanned() -> MaskOptions {
    MaskOptions {
        include_unscanned: true,
        ..MaskOptions::default()
    }
}

#[test]
fn m1_masking_leaves_input_untouched() {
    let d = dirs();
    let s = sample_tree(&d.input);
    let before = tree_hashes(&d.input);
    let mut vault = test_vault(d.tmp.path());
    let report = mask_all(&d.input, &d.out, &mut vault);
    assert_eq!(tree_hashes(&d.input), before);
    assert_eq!((report.files_written, report.secrets_masked), (3, 3));
    let tok = token_for(&vault, s.pw.as_bytes());
    let env = format!("APP=demo\nDB_PASSWORD={}\n", tok.as_str());
    assert_eq!(read(&d.out, ".env"), env.as_bytes());
    let tok = token_for(&vault, s.key.as_bytes());
    let php = format!("<?php\ndefine('AUTH_KEY', '{}');\n", tok.as_str());
    assert_eq!(read(&d.out, "wp-config.php"), php.as_bytes());
    let tok = token_for(&vault, s.pat.as_bytes());
    let js = format!("let a = 1;\nconst t = \"{}\";\nlet z = 2;\n", tok.as_str());
    assert_eq!(read(&d.out, "src/app.js"), js.as_bytes());
    assert_no_secret(&all_bytes(&d.out), &s.all());
}

#[test]
fn m2_output_inside_input() {
    let d = dirs();
    let s = sample_tree(&d.input);
    let before = tree_hashes(&d.input);
    let report = scan_dir(&d.input);
    let mut vault = test_vault(d.tmp.path());
    let (sel, opts) = (Selection::All, MaskOptions::default());
    let nested = d.input.join("sub").join("out");
    for out in [nested, d.input.clone(), d.input.join("src")] {
        let err = mask(&report, &sel, &d.input, &out, &mut vault, &opts).expect_err("inside");
        assert!(matches!(err, CoreError::OutputInsideInput), "{err}");
        assert_no_secret(format!("{err} {err:?}").as_bytes(), &s.all());
    }
    assert!(!d.input.join("sub").exists());
    assert_eq!(tree_hashes(&d.input), before);
    assert!(vault.sessions().is_empty());
}

#[test]
fn m3_non_empty_output() {
    let d = dirs();
    sample_tree(&d.input);
    let report = scan_dir(&d.input);
    write_tree(&d.out, &[("keep.txt", b"keep")]);
    let err = run(&d, &report, &Selection::All, &MaskOptions::default()).expect_err("non-empty");
    assert!(matches!(err, CoreError::OutputExists { .. }), "{err}");
    let after = tree_hashes(&d.out);
    assert_eq!(after.keys().collect::<Vec<_>>(), vec!["keep.txt"]);
    assert_eq!(read(&d.out, "keep.txt"), b"keep");
    let file = d.tmp.path().join("file-out");
    std::fs::write(&file, b"x").expect("write");
    let mut vault = test_vault(d.tmp.path());
    let opts = MaskOptions::default();
    let err =
        mask(&report, &Selection::All, &d.input, &file, &mut vault, &opts).expect_err("not a dir");
    assert!(matches!(err, CoreError::OutputExists { .. }), "{err}");
    assert_eq!(std::fs::read(&file).expect("read"), b"x");
}

fn assert_rescan(d: &Dirs, report: &ScanReport) {
    let err = run(d, report, &Selection::All, &MaskOptions::default()).expect_err("rescan");
    assert!(matches!(err, CoreError::Rescan), "{err}");
    assert_eq!(err.to_string(), "file changed since scan — rescan");
    assert!(!d.out.exists(), "output created before the rescan check");
}

#[test]
fn m4_file_changed_after_scan() {
    let d = dirs();
    let s = sample_tree(&d.input);
    let report = scan_dir(&d.input);
    let env = format!("APP=demo\nDB_PASSWORD={}\nX=1\n", s.pw);
    std::fs::write(d.input.join(".env"), env).expect("edit");
    assert_rescan(&d, &report);
}

#[test]
fn m4b_clean_file_changed_after_scan() {
    let d = dirs();
    sample_tree(&d.input);
    write_tree(&d.input, &[("README.md", b"hello\n")]);
    let report = scan_dir(&d.input);
    let pat = fake_github_pat();
    std::fs::write(d.input.join("README.md"), format!("hello {pat}\n")).expect("edit");
    assert_rescan(&d, &report);
    // A new text file that was not scanned is also a rescan.
    let d = dirs();
    sample_tree(&d.input);
    let report = scan_dir(&d.input);
    write_tree(&d.input, &[("new.txt", format!("t {pat}\n").as_bytes())]);
    assert_rescan(&d, &report);
}

#[test]
fn m5_deselected_finding() {
    let d = dirs();
    let s = sample_tree(&d.input);
    let report = scan_dir(&d.input);
    assert_eq!(report.findings.len(), 3);
    let ids = report
        .findings
        .iter()
        .filter(|f| f.rel_path != "src/app.js")
        .map(|f| f.id.clone())
        .collect();
    let masked = run(&d, &report, &Selection::Ids(ids), &MaskOptions::default()).expect("mask");
    assert_eq!(masked.secrets_masked, 2);
    let out = all_bytes(&d.out);
    let pat = s.pat.as_bytes();
    assert!(
        out.windows(pat.len()).any(|w| w == pat),
        "deselected PAT missing"
    );
    assert_no_secret(&out, &[&s.pw, &s.key]);
    let unknown = Selection::Ids(BTreeSet::from(["0123456789abcdef".to_string()]));
    let d2 = dirs();
    sample_tree(&d2.input);
    let report = scan_dir(&d2.input);
    let err = run(&d2, &report, &unknown, &MaskOptions::default()).expect_err("unknown id");
    assert!(matches!(err, CoreError::UnknownFinding { ref id } if id == "0123456789abcdef"));
    assert!(!d2.out.exists());
}

fn unscanned_tree(d: &Dirs) -> (Vec<u8>, Vec<u8>) {
    let bin = b"\x7fELF\0\x01\x02 binary".to_vec();
    let big = vec![b'a'; 5 * 1024 * 1024 + 1];
    write_tree(
        &d.input,
        &[("bin.dat", &bin), ("big.txt", &big), ("a.txt", b"x\n")],
    );
    (bin, big)
}

#[test]
fn m6_unscanned_files() {
    let d = dirs();
    unscanned_tree(&d);
    let report = scan_dir(&d.input);
    let r = run(&d, &report, &Selection::All, &MaskOptions::default()).expect("mask");
    assert_eq!(
        tree_hashes(&d.out).keys().collect::<Vec<_>>(),
        vec!["a.txt"]
    );
    assert_eq!(
        r.not_copied,
        vec!["big.txt".to_string(), "bin.dat".to_string()]
    );
    let d = dirs();
    let (bin, big) = unscanned_tree(&d);
    let report = scan_dir(&d.input);
    let r = run(&d, &report, &Selection::All, &include_unscanned()).expect("mask");
    assert_eq!(read(&d.out, "bin.dat"), bin);
    assert!(read(&d.out, "big.txt") == big, "oversized copy differs");
    assert_eq!(read(&d.out, "a.txt"), b"x\n");
    assert_eq!(r.not_copied, Vec::<String>::new());
    assert_eq!(r.files_written, 3);
}

#[cfg(unix)]
#[test]
fn m6b_symlinks_never_copied() {
    let d = dirs();
    write_tree(&d.input, &[("a.txt", b"x\n")]);
    std::os::unix::fs::symlink(d.input.join("a.txt"), d.input.join("link.txt")).expect("ln");
    std::os::unix::fs::symlink(d.tmp.path(), d.input.join("linkdir")).expect("ln");
    let report = scan_dir(&d.input);
    let r = run(&d, &report, &Selection::All, &include_unscanned()).expect("mask");
    assert_eq!(
        tree_hashes(&d.out).keys().collect::<Vec<_>>(),
        vec!["a.txt"]
    );
    assert!(std::fs::symlink_metadata(d.out.join("link.txt")).is_err());
    assert!(std::fs::symlink_metadata(d.out.join("linkdir")).is_err());
    let want = vec!["link.txt".to_string(), "linkdir".to_string()];
    assert_eq!(r.not_copied, want);
}

#[test]
fn m7_byte_preservation() {
    let d = dirs();
    let pw = fake_password();
    let head = b"# caf\xe9 \xff\r\nDB_PASSWORD=".to_vec();
    let tail = b"\r\nOTHER=\xe9t\xe9\r\n\r\n".to_vec();
    let body = [head.as_slice(), pw.as_bytes(), &tail].concat();
    write_tree(&d.input, &[(".env", &body)]);
    let mut vault = test_vault(d.tmp.path());
    mask_all(&d.input, &d.out, &mut vault);
    let tok = token_for(&vault, pw.as_bytes());
    let want = [head.as_slice(), tok.as_str().as_bytes(), &tail].concat();
    assert!(
        read(&d.out, ".env") == want,
        "masked bytes differ outside the span"
    );
}

fn sorted_values(v: &Vault, tokens: &[crate::Token]) -> Vec<Vec<u8>> {
    let mut values: Vec<Vec<u8>> = tokens
        .iter()
        .map(|t| v.value(t).expect("entry").expose().to_vec())
        .collect();
    values.sort();
    values
}

#[test]
fn m8_vault_state_after_mask() {
    let d = dirs();
    let s = sample_tree(&d.input);
    let again = format!("DB_PASSWORD={}\n", s.pw);
    write_tree(&d.input, &[("sub/.env", again.as_bytes())]);
    let mut vault = test_vault(d.tmp.path());
    let r = mask_all(&d.input, &d.out, &mut vault);
    assert_eq!((r.secrets_masked, r.tokens), (4, 3));
    let reopened = Vault::open(&d.tmp.path().join("vault.vc"), &test_pass()).expect("open");
    let mut want: Vec<Vec<u8>> = s.all().iter().map(|x| x.as_bytes().to_vec()).collect();
    want.sort();
    for v in [&vault, &reopened] {
        assert_eq!(v.sessions().len(), 1);
        let session = &v.sessions()[0];
        assert_eq!(session.id, r.session_id);
        assert_eq!(session.source_label, "in");
        assert_eq!(session.tokens.len(), 3);
        assert!(
            sorted_values(v, &session.tokens) == want,
            "vault values differ"
        );
    }
    // D53: a session is recorded even with 0 tokens.
    let d = dirs();
    write_tree(&d.input, &[("a.txt", b"nothing here\n")]);
    let mut vault = test_vault(d.tmp.path());
    let r = mask_all(&d.input, &d.out, &mut vault);
    assert_eq!((r.tokens, vault.sessions().len()), (0, 1));
    assert_eq!(vault.sessions()[0].tokens.len(), 0);
}

#[test]
fn m9_non_utf8_secret_masked_and_restored() {
    let d = dirs();
    let secret = [b"ab".as_slice(), b"\xff\xfe", random_alnum(12).as_bytes()].concat();
    let body = [b"DB_PASSWORD=".as_slice(), &secret, b"\n"].concat();
    write_tree(&d.input, &[(".env", &body)]);
    let mut vault = test_vault(d.tmp.path());
    let r = mask_all(&d.input, &d.out, &mut vault);
    assert_eq!(r.secrets_masked, 1);
    let tok = token_for(&vault, &secret);
    let value_hex = crate::hex::encode(vault.value(&tok).expect("entry").expose());
    assert!(
        value_hex == crate::hex::encode(&secret),
        "value_hex differs"
    );
    assert_eq!(&value_hex[4..8], "fffe");
    let restored = d.tmp.path().join("restored");
    crate::restore(&d.out, &restored, &mut vault, None, false).expect("restore");
    assert!(read(&restored, ".env") == body, "restored bytes differ");
}

#[test]
fn m10_malicious_findings_file_paths() {
    let bad = ["../x", "a/../../x", "/etc/x", "C:\\x", "\\\\srv\\x", "a//b"];
    for rel in bad {
        assert!(crate::paths::RelPath::parse(rel).is_err(), "{rel} accepted");
        for in_findings in [true, false] {
            let d = dirs();
            sample_tree(&d.input);
            let mut report = scan_dir(&d.input);
            if in_findings {
                report.findings[0].rel_path = rel.to_string();
            } else {
                report.scanned_files[0].rel_path = rel.to_string();
            }
            let mut vault = test_vault(d.tmp.path());
            let opts = MaskOptions::default();
            let err = mask(
                &report,
                &Selection::All,
                &d.input,
                &d.out,
                &mut vault,
                &opts,
            )
            .expect_err("bad path");
            assert!(matches!(err, CoreError::BadRelPath { .. }), "{rel}: {err}");
            assert!(!d.out.exists(), "{rel}: output created");
            assert!(vault.sessions().is_empty());
        }
    }
}

#[test]
fn m11_output_dir_must_be_new_and_private() {
    let d = dirs();
    let s = sample_tree(&d.input);
    let report = scan_dir(&d.input);
    std::fs::create_dir(&d.out).expect("mkdir");
    let err = run(&d, &report, &Selection::All, &MaskOptions::default()).expect_err("exists");
    assert!(matches!(err, CoreError::OutputExists { .. }), "{err}");
    assert!(dir_is_empty(&d.out));
    let mut vault = test_vault(d.tmp.path());
    let masked = d.tmp.path().join("masked");
    mask_all(&d.input, &masked, &mut vault);
    let err = crate::restore(&masked, &d.out, &mut vault, None, false).expect_err("exists");
    assert!(matches!(err, CoreError::OutputExists { .. }), "{err}");
    assert!(dir_is_empty(&d.out));
    let nested = d.tmp.path().join("a").join("b").join("restored");
    crate::restore(&masked, &nested, &mut vault, None, false).expect("restore");
    assert!(read(&nested, ".env") == read(&d.input, ".env"));
    assert_no_secret(format!("{err:?}").as_bytes(), &s.all());
}

#[cfg(unix)]
#[test]
fn m11_unix_modes_and_unsafe_parent() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o7777;
    let chmod = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).expect("chmod");
    };
    let d = dirs();
    write_tree(&d.input, &[("a.txt", b"x\n")]);
    let report = scan_dir(&d.input);
    let r = run(&d, &report, &Selection::All, &MaskOptions::default()).expect("mask");
    assert_eq!(r.files_written, 1);
    assert_eq!(mode(&d.out), 0o700);
    let open = d.tmp.path().join("open");
    std::fs::create_dir(&open).expect("mkdir");
    chmod(&open, 0o777);
    let vault_dir = tempfile::tempdir().expect("tempdir");
    let mut vault = test_vault(vault_dir.path());
    let out = open.join("out");
    let opts = MaskOptions::default();
    let err =
        mask(&report, &Selection::All, &d.input, &out, &mut vault, &opts).expect_err("unsafe");
    assert!(matches!(err, CoreError::UnsafeOutputParent { .. }), "{err}");
    assert!(!out.exists());
    chmod(&open, 0o1777);
    mask(&report, &Selection::All, &d.input, &out, &mut vault, &opts).expect("sticky ok");
    assert_eq!(mode(&out), 0o700);
}
