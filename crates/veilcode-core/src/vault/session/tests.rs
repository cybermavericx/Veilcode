//! Secret lifecycle tests (TEST_CASES.md SE2, LF1–LF7; D57r, D60–D63).

use super::*;
use crate::clock::ManualClock;
use crate::mask::{MaskOptions, Selection, mask};
use crate::report::{KeptReason, MaskReport, RestoreReport};
use crate::restore::restore;
use crate::scan::ScanOptions;
use crate::test_support::*;
use crate::token::Token;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A temp dir holding `vault.vc` plus numbered input/output folders.
struct Lab {
    tmp: tempfile::TempDir,
    next: usize,
}

impl Lab {
    fn new() -> Lab {
        Lab {
            tmp: tempfile::tempdir().expect("tempdir"),
            next: 0,
        }
    }

    fn vault_path(&self) -> PathBuf {
        self.tmp.path().join("vault.vc")
    }

    fn tmp_path(&self) -> PathBuf {
        self.tmp.path().join("vault.vc.tmp")
    }

    /// A fresh, not yet existing folder path.
    fn dir(&mut self, what: &str) -> PathBuf {
        self.next += 1;
        self.tmp.path().join(format!("{what}{}", self.next))
    }

    /// Writes `files` into a new input folder and returns it.
    fn input(&mut self, files: &[(&str, &[u8])]) -> PathBuf {
        let dir = self.dir("in");
        std::fs::create_dir(&dir).expect("mkdir");
        write_tree(&dir, files);
        dir
    }

    fn open(&self) -> Vault {
        Vault::open(&self.vault_path(), &test_pass()).expect("open")
    }

    fn file_sha(&self) -> [u8; 32] {
        Sha256::digest(std::fs::read(self.vault_path()).expect("read vault")).into()
    }
}

fn env_file(key: &str, value: &str) -> Vec<u8> {
    format!("{key}={value}\n").into_bytes()
}

/// Masks `input` into a new folder with `ttl_days`; returns (masked dir, report).
fn mask_ttl(
    lab: &mut Lab,
    vault: &mut Vault,
    input: &Path,
    ttl_days: u32,
) -> (PathBuf, MaskReport) {
    let out = lab.dir("masked");
    let report = scan_dir(input);
    let opts = MaskOptions {
        ttl_days,
        ..MaskOptions::default()
    };
    let r = mask(&report, &Selection::All, input, &out, vault, &opts).expect("mask");
    (out, r)
}

fn restore_into(
    lab: &mut Lab,
    vault: &mut Vault,
    masked: &Path,
    id: &SessionId,
    keep: bool,
) -> RestoreReport {
    let out = lab.dir("restored");
    restore(masked, &out, vault, Some(id), keep).expect("restore")
}

fn session<'v>(v: &'v Vault, id: &SessionId) -> Option<&'v Session> {
    v.sessions().iter().find(|s| &s.id == id)
}

/// Every token of the session still has its value.
fn assert_session_intact(v: &Vault, id: &SessionId, want: &[Token]) {
    let s = session(v, id).expect("session kept");
    assert_eq!(s.tokens, want);
    assert!(s.tokens.iter().all(|t| v.value(t).is_some()), "entry lost");
}

#[test]
fn se2_session_records_scan_options() {
    let mut lab = Lab::new();
    let pw = fake_password();
    let input = lab.input(&[
        ("node_modules/x.js", b"let x = 1;\n"),
        (".env", &env_file("DB_PASSWORD", &pw)),
    ]);
    let mut vault = test_vault(lab.tmp.path());
    let opts = ScanOptions {
        no_default_excludes: true,
    };
    let report = crate::scan(&input, &opts).expect("scan");
    let masked = lab.dir("masked");
    let m = mask(
        &report,
        &Selection::All,
        &input,
        &masked,
        &mut vault,
        &MaskOptions::default(),
    )
    .expect("mask");
    let json = serde_json::to_value(&vault.sessions()[0]).expect("json");
    assert_eq!(json["scan_options"]["no_default_excludes"], true);
    assert!(lab.open().sessions()[0].scan_options == opts);
    let out = lab.dir("restored");
    restore(&masked, &out, &mut vault, Some(&m.session_id), false).expect("restore");
    assert_eq!(tree_hashes(&out), tree_hashes(&input));
}

#[test]
fn lf1_clean_restore_forgets_session() {
    let mut lab = Lab::new();
    let (shared, own) = (fake_password(), fake_password());
    let php = format!("<?php\ndefine('AUTH_KEY', '{own}');\n");
    let in_a = lab.input(&[
        (".env", &env_file("DB_PASSWORD", &shared)),
        ("wp-config.php", php.as_bytes()),
    ]);
    let in_b = lab.input(&[(".env", &env_file("DB_PASSWORD", &shared))]);
    let mut vault = test_vault(lab.tmp.path());
    let (masked_a, a) = mask_ttl(&mut lab, &mut vault, &in_a, 30);
    let (_, b) = mask_ttl(&mut lab, &mut vault, &in_b, 30);
    let (t_shared, t_own) = (
        token_for(&vault, shared.as_bytes()),
        token_for(&vault, own.as_bytes()),
    );
    let rep = restore_into(&mut lab, &mut vault, &masked_a, &a.session_id, false);
    assert!(rep.session_forgotten);
    assert_eq!(rep.kept_reason, None);
    for v in [&vault, &lab.open()] {
        assert!(session(v, &a.session_id).is_none());
        assert!(v.value(&t_own).is_none());
        assert!(
            v.value(&t_shared)
                .is_some_and(|x| x.expose() == shared.as_bytes())
        );
        assert_eq!(
            session(v, &b.session_id).expect("B kept").tokens,
            vec![t_shared.clone()]
        );
    }
    assert_no_secret(&serde_json::to_vec(&rep).expect("json"), &[&shared, &own]);
}

#[test]
fn lf2_non_clean_restore_keeps_session() {
    for case in 0..3 {
        let mut lab = Lab::new();
        let s = {
            let dir = lab.dir("in");
            std::fs::create_dir(&dir).expect("mkdir");
            (sample_tree(&dir), dir)
        };
        let (sample, input) = s;
        let mut vault = test_vault(lab.tmp.path());
        let (masked, m) = mask_ttl(&mut lab, &mut vault, &input, 30);
        let tokens = vault.sessions()[0].tokens.clone();
        let pat = fake_github_pat();
        let want = match case {
            0 => {
                std::fs::write(masked.join("src/app.js"), b"gone\n").expect("edit");
                (1, 0, 0)
            }
            1 => {
                write_tree(&masked, &[("ai.txt", b"VEILCODE_FAKE_1a2b3c4d\n")]);
                (0, 1, 0)
            }
            _ => {
                write_tree(
                    &masked,
                    &[("ai.js", format!("k = \"{pat}\";\n").as_bytes())],
                );
                (0, 0, 1)
            }
        };
        let rep = restore_into(&mut lab, &mut vault, &masked, &m.session_id, false);
        assert!(!rep.session_forgotten, "case {case}");
        let (missing, unknown, new_secrets) = want;
        let reason = KeptReason::NotClean {
            missing,
            unknown,
            new_secrets,
            not_copied: 0,
            tokens_in_unscanned: 0,
        };
        assert_eq!(rep.kept_reason, Some(reason), "case {case}");
        assert_session_intact(&vault, &m.session_id, &tokens);
        assert_session_intact(&lab.open(), &m.session_id, &tokens);
        let secrets = [pat.as_str(), &sample.pw, &sample.key, &sample.pat];
        assert_no_secret(&serde_json::to_vec(&rep).expect("json"), &secrets);
    }
}

#[test]
fn lf3_keep_retains_session() {
    let mut lab = Lab::new();
    let input = lab.input(&[(".env", &env_file("DB_PASSWORD", &fake_password()))]);
    let mut vault = test_vault(lab.tmp.path());
    let (masked, m) = mask_ttl(&mut lab, &mut vault, &input, 30);
    let before = vault.sessions().to_vec();
    let sha = lab.file_sha();
    let rep = restore_into(&mut lab, &mut vault, &masked, &m.session_id, true);
    assert!(!rep.session_forgotten);
    assert_eq!(rep.kept_reason, Some(KeptReason::KeepRequested));
    assert_eq!(vault.sessions(), before.as_slice());
    assert_session_intact(&lab.open(), &m.session_id, &before[0].tokens);
    assert_eq!(lab.file_sha(), sha);
}

#[test]
fn lf4_expiry_on_open() {
    let mut lab = Lab::new();
    let (px, py) = (fake_password(), fake_password());
    let in_x = lab.input(&[(".env", &env_file("DB_PASSWORD", &px))]);
    let in_y = lab.input(&[(".env", &env_file("DB_PASSWORD", &py))]);
    let mut vault = test_vault(lab.tmp.path());
    let (_, x) = mask_ttl(&mut lab, &mut vault, &in_x, 1);
    let (_, y) = mask_ttl(&mut lab, &mut vault, &in_y, 30);
    let (tx, ty) = (
        token_for(&vault, px.as_bytes()),
        token_for(&vault, py.as_bytes()),
    );
    let t = session(&vault, &x.session_id).expect("x").created;
    assert_eq!(
        session(&vault, &x.session_id).expect("x").expires_at,
        t + 86_400
    );
    drop(vault);
    let sha = lab.file_sha();
    let early = Vault::open_with_clock(&lab.vault_path(), &test_pass(), &ManualClock::new(t + 10));
    assert_eq!(early.expect("open").expired_removed(), 0);
    assert_eq!(lab.file_sha(), sha);
    let clock = ManualClock::new(t + 86_400 + 1);
    let v = Vault::open_with_clock(&lab.vault_path(), &test_pass(), &clock).expect("open");
    assert_eq!(v.expired_removed(), 1);
    assert_ne!(lab.file_sha(), sha);
    for v in [&v, &lab.open()] {
        assert!(session(v, &x.session_id).is_none());
        assert!(v.value(&tx).is_none());
        assert!(session(v, &y.session_id).is_some() && v.value(&ty).is_some());
    }
    assert!(!lab.tmp_path().exists());
}

#[test]
fn lf4_ttl_range_and_tampered_expiry() {
    let mut lab = Lab::new();
    let input = lab.input(&[(".env", &env_file("DB_PASSWORD", &fake_password()))]);
    let mut vault = test_vault(lab.tmp.path());
    for bad in [0, 366] {
        let out = lab.dir("masked");
        let opts = MaskOptions {
            ttl_days: bad,
            ..MaskOptions::default()
        };
        let err = mask(
            &scan_dir(&input),
            &Selection::All,
            &input,
            &out,
            &mut vault,
            &opts,
        )
        .expect_err("bad ttl");
        assert!(matches!(err, CoreError::BadTtl), "{bad}: {err}");
        assert!(!out.exists());
    }
    for days in [1, 365] {
        mask_ttl(&mut lab, &mut vault, &input, days);
    }
    for tamper in [MAX_TTL_SECS + 1, 0] {
        let mut v = lab.open();
        let created = v.data.sessions[0].created;
        v.data.sessions[0].expires_at = created + tamper;
        v.save().expect("re-seal");
        let err = Vault::open(&lab.vault_path(), &test_pass()).expect_err("tampered");
        assert_eq!(err.to_string(), "wrong passphrase or corrupted vault");
        v.data.sessions[0].expires_at = created + 86_400;
        v.save().expect("repair");
    }
}

/// After the last session is gone: no file, no tmp, and a new mask works.
fn assert_removed_then_reusable(lab: &mut Lab, mut vault: Vault, what: &str) {
    assert_eq!(vault.sessions().len(), 0, "{what}");
    assert!(!lab.vault_path().exists(), "{what}: vault.vc still exists");
    assert!(!lab.tmp_path().exists(), "{what}: vault.vc.tmp exists");
    let input = lab.input(&[(".env", &env_file("DB_PASSWORD", &fake_password()))]);
    mask_ttl(lab, &mut vault, &input, 30);
    assert_eq!(lab.open().sessions().len(), 1, "{what}");
}

fn one_session(lab: &mut Lab) -> (Vault, PathBuf, MaskReport) {
    let input = lab.input(&[(".env", &env_file("DB_PASSWORD", &fake_password()))]);
    let mut vault = test_vault(lab.tmp.path());
    let (masked, m) = mask_ttl(lab, &mut vault, &input, 1);
    (vault, masked, m)
}

#[test]
fn lf5_last_session_removal_deletes_file() {
    let mut lab = Lab::new();
    let (mut vault, masked, m) = one_session(&mut lab);
    let rep = restore_into(&mut lab, &mut vault, &masked, &m.session_id, false);
    assert!(rep.session_forgotten);
    assert_removed_then_reusable(&mut lab, vault, "forget");

    let mut lab = Lab::new();
    let (vault, _, m) = one_session(&mut lab);
    let created = session(&vault, &m.session_id).expect("s").created;
    drop(vault);
    let clock = ManualClock::new(created + 86_400);
    let vault = Vault::open_with_clock(&lab.vault_path(), &test_pass(), &clock).expect("open");
    assert_eq!(vault.expired_removed(), 1);
    assert_removed_then_reusable(&mut lab, vault, "expiry");

    let mut lab = Lab::new();
    let (mut vault, _, m) = one_session(&mut lab);
    vault.delete_session(&m.session_id).expect("delete");
    assert_removed_then_reusable(&mut lab, vault, "delete");

    let mut lab = Lab::new();
    let (mut vault, _, _) = one_session(&mut lab);
    vault.purge().expect("purge");
    assert_removed_then_reusable(&mut lab, vault, "purge");
}

#[test]
fn lf6_purge_and_status_hold_no_secrets() {
    let mut lab = Lab::new();
    let mut vault = test_vault(lab.tmp.path());
    let mut secrets = Vec::new();
    let mut out = Vec::new();
    for ttl in [20, 5, 10] {
        let pw = fake_password();
        let input = lab.input(&[(".env", &env_file("DB_PASSWORD", &pw))]);
        let (_, m) = mask_ttl(&mut lab, &mut vault, &input, ttl);
        out.extend(serde_json::to_vec(&m).expect("json"));
        secrets.push(pw);
    }
    let reopened = lab.open();
    out.extend(format!("{} {:?}", reopened.expired_removed(), reopened).as_bytes());
    let st = vault.status();
    let created = vault.sessions().iter().map(|s| s.created).min();
    let expiry = vault.sessions().iter().map(|s| s.expires_at).min();
    assert_eq!(
        st,
        VaultStatus {
            sessions: 3,
            oldest_created: created,
            next_expiry: expiry
        }
    );
    assert_eq!(expiry, Some(vault.sessions()[1].created + 5 * 86_400));
    let purged = vault.purge().expect("purge");
    assert_eq!(
        purged,
        PurgeResult {
            sessions_removed: 3,
            entries_removed: 3
        }
    );
    assert!(!lab.vault_path().exists() && !lab.tmp_path().exists());
    let empty = vault.status();
    assert_eq!(
        empty,
        VaultStatus {
            sessions: 0,
            oldest_created: None,
            next_expiry: None
        }
    );
    for v in [&st, &empty] {
        out.extend(serde_json::to_vec(v).expect("json"));
        out.extend(format!("{v:?}").as_bytes());
    }
    out.extend(serde_json::to_vec(&purged).expect("json"));
    out.extend(format!("{purged:?}").as_bytes());
    assert_no_secret(&out, &secrets);
}

#[test]
fn lf7_forget_only_after_output_written() {
    let mut lab = Lab::new();
    let s = {
        let dir = lab.dir("in");
        std::fs::create_dir(&dir).expect("mkdir");
        (sample_tree(&dir), dir)
    };
    let mut vault = test_vault(lab.tmp.path());
    let (masked, m) = mask_ttl(&mut lab, &mut vault, &s.1, 30);
    let tokens = vault.sessions()[0].tokens.clone();
    let sha = lab.file_sha();
    let out = lab.dir("restored");
    crate::paths::fail_file_writes_after(Some(2));
    let err = restore(&masked, &out, &mut vault, Some(&m.session_id), false);
    crate::paths::fail_file_writes_after(None);
    let err = err.expect_err("write failure");
    let CoreError::PartialOutput { cleaned, cause, .. } = &err else {
        panic!("expected PartialOutput, got {err}");
    };
    assert!(*cleaned && !out.exists());
    assert!(matches!(
        **cause,
        CoreError::Io {
            kind: std::io::ErrorKind::PermissionDenied,
            ..
        }
    ));
    assert_session_intact(&vault, &m.session_id, &tokens);
    assert_session_intact(&lab.open(), &m.session_id, &tokens);
    assert_eq!(lab.file_sha(), sha);
    assert_no_secret(format!("{err} {err:?}").as_bytes(), &s.0.all());
}

fn not_clean(not_copied: usize, tokens_in_unscanned: usize) -> Option<KeptReason> {
    Some(KeptReason::NotClean {
        missing: 0,
        unknown: 0,
        new_secrets: 0,
        not_copied,
        tokens_in_unscanned,
    })
}

#[test]
fn lf2b_not_clean_when_not_copied_or_tokens_in_unscanned() {
    let mut lab = Lab::new();
    let (pa, pb) = (fake_password(), fake_password());
    let in_a = lab.input(&[(".env", &env_file("DB_PASSWORD", &pa))]);
    let mut vault = test_vault(lab.tmp.path());
    let (masked_a, a) = mask_ttl(&mut lab, &mut vault, &in_a, 30);
    let tok_a = token_for(&vault, pa.as_bytes());
    let bin = [b"\0bin ".as_slice(), tok_a.as_str().as_bytes()].concat();
    write_tree(&masked_a, &[("blob.bin", &bin)]);
    let rep = restore_into(&mut lab, &mut vault, &masked_a, &a.session_id, false);
    assert_eq!(
        (rep.tokens_in_unscanned, rep.kept_reason.clone()),
        (1, not_clean(0, 1))
    );
    assert!(!rep.session_forgotten && session(&vault, &a.session_id).is_some());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::fs::remove_file(masked_a.join("blob.bin")).expect("rm");
        let name = std::ffi::OsStr::from_bytes(b"bad\xffname.txt");
        std::fs::write(masked_a.join(name), b"x\n").expect("write");
        let rep = restore_into(&mut lab, &mut vault, &masked_a, &a.session_id, false);
        assert_eq!(rep.kept_reason, not_clean(1, 0));
        assert!(session(&lab.open(), &a.session_id).is_some());
        std::fs::remove_file(masked_a.join(name)).expect("rm");
    }
    // A token from another session is counted but does not block forgetting.
    let in_b = lab.input(&[(".env", &env_file("DB_PASSWORD", &pb))]);
    let (masked_b, b) = mask_ttl(&mut lab, &mut vault, &in_b, 30);
    write_tree(
        &masked_b,
        &[("other.txt", format!("{}\n", tok_a.as_str()).as_bytes())],
    );
    let rep = restore_into(&mut lab, &mut vault, &masked_b, &b.session_id, false);
    assert_eq!(rep.foreign_session_tokens, 1);
    assert!(rep.session_forgotten, "{:?}", rep.kept_reason);
    assert!(session(&vault, &a.session_id).is_some());
    assert_no_secret(&serde_json::to_vec(&rep).expect("json"), &[&pa, &pb]);
}

/// Holds the D28 lock so every persist fails with SaveLocked.
fn lock(lab: &Lab) {
    std::fs::write(lab.tmp_path(), b"held").expect("lock");
}

fn ids(v: &Vault) -> Vec<SessionId> {
    v.sessions().iter().map(|s| s.id.clone()).collect()
}

#[test]
fn lf9_failed_persist_leaves_memory_equal_to_disk() {
    let mut lab = Lab::new();
    let mut vault = test_vault(lab.tmp.path());
    let mut masked = Vec::new();
    for _ in 0..2 {
        let input = lab.input(&[(".env", &env_file("DB_PASSWORD", &fake_password()))]);
        masked.push(mask_ttl(&mut lab, &mut vault, &input, 30));
    }
    lock(&lab);
    let (dir, m) = &masked[1];
    let out = lab.dir("restored");
    let err = restore(dir, &out, &mut vault, Some(&m.session_id), false).expect_err("locked");
    assert!(matches!(err, CoreError::SaveLocked), "{err}");
    assert!(out.join(".env").is_file(), "D67: the output stays complete");
    let id = masked[0].1.session_id.clone();
    let err = vault.delete_session(&id).expect_err("locked");
    assert!(matches!(err, CoreError::SaveLocked), "{err}");
    let err = vault.purge().expect_err("locked");
    assert!(matches!(err, CoreError::SaveLocked), "{err}");
    std::fs::remove_file(lab.tmp_path()).expect("unlock");
    let disk = lab.open();
    assert_eq!(ids(&vault), ids(&disk));
    assert_eq!(vault.sessions().len(), 2);
    assert_eq!(vault.data.entries.len(), disk.data.entries.len());
    vault.purge().expect("purge after unlock");
    assert!(!lab.vault_path().exists());
}
