//! Placeholders changed by the developer (TEST_CASES.md R14–R16, D146).

use super::*;
use crate::test_support::*;
use std::path::PathBuf;

struct Run {
    _tmp: tempfile::TempDir,
    input: PathBuf,
    masked: PathBuf,
    restored: PathBuf,
    vault: Vault,
    pw: String,
    key1: String,
    key2: String,
    dev: String,
}

/// `.env` with `DB_PASSWORD` and `API_KEY`, `other.env` with another
/// `API_KEY`, masked into `masked`.
fn masked_run() -> Run {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    let (pw, key1, key2) = (fake_password(), fake_password(), fake_password());
    write_tree(
        &input,
        &[
            (
                ".env",
                format!("DB_PASSWORD={pw}\nAPI_KEY={key1}\n").as_bytes(),
            ),
            ("other.env", format!("API_KEY={key2}\n").as_bytes()),
        ],
    );
    let mut vault = test_vault(tmp.path());
    let masked = tmp.path().join("masked");
    mask_all(&input, &masked, &mut vault);
    Run {
        input,
        restored: tmp.path().join("restored"),
        masked,
        vault,
        pw,
        key1,
        key2,
        dev: fake_password(),
        _tmp: tmp,
    }
}

impl Run {
    fn tok(&self, secret: &str) -> Token {
        token_for(&self.vault, secret.as_bytes())
    }

    /// Replaces `from` with `to` in the masked `rel`.
    fn edit(&self, rel: &str, from: &str, to: &str) {
        let text = String::from_utf8(read(&self.masked, rel)).expect("utf8");
        assert!(text.contains(from), "{rel} lacks the text to replace");
        std::fs::write(self.masked.join(rel), text.replace(from, to)).expect("write");
    }

    /// The developer replaced the `DB_PASSWORD` placeholder.
    fn replace_pw_token(&self) {
        let tok = self.tok(&self.pw);
        self.edit(".env", tok.as_str(), &self.dev);
    }

    fn restore(&mut self, originals: &Originals) -> RestoreReport {
        let profile = Profile::default();
        let (input, out) = (&self.masked, &self.restored);
        restore_with(
            input,
            out,
            &mut self.vault,
            None,
            false,
            &profile,
            originals,
        )
        .expect("restore")
    }

    fn secrets(&self) -> [&str; 4] {
        [&self.pw, &self.key1, &self.key2, &self.dev]
    }
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("json")
}

fn kept_changed(rep: &RestoreReport) -> usize {
    match rep.kept_reason {
        Some(KeptReason::NotClean {
            changed_by_developer,
            ..
        }) => changed_by_developer,
        ref other => panic!("not a NotClean outcome: {other:?}"),
    }
}

#[test]
fn r14_replaced_placeholder_is_changed_by_developer() {
    let mut r = masked_run();
    let pw_tok = r.tok(&r.pw);
    let files = &r.vault.sessions()[0].files;
    assert_eq!(files.get(&pw_tok), Some(&vec![".env".to_string()]));
    assert_eq!(
        files.get(&r.tok(&r.key2)),
        Some(&vec!["other.env".to_string()])
    );
    r.replace_pw_token();
    let rep = r.restore(&Originals::Keep);
    assert_eq!(rep.changed_by_developer.len(), 1);
    let c = &rep.changed_by_developer[0];
    assert_eq!(c.token, pw_tok);
    assert_eq!(c.finding.rel_path, ".env");
    assert_eq!(c.finding.key_name.as_deref(), Some("DB_PASSWORD"));
    assert!(!c.original_used);
    assert_eq!(rep.missing, Vec::<Token>::new());
    assert!(rep.new_secrets.is_empty(), "{:?}", rep.new_secrets.len());
    let want = format!("DB_PASSWORD={}\nAPI_KEY={}\n", r.dev, r.key1);
    assert!(read(&r.restored, ".env") == want.as_bytes());
    assert_eq!(kept_changed(&rep), 1);
    assert!(!rep.session_forgotten);
    assert_no_secret(&json(&rep), &r.secrets());
}

#[test]
fn r14_value_in_a_file_the_token_was_not_written_to_does_not_pair() {
    let mut r = masked_run();
    let key1_tok = r.tok(&r.key1);
    r.edit(".env", &format!("API_KEY={}\n", key1_tok.as_str()), "");
    let other = format!("API_KEY={}\n", r.tok(&r.key2).as_str());
    r.edit("other.env", &other, &format!("{other}API_KEY={}\n", r.dev));
    let rep = r.restore(&Originals::Keep);
    assert!(rep.changed_by_developer.is_empty());
    assert_eq!(rep.missing, vec![key1_tok]);
    assert_eq!(rep.new_secrets.len(), 1);
    assert_eq!(rep.new_secrets[0].rel_path, "other.env");
    assert_no_secret(&json(&rep), &r.secrets());
}

#[test]
fn r14_session_without_files_record_pairs_by_key_name_only() {
    let mut r = masked_run();
    assert!(String::from_utf8_lossy(&r.vault.plaintext_json()).contains(r#""files""#));
    r.vault.clear_files_record();
    assert!(!String::from_utf8_lossy(&r.vault.plaintext_json()).contains(r#""files""#));
    r.replace_pw_token();
    let rep = r.restore(&Originals::Keep);
    assert_eq!(rep.changed_by_developer.len(), 1);
    assert_eq!(rep.changed_by_developer[0].token, r.tok(&r.pw));
    assert_no_secret(&json(&rep), &r.secrets());
}

#[test]
fn r14_two_missing_tokens_with_one_candidate_do_not_pair() {
    let mut r = masked_run();
    r.vault.clear_files_record();
    let (k1, k2) = (r.tok(&r.key1), r.tok(&r.key2));
    r.edit(".env", &format!("API_KEY={}\n", k1.as_str()), "");
    r.edit("other.env", k2.as_str(), &r.dev);
    let rep = r.restore(&Originals::Keep);
    assert!(rep.changed_by_developer.is_empty());
    let mut want = vec![k1, k2];
    want.sort();
    assert_eq!(rep.missing, want);
    assert_eq!(rep.new_secrets.len(), 1);
    assert_no_secret(&json(&rep), &r.secrets());
}

#[test]
fn r15_check_then_use_original() {
    let mut r = masked_run();
    r.replace_pw_token();
    let pw_tok = r.tok(&r.pw);
    let profile = Profile::default();
    let pairs = restore_check(&r.masked, &r.vault, None, &profile).expect("check");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].token, pw_tok);
    assert!(!pairs[0].original_used);
    assert!(!r.restored.exists());
    assert_no_secret(&json(&pairs), &r.secrets());
    let rep = r.restore(&Originals::Only(BTreeSet::from([pw_tok.clone()])));
    assert!(read(&r.restored, ".env") == read(&r.input, ".env"));
    assert_eq!(rep.changed_by_developer.len(), 1);
    assert_eq!(rep.changed_by_developer[0].token, pw_tok);
    assert!(rep.changed_by_developer[0].original_used);
    assert_eq!(rep.tokens_replaced, 3);
    assert!(rep.missing.is_empty() && rep.new_secrets.is_empty());
    assert!(rep.session_forgotten, "{:?}", rep.kept_reason);
    assert_no_secret(&json(&rep), &r.secrets());
}

#[test]
fn r15_choice_for_a_token_that_does_not_pair_changes_nothing() {
    let mut r = masked_run();
    r.replace_pw_token();
    let rep = r.restore(&Originals::Only(BTreeSet::from([r.tok(&r.key1)])));
    let want = format!("DB_PASSWORD={}\nAPI_KEY={}\n", r.dev, r.key1);
    assert!(read(&r.restored, ".env") == want.as_bytes());
    assert_eq!(rep.changed_by_developer.len(), 1);
    assert!(!rep.changed_by_developer[0].original_used);
    assert_eq!(kept_changed(&rep), 1);
}

#[test]
fn r16_original_not_written_over_a_file_that_changed() {
    let mut r = masked_run();
    r.replace_pw_token();
    let env = r.masked.join(".env");
    set_between_passes(Box::new(move || {
        let mut text = std::fs::read(&env).expect("read");
        text.extend_from_slice(b"# edited\n");
        std::fs::write(&env, text).expect("write");
    }));
    let rep = r.restore(&Originals::All);
    let want = format!("DB_PASSWORD={}\nAPI_KEY={}\n# edited\n", r.dev, r.key1);
    assert!(read(&r.restored, ".env") == want.as_bytes());
    assert_eq!(rep.changed_by_developer.len(), 1);
    assert!(!rep.changed_by_developer[0].original_used);
    assert_eq!(kept_changed(&rep), 1);
    assert!(!rep.session_forgotten);
    assert_no_secret(&json(&rep), &r.secrets());
}
