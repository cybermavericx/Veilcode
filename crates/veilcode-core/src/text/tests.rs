//! P3 Text Mode test (TEST_CASES.md X1).

use super::*;
use crate::test_support::*;

#[test]
fn x1_text_mode_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut vault = test_vault(dir.path());
    let (pat, url_pw, env_pw) = (fake_github_pat(), random_alnum(20), fake_password());
    let s =
        format!("pat {pat}\r\nurl postgres://u:{url_pw}@h/db\nDB_PASSWORD={env_pw}\ncaf\u{e9}\n");
    let (masked, id) = mask_text(&s, &mut vault).expect("mask_text");
    let secrets = [pat.as_str(), &url_pw, &env_pw];
    assert_no_secret(masked.as_bytes(), &secrets);
    let session = vault
        .sessions()
        .iter()
        .find(|x| x.id == id)
        .expect("session");
    assert_eq!(
        (session.source_label.as_str(), session.tokens.len()),
        ("text", 3)
    );
    let reopened = Vault::open(&dir.path().join("vault.vc"), &test_pass()).expect("saved");
    assert_eq!(reopened.sessions().len(), 1);
    let (restored, report) = restore_text(&masked, &mut vault, None, false).expect("restore_text");
    assert!(restored == s, "text round trip differs");
    assert_eq!(report.tokens_replaced, 3);
    assert_eq!((report.unknown.len(), report.new_secrets.len()), (0, 0));
    // D60: a clean Text Mode restore forgets its session.
    assert_eq!(report.session_id, Some(id));
    assert!(report.session_forgotten);
    assert_no_secret(&serde_json::to_vec(&report).expect("json"), &secrets);
}
