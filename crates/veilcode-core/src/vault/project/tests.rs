//! T11: per-project prefix memory in the vault (D141).

use super::super::model::VaultData;
use super::*;
use crate::secret::SecretBytes;
use crate::test_support::*;
use crate::token::Token;

fn prefix(p: &str) -> TokenPrefix {
    TokenPrefix::parse(p).expect("prefix")
}

fn json_text(v: &Vault) -> String {
    String::from_utf8(v.plaintext_json().to_vec()).expect("utf8")
}

#[test]
fn t11_project_key_is_a_hash_of_the_canonical_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b) = (dir.path().join("projalpha"), dir.path().join("projbeta"));
    std::fs::create_dir_all(a.join("sub")).expect("mkdir");
    std::fs::create_dir(&b).expect("mkdir");
    let key = ProjectKey::for_input(&a).expect("key");
    let again = ProjectKey::for_input(&a.join("sub").join("..")).expect("key");
    assert_eq!(key, again, "another spelling of the same folder");
    assert_ne!(key, ProjectKey::for_input(&b).expect("key"));
    assert_eq!(key.as_str().len(), 64);
    assert!(
        key.as_str()
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    );
    let debug = format!("{key:?}");
    assert!(
        !debug.contains("projalpha") && !debug.contains("tmp"),
        "{debug}"
    );
    let missing = ProjectKey::for_input(&dir.path().join("gone"));
    assert!(matches!(missing, Err(CoreError::Io { .. })), "{missing:?}");
}

#[test]
fn t11_remembered_prefix_round_trips_and_default_is_not_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("projalpha");
    std::fs::create_dir(&project).expect("mkdir");
    let key = ProjectKey::for_input(&project).expect("key");
    let mut v = test_vault(dir.path());
    assert_eq!(v.remembered_prefix(&key), None);
    v.remember_prefix(key.clone(), &prefix("Infra_Mask_"));
    v.save().expect("save");
    let mut r = Vault::open(&dir.path().join("vault.vc"), &test_pass()).expect("open");
    assert_eq!(r.remembered_prefix(&key), Some(&prefix("Infra_Mask_")));
    let json = json_text(&r);
    let member = format!(r#""project_prefixes":{{"{}":"Infra_Mask_"}}"#, key.as_str());
    assert!(json.contains(&member), "{json}");
    assert!(
        !json.contains("projalpha"),
        "path text in the vault: {json}"
    );
    r.remember_prefix(key.clone(), &TokenPrefix::default());
    assert_eq!(r.remembered_prefix(&key), None);
    let json = json_text(&r);
    assert!(!json.contains("project_prefixes"), "pre-D141 shape: {json}");
}

/// A plaintext with no session or entry and `member` as extra top-level JSON.
fn with_member(member: &str) -> Vec<u8> {
    format!(r#"{{"version":1,"sessions":[],"entries":{{}}{member}}}"#).into_bytes()
}

#[test]
fn t11_bad_project_entries_are_the_generic_error() {
    let old = VaultData::from_json(&with_member("")).expect("pre-D141 shape");
    assert!(old.project_prefixes.is_empty());
    let good = "ab".repeat(32);
    let ok = format!(r#","project_prefixes":{{"{good}":"Infra_Mask_"}}"#);
    let data = VaultData::from_json(&with_member(&ok)).expect("valid");
    let key = ProjectKey::parse(&good).expect("key");
    assert_eq!(
        data.project_prefixes.get(&key),
        Some(&prefix("Infra_Mask_"))
    );
    let upper = "AB".repeat(32);
    let short = "ab".repeat(31);
    for (k, p) in [
        (upper.as_str(), r#""Infra_Mask_""#),
        (short.as_str(), r#""Infra_Mask_""#),
        ("projalpha", r#""Infra_Mask_""#),
        (good.as_str(), r#""Infra_Mask""#),
        (good.as_str(), r#""VEILCODE_X_""#),
        (good.as_str(), "7"),
    ] {
        let raw = format!(r#","project_prefixes":{{"{k}":{p}}}"#);
        let err = VaultData::from_json(&with_member(&raw)).err();
        assert!(matches!(err, Some(CoreError::VaultOpen)), "{k} {p}");
    }
}

/// A saved vault with one session and `Infra_Mask_` remembered for `key`.
fn vault_with_memory(dir: &Path, key: &ProjectKey) -> Vault {
    let mut v = test_vault(dir);
    let value = SecretBytes::new(fake_password().into_bytes());
    let t: Token = v.get_or_create_token(&value, "k", "r", &[]).expect("token");
    v.add_test_session("s", vec![t]).expect("session");
    v.remember_prefix(key.clone(), &prefix("Infra_Mask_"));
    v.save().expect("save");
    v
}

#[test]
fn t11_last_session_gone_or_purge_clears_the_memory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = ProjectKey::for_input(dir.path()).expect("key");
    let mut v = vault_with_memory(dir.path(), &key);
    let id = v.sessions()[0].id.clone();
    v.delete_session(&id).expect("delete");
    assert!(!dir.path().join("vault.vc").exists(), "D62 removal");
    assert_eq!(v.remembered_prefix(&key), None, "memory equals disk");
    let mut v = vault_with_memory(dir.path(), &key);
    v.purge().expect("purge");
    assert_eq!(v.remembered_prefix(&key), None);
}
