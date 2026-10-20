//! P8 restore tests for custom placeholder prefixes (TEST_CASES R14–R17, D138).

use super::*;
use crate::mask::{MaskOptions, Selection, mask};
use crate::report::MaskReport;
use crate::secret::SecretBytes;
use crate::test_support::*;
use crate::token::TokenPrefix;
use std::path::PathBuf;

fn prefix(s: &str) -> TokenPrefix {
    TokenPrefix::parse(s).expect("valid prefix")
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("json")
}

/// Scans `input` and masks every finding into `out` with `p`.
fn mask_with(input: &Path, out: &Path, vault: &mut Vault, p: &TokenPrefix) -> MaskReport {
    let report = scan_dir(input);
    let opts = MaskOptions {
        token_prefix: p.clone(),
        ..MaskOptions::default()
    };
    mask(&report, &Selection::All, input, out, vault, &opts).expect("mask")
}

fn restore_dir(input: &Path, out: &Path, vault: &mut Vault) -> RestoreReport {
    let profile = Profile::default();
    restore(input, out, vault, None, false, &profile).expect("restore")
}

struct Dirs {
    tmp: tempfile::TempDir,
    input: PathBuf,
}

impl Dirs {
    fn new() -> Dirs {
        let tmp = tempfile::tempdir().expect("tempdir");
        let input = tmp.path().join("in");
        std::fs::create_dir(&input).expect("mkdir");
        Dirs { tmp, input }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }
}

#[test]
fn r14_custom_prefix_round_trip() {
    let d = Dirs::new();
    let mut vault = test_vault(d.tmp.path());
    let s = sample_tree(&d.input);
    write_tree(
        &d.input,
        &[("notes.txt", b"see Infra_Mask_ docs and Infra_Mask_x\n")],
    );
    let p = prefix("Infra_Mask_");
    let (masked, restored) = (d.path("masked"), d.path("restored"));
    let m = mask_with(&d.input, &masked, &mut vault, &p);
    assert_eq!(m.secrets_masked, 3);
    let out = all_bytes(&masked);
    assert!(
        !out.windows(9).any(|w| w == b"VEILCODE_"),
        "default token written"
    );
    for secret in s.all() {
        let t = token_for(&vault, secret.as_bytes());
        assert!(t.as_str().starts_with("Infra_Mask_"), "{}", t.as_str());
        assert!(
            out.windows(t.as_str().len())
                .any(|w| w == t.as_str().as_bytes())
        );
    }
    assert_eq!(read(&masked, "notes.txt"), read(&d.input, "notes.txt"));
    let rep = restore_dir(&masked, &restored, &mut vault);
    assert_eq!(tree_hashes(&restored), tree_hashes(&d.input));
    assert_eq!(rep.tokens_replaced, 3);
    assert!(rep.unknown.is_empty(), "{:?}", rep.unknown);
    assert!(rep.missing.is_empty() && rep.new_secrets.is_empty());
    assert!(rep.session_forgotten);
    assert_no_secret(&json(&m), &s.all());
    assert_no_secret(&json(&rep), &s.all());
}

/// A vault with a default-prefix session for `a` and a `MASK_` session for `b`.
fn mixed_vault(dir: &Path, a: &str, b: &str) -> (Vault, Token, Token) {
    let mut v = test_vault(dir);
    let val = |s: &str| SecretBytes::new(s.as_bytes().to_vec());
    let ta = v.get_or_create_token(&val(a), "db", "r", &[]).expect("a");
    let tb = v
        .get_or_create_token_with(&val(b), "db", "r", &prefix("MASK_"), &[])
        .expect("b");
    v.add_test_session("one", vec![ta.clone()]).expect("s1");
    v.add_test_session("two", vec![tb.clone()]).expect("s2");
    (v, ta, tb)
}

#[test]
fn r15_mixed_prefix_vault_replaces_both_across_prefixes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (a, b) = (fake_password(), fake_password());
    let (vault, ta, tb) = mixed_vault(tmp.path(), &a, &b);
    let (ta, tb) = (ta.as_str(), tb.as_str());
    assert!(tb.starts_with("MASK_DB_"));
    // D29 across prefixes: the default prefix directly before a MASK_ token.
    let text = format!("x={ta}\ny=VEILCODE_{tb}\nz=MASK_ZZ_abcdef01\n");
    let known = vault.known_prefixes();
    let r = replace_tokens(text.as_bytes(), &vault, &known);
    let want = format!("x={a}\ny=VEILCODE_{b}\nz=MASK_ZZ_abcdef01\n");
    assert_eq!(r.bytes.as_slice(), want.as_bytes());
    let seen: Vec<&str> = r.seen.iter().map(Token::as_str).collect();
    assert_eq!(seen, vec![ta, tb]);
    assert_eq!(r.unknown, vec!["MASK_ZZ_abcdef01".to_string()]);
}

#[test]
fn r15_pre_v1_4_vault_shape_restores_unchanged() {
    let d = Dirs::new();
    let mut vault = test_vault(d.tmp.path());
    let s = sample_tree(&d.input);
    let (masked, restored) = (d.path("masked"), d.path("restored"));
    mask_all(&d.input, &masked, &mut vault);
    let plain = vault.plaintext_json();
    assert!(
        !String::from_utf8_lossy(&plain).contains("prefix"),
        "new field written"
    );
    drop(vault);
    let mut vault = Vault::open(&d.tmp.path().join("vault.vc"), &test_pass()).expect("open");
    let rep = restore_dir(&masked, &restored, &mut vault);
    assert_eq!(tree_hashes(&restored), tree_hashes(&d.input));
    assert_eq!(rep.tokens_replaced, 3);
    assert_no_secret(&json(&rep), &s.all());
}

#[test]
fn r16_counter_finds_a_long_prefix_token_split_anywhere() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut v = test_vault(tmp.path());
    let p = prefix("Abcdefghijklmno_");
    assert_eq!(p.as_str().len(), 16);
    let val = SecretBytes::new(fake_password().into_bytes());
    let name = "N".repeat(30);
    let t = v
        .get_or_create_token_with(&val, &name, "r", &p, &[])
        .expect("token");
    assert_eq!(t.as_str().len(), 16 + 24 + 1 + 8);
    let other = format!("Abcdefghijklmno_{}_abcdef01", "M".repeat(24));
    for (token, want) in [(t.as_str(), 1), (other.as_str(), 0)] {
        let buf = format!("xx{token}yy");
        for cut in 0..=buf.len() {
            let known = v.known_prefixes();
            let mut c = TokenCounter::new(&v, &known);
            c.feed(&buf.as_bytes()[..cut]);
            c.feed(&buf.as_bytes()[cut..]);
            assert_eq!(c.count, want, "cut at {cut}");
        }
    }
}

#[test]
fn r17_custom_prefix_tokens_are_not_new_secrets() {
    let d = Dirs::new();
    let mut vault = test_vault(d.tmp.path());
    let pw = fake_password();
    let env = format!("DB_PASSWORD={pw}\nAPI_KEY='{}'\n", fake_password());
    write_tree(&d.input, &[(".env", env.as_bytes())]);
    let (masked, restored) = (d.path("masked"), d.path("restored"));
    let m = mask_with(&d.input, &masked, &mut vault, &prefix("Infra_Mask_"));
    assert_eq!(m.secrets_masked, 2);
    let rep = restore_dir(&masked, &restored, &mut vault);
    assert!(
        rep.new_secrets.is_empty(),
        "{} new secrets",
        rep.new_secrets.len()
    );
    assert_eq!(read(&restored, ".env"), env.as_bytes());
}

#[test]
fn r15_unknown_custom_tokens_need_a_hex_letter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (a, b) = (fake_password(), fake_password());
    let (vault, _, _) = mixed_vault(tmp.path(), &a, &b);
    let text = "x MASK_K_12345678 y MASK_K_1234567a z VEILCODE_K_12345678\n";
    let r = replace_tokens(text.as_bytes(), &vault, &vault.known_prefixes());
    assert_eq!(r.bytes.as_slice(), text.as_bytes());
    assert_eq!(r.unknown, vec!["MASK_K_1234567a", "VEILCODE_K_12345678"]);
}

/// Inserts an entry with an exact token (R15b needs tokens at one offset).
fn crafted(v: &mut Vault, token: &str, p: &TokenPrefix, value: &str) -> Token {
    v.insert_test_entry(token, p, SecretBytes::new(value.as_bytes().to_vec()))
}

#[test]
fn r15b_longest_vault_token_wins_across_prefixes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut v = test_vault(tmp.path());
    let (short_p, long_p) = (prefix("A_"), prefix("A_B_ab000000_"));
    let (s1, s2) = (fake_password(), fake_password());
    // Both start at offset 0: `A_` + NAME `B` + HEX8, and the longer prefix.
    let short = crafted(&mut v, "A_B_ab000000", &short_p, &s1);
    let long = crafted(&mut v, "A_B_ab000000_K_cd000000", &long_p, &s2);
    v.add_test_session("s", vec![short, long.clone()])
        .expect("session");
    let text = "A_B_ab000000_K_cd000000\n";
    let r = replace_tokens(text.as_bytes(), &v, &v.known_prefixes());
    assert_eq!(r.bytes.as_slice(), format!("{s2}\n").as_bytes());
    assert_eq!(r.seen, vec![long]);
    // And the shorter one alone still matches.
    let r = replace_tokens(b"A_B_ab000000 ", &v, &v.known_prefixes());
    assert_eq!(r.bytes.as_slice(), format!("{s1} ").as_bytes());
}
