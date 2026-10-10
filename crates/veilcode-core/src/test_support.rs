//! Shared test helpers (TEST_CASES.md "Shared test helpers").

use crate::secret::{SecretBytes, SecretString};
use crate::vault::KdfParams;
use crate::vault::Vault;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// Low Argon2 params for fast tests.
pub(crate) const LOW_PARAMS: KdfParams = KdfParams {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `n` random `[A-Za-z0-9]` characters from getrandom.
pub(crate) fn random_alnum(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).expect("getrandom");
        // 248 = 4 * 62: reject the tail so every character is equally likely.
        if b[0] < 248 {
            out.push(char::from(ALNUM[usize::from(b[0]) % ALNUM.len()]));
        }
    }
    out
}

/// A random GitHub-PAT-shaped string; the prefix is built at runtime.
pub(crate) fn fake_github_pat() -> String {
    [["gh", "p_"].concat(), random_alnum(36)].concat()
}

/// 20 random alnum characters plus one symbol from `!%^*`.
pub(crate) fn fake_password() -> String {
    let mut b = [0u8; 1];
    getrandom::fill(&mut b).expect("getrandom");
    let sym = char::from(b"!%^*"[usize::from(b[0] % 4)]);
    format!("{}{sym}", random_alnum(20))
}

/// Writes each `(rel, bytes)` under `dir`, creating parent directories.
pub(crate) fn write_tree(dir: &Path, files: &[(&str, &[u8])]) {
    for (rel, bytes) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create dirs");
        }
        std::fs::write(&path, bytes).expect("write file");
    }
}

/// sha256 of every file under `dir`, keyed by `/`-separated relative path.
pub(crate) fn tree_hashes(dir: &Path) -> BTreeMap<String, [u8; 32]> {
    let mut out = BTreeMap::new();
    hash_into(dir, "", &mut out);
    out
}

fn hash_into(dir: &Path, prefix: &str, out: &mut BTreeMap<String, [u8; 32]>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type().expect("file type");
        if kind.is_dir() {
            hash_into(&entry.path(), &rel, out);
        } else if kind.is_file() {
            let bytes = std::fs::read(entry.path()).expect("read file");
            out.insert(rel, Sha256::digest(&bytes).into());
        }
    }
}

/// Fails if any secret occurs in `haystack`; the message shows only a preview.
pub(crate) fn assert_no_secret(haystack: &[u8], secrets: &[impl AsRef<[u8]>]) {
    for s in secrets {
        let s = s.as_ref();
        assert!(!s.is_empty(), "assert_no_secret: empty secret");
        if haystack.windows(s.len()).any(|w| w == s) {
            let preview = SecretBytes::new(s.to_vec()).preview();
            panic!("secret {preview} found in output");
        }
    }
}

/// The passphrase used by `test_vault`.
pub(crate) fn test_pass() -> SecretString {
    SecretString::new("test vault passphrase".to_string())
}

/// A vault at `dir/vault.vc` with low Argon2 params (m=8 KiB, t=1, p=1).
pub(crate) fn test_vault(dir: &Path) -> Vault {
    Vault::create_with_params(&dir.join("vault.vc"), &test_pass(), LOW_PARAMS)
        .expect("create test vault")
}

#[test]
fn helpers_generate_expected_shapes() {
    let a = random_alnum(50);
    assert_eq!(a.len(), 50);
    assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
    let pat = fake_github_pat();
    assert_eq!(pat.len(), 40);
    assert!(pat.starts_with(&["gh", "p_"].concat()));
    let pw = fake_password();
    assert_eq!(pw.chars().count(), 21);
    assert!(pw.chars().any(|c| "!%^*".contains(c)));
}

#[test]
fn helpers_write_tree_and_hash_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_tree(dir.path(), &[("a.txt", b"x"), ("sub/b/c.bin", &[0xff])]);
    let h = tree_hashes(dir.path());
    let keys: Vec<&str> = h.keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["a.txt", "sub/b/c.bin"]);
    let expect: [u8; 32] = Sha256::digest(b"x").into();
    assert_eq!(h["a.txt"], expect);
}

#[test]
#[should_panic(expected = "secret …(3) found in output")]
fn helpers_assert_no_secret_shows_preview_only() {
    assert_no_secret(b"xx abc yy", &["abc"]);
}
