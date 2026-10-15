//! Test helpers: small copies of the core helpers (core's are `#[cfg(test)]`)
//! plus a manual clock (D70: core's `ManualClock` is test-only, so the GUI
//! defines its own against the `Clock` trait). Secrets are made at runtime.

use std::cell::Cell;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::path::Path;
use std::rc::Rc;
use veilcode_core::{Clock, SecretBytes};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// One random u64 from std's randomly seeded SipHash keys (no extra crate).
fn random_u64(i: usize) -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_usize(i);
    h.finish()
}

/// `n` random `[A-Za-z0-9]` characters.
pub fn random_alnum(n: usize) -> String {
    let pick = |i| char::from(ALNUM[(random_u64(i) % ALNUM.len() as u64) as usize]);
    (0..n).map(pick).collect()
}

/// A random GitHub-PAT-shaped string; the prefix is built at runtime.
pub fn fake_github_pat() -> String {
    [["gh", "p_"].concat(), random_alnum(36)].concat()
}

/// 20 random alnum characters plus one symbol from `!%^*`.
pub fn fake_password() -> String {
    let sym = char::from(b"!%^*"[(random_u64(99) % 4) as usize]);
    format!("{}{sym}", random_alnum(20))
}

/// Writes each `(rel, bytes)` under `dir`, creating parent directories.
pub fn write_tree(dir: &Path, files: &[(&str, &[u8])]) {
    for (rel, bytes) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create dirs");
        }
        std::fs::write(&path, bytes).expect("write file");
    }
}

/// Fails, showing only the secret's preview, if any secret is in `haystack`.
pub fn assert_no_secret(haystack: &[u8], secrets: &[impl AsRef<[u8]>]) {
    for s in secrets {
        let s = s.as_ref();
        assert!(!s.is_empty(), "assert_no_secret: empty secret");
        if haystack.windows(s.len()).any(|w| w == s) {
            let preview = SecretBytes::new(s.to_vec()).preview();
            panic!("secret {preview} found in output");
        }
    }
}

/// A clock that only moves when told to; clones share the time.
#[derive(Clone)]
pub struct TestClock(Rc<Cell<u64>>);

impl TestClock {
    /// A clock reading `now` unix seconds.
    pub fn new(now: u64) -> Self {
        TestClock(Rc::new(Cell::new(now)))
    }

    /// Moves the time forward by `secs`.
    pub fn advance(&self, secs: u64) {
        self.0.set(self.0.get() + secs);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}
