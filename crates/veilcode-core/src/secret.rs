//! Holders for secret values: wiped on drop, redacted in `Debug`, no `Display`.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Raw secret bytes (may be non-UTF-8).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Takes ownership of `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    /// The raw bytes. Crate-internal so values only leave via restore.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Safe preview per D25: `abcd…(N)`, or `…(N)` under 8 chars.
    pub fn preview(&self) -> String {
        preview_str(&String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted>, len={})", self.0.len())
    }
}

/// A secret UTF-8 string, such as a passphrase.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Takes ownership of `s`.
    pub fn new(s: String) -> Self {
        SecretString(s)
    }

    /// The string. Crate-internal.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// Safe preview per D25.
    pub fn preview(&self) -> String {
        preview_str(&self.0)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<redacted>, len={})", self.0.len())
    }
}

/// D25: fewer than 8 chars shows none; otherwise the first 4. N counts chars.
fn preview_str(s: &str) -> String {
    let n = s.chars().count();
    if n < 8 {
        return format!("…({n})");
    }
    let head: String = s.chars().take(4).collect();
    format!("{head}…({n})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_follows_d25() {
        assert_eq!(SecretBytes::new(b"abc".to_vec()).preview(), "…(3)");
        assert_eq!(SecretBytes::new(b"abcdefg".to_vec()).preview(), "…(7)");
        assert_eq!(SecretBytes::new(b"abcdefgh".to_vec()).preview(), "abcd…(8)");
        assert_eq!(
            SecretString::new("éééééééééé".into()).preview(),
            "éééé…(10)"
        );
    }

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::new(b"abcdefghij".to_vec());
        assert_eq!(format!("{s:?}"), "SecretBytes(<redacted>, len=10)");
        let p = SecretString::new("abcdefghij".into());
        assert_eq!(format!("{p:?}"), "SecretString(<redacted>, len=10)");
    }
}
