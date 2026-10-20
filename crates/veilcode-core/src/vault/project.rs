//! Per-project placeholder prefix memory (D141). The vault remembers the
//! prefix of the last successful mask of a folder, keyed by a hash of the
//! folder's canonical path, so not even the decrypted vault holds the path.

use super::Vault;
use crate::error::{CoreError, Result};
use crate::hex;
use crate::token::TokenPrefix;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Domain separation for the key hash (D141).
const DOMAIN: &[u8] = b"veilcode project prefix v1\0";

/// A project key: lowercase hex sha256 of `DOMAIN` + the canonical path
/// of the scanned folder (D141). Holds no path text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectKey(String);

impl ProjectKey {
    /// The key of the folder `input` (canonicalised first, so other
    /// spellings of the same folder give the same key).
    pub fn for_input(input: &Path) -> Result<ProjectKey> {
        let canonical = std::fs::canonicalize(input).map_err(|e| CoreError::io(input, &e))?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(path_bytes(&canonical));
        Ok(ProjectKey(hex::encode(&hash.finalize())))
    }

    /// A stored key: exactly 64 lowercase hex characters.
    pub(crate) fn parse(s: &str) -> Option<ProjectKey> {
        let hex = |c: u8| matches!(c, b'0'..=b'9' | b'a'..=b'f');
        (s.len() == 64 && s.bytes().all(hex)).then(|| ProjectKey(s.to_string()))
    }

    /// The key text (64 hex characters).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The path bytes that are hashed: the OS bytes on Unix, UTF-16LE code
/// units on Windows (both lossless).
#[cfg(unix)]
fn path_bytes(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn path_bytes(p: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn path_bytes(p: &Path) -> Vec<u8> {
    p.to_string_lossy().as_bytes().to_vec()
}

impl Vault {
    /// The prefix remembered for the project `key`, if any (D141).
    pub fn remembered_prefix(&self, key: &ProjectKey) -> Option<&TokenPrefix> {
        self.data.project_prefixes.get(key)
    }

    /// Remembers `prefix` for `key` (memory only; the caller saves).
    /// `VEILCODE_` removes the key, so only custom prefixes are stored.
    pub(crate) fn remember_prefix(&mut self, key: ProjectKey, prefix: &TokenPrefix) {
        if prefix.is_default() {
            self.data.project_prefixes.remove(&key);
        } else {
            self.data.project_prefixes.insert(key, prefix.clone());
        }
    }
}

#[cfg(test)]
mod tests;
