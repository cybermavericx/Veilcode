//! Core error type. Variants carry paths, ids and counts, never secret values.

use std::io;
use std::path::PathBuf;

/// Every error the core can return.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Any vault open failure: wrong passphrase, corruption, bad header (SPEC §7).
    #[error("wrong passphrase or corrupted vault")]
    VaultOpen,
    /// The vault file changed on disk since it was opened or saved (D7).
    #[error("vault changed by another Veilcode process — reopen")]
    VaultChanged,
    /// `vault.vc.tmp` already exists: a save is running or one crashed (D28).
    #[error(
        "vault is being saved by another Veilcode process, or a previous save crashed \
         — delete vault.vc.tmp if no Veilcode is running"
    )]
    SaveLocked,
    /// An empty secret value was given (D30).
    #[error("secret value is empty")]
    EmptyValue,
    /// A new vault's passphrase has fewer than 12 characters (D8).
    #[error("passphrase must be at least 12 characters")]
    PassphraseTooShort,
    /// A file system operation failed.
    #[error("I/O error on {}: {kind}", path.display())]
    Io { path: PathBuf, kind: io::ErrorKind },
    /// The OS random number generator failed.
    #[error("OS random number generator failed")]
    Random,
    /// `.veilcodeignore` is not a regular file of at most 1 MiB (D44).
    #[error("unsafe .veilcodeignore (must be a regular file ≤ 1 MiB)")]
    UnsafeIgnoreFile,
    /// The built-in gitleaks rule file could not be parsed.
    #[error("built-in detection rules failed to load")]
    RulesLoad,
    /// Encrypting the vault failed.
    #[error("vault encryption failed")]
    Encrypt,
}

impl CoreError {
    /// Builds an `Io` error from a path and an `io::Error` (kind only).
    pub(crate) fn io(path: &std::path::Path, err: &io::Error) -> Self {
        CoreError::Io {
            path: path.to_path_buf(),
            kind: err.kind(),
        }
    }
}

/// Result alias for the core.
pub type Result<T> = std::result::Result<T, CoreError>;
