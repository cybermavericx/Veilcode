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
    /// The input no longer matches the ScanReport (SPEC §6.1 step 3, D13).
    #[error("file changed since scan — rescan")]
    Rescan,
    /// A selected finding does not fit its scanned file (bad offsets or hash).
    #[error("finding {id} does not match the scanned file — rescan")]
    BadFinding { id: String },
    /// The selection names a finding id that is not in the report (D51).
    #[error("unknown finding id {id}")]
    UnknownFinding { id: String },
    /// No session with this id (SPEC §6.4).
    #[error("unknown session {id}")]
    UnknownSession { id: String },
    /// A `rel_path` failed validation (SPEC §6.1 step 2, D14).
    #[error("invalid relative path {rel_path:?}")]
    BadRelPath { rel_path: String },
    /// The output folder is the input folder or inside it (SPEC §6.1 step 1).
    #[error("output folder must not be inside the input folder")]
    OutputInsideInput,
    /// The output folder already exists; Veilcode creates it itself (D68).
    #[error("output folder already exists: {}", path.display())]
    OutputExists { path: PathBuf },
    /// Unix: the output's nearest existing parent is group/other-writable
    /// without the sticky bit (D68).
    #[error("unsafe output location (parent writable by others, no sticky bit): {}", path.display())]
    UnsafeOutputParent { path: PathBuf },
    /// A run failed after creating its output folder (D69).
    #[error("{}", partial_message(*.cleaned, .dir, .cause))]
    PartialOutput {
        cleaned: bool,
        dir: PathBuf,
        cause: Box<CoreError>,
    },
    /// Restore without a session id on a vault with no matching session (D73).
    #[error("vault has no sessions to restore")]
    NoSession,
    /// `ttl_days` outside 1–365 (D61).
    #[error("ttl_days must be between 1 and 365")]
    BadTtl,
    /// Text Mode output would not be valid UTF-8.
    #[error("text result is not valid UTF-8")]
    TextNotUtf8,
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

/// D69 message: cleanup failure must tell the user to delete the folder.
fn partial_message(cleaned: bool, dir: &std::path::Path, cause: &CoreError) -> String {
    if cleaned {
        format!("{cause} (partial output removed)")
    } else {
        format!(
            "{cause}; output folder may contain real secrets — delete it: {}",
            dir.display()
        )
    }
}

/// Result alias for the core.
pub type Result<T> = std::result::Result<T, CoreError>;
