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
    /// The profile is not a regular file of at most 1 MiB (D79).
    #[error("unsafe profile (must be a regular file ≤ 1 MiB)")]
    UnsafeProfile,
    /// The profile is not strict TOML with known fields (D79). Only the
    /// line is reported, never the parser text, which can quote the file.
    #[error("profile is not valid TOML or has an unknown or mistyped field (line {line})")]
    ProfileParse { line: usize },
    /// The profile `version` is not 1 (D74).
    #[error("unsupported profile version {version} (expected 1)")]
    ProfileVersion { version: u32 },
    /// A key name or rule id is not 1–64 of `A-Z a-z 0-9 _ . -` or space (D79).
    #[error(
        "key names and rule ids must be 1–64 characters of A–Z, a–z, 0–9, _, ., - or space, \
         with at least one letter or digit"
    )]
    BadKeyName,
    /// An `[[ignored]]` entry needs exactly one of key_name or rule_id (D74).
    #[error("each [[ignored]] entry needs exactly one of key_name or rule_id")]
    BadIgnoreEntry,
    /// A finding without a key name can only be ignored in its own file.
    #[error("this finding has no key name; it can only be ignored in its file")]
    NoKeyName,
    /// A profile list is over its D88 cap.
    #[error("profile has too many {what} (at most {max})")]
    ProfileTooLarge { what: &'static str, max: usize },
    /// The profile extra_keys could not be compiled into the D5 detector (D88).
    #[error("profile extra_keys could not be compiled into the custom-key detector")]
    ProfileRegex,
    /// `profile.toml.tmp` already exists: a save is running or one crashed.
    #[error(
        "profile is being saved by another Veilcode process, or a previous save crashed \
         — delete {} if no Veilcode is running", path.display()
    )]
    ProfileSaveLocked { path: PathBuf },
    /// A findings file is not a valid scan report. Only the position is
    /// reported, never the parser text, which can quote the file.
    #[error("findings file is not a valid scan report (line {line}, column {column})")]
    FindingsFile { line: usize, column: usize },
    /// A report could not be encoded as JSON.
    #[error("report could not be encoded as JSON")]
    ReportEncode,
    /// A placeholder prefix breaks the D138 rule. The input is not quoted.
    #[error(
        "placeholder prefix must be 2–16 ASCII characters: a letter first, \
         then letters, digits or _, ending with _"
    )]
    BadTokenPrefix,
    /// A custom prefix starts with `VEILCODE_` (L4).
    #[error("a placeholder prefix other than VEILCODE_ must not start with VEILCODE_")]
    ReservedTokenPrefix,
    /// The finding viewer refused a path: not a regular file reached
    /// without links inside the scanned folder (D137).
    #[error("cannot show {rel_path}: not a regular file inside the scanned folder")]
    NotViewable { rel_path: String },
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
