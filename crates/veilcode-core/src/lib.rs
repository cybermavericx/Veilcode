//! Veilcode core: all masking, restore, scanning and vault logic lives here.
//!
//! This crate does no printing, no prompting and no process launching.
#![forbid(unsafe_code)]

mod clock;
mod error;
mod hex;
mod mask;
mod paths;
mod profile;
mod report;
mod restore;
mod rng;
mod scan;
mod secret;
mod text;
mod token;
mod vault;

#[cfg(test)]
mod test_support;

pub use clock::{Clock, SystemClock};
pub use error::{CoreError, Result};
pub use mask::{MaskOptions, Selection, mask};
pub use profile::{IgnoreEntry, Profile, Scope, default_profile_path};
pub use report::{KeptReason, MaskReport, RestoreReport};
pub use restore::restore;
pub use scan::{
    Detector, Finding, IgnoreReason, ScanOptions, ScanReport, ScannedFile, Skipped, scan, to_json,
};
pub use secret::{SecretBytes, SecretString};
pub use text::{mask_text, restore_text};
pub use token::{TOKEN_PATTERN, Token};
pub use vault::{PurgeResult, Session, SessionId, Vault, VaultStatus, default_vault_path};
