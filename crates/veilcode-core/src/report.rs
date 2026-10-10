//! Mask and restore reports (SPEC §6.1 step 6, §6.2 step 5). They hold
//! ids, counts, paths, tokens and D25 previews only, never a secret value.

use crate::scan::Finding;
use crate::token::Token;
use crate::vault::SessionId;
use serde::Serialize;

/// The result of a mask run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaskReport {
    /// The session recorded in the vault (D53: also with 0 tokens).
    pub session_id: SessionId,
    /// Files written to the output folder.
    pub files_written: usize,
    /// Secret spans replaced by tokens.
    pub secrets_masked: usize,
    /// Distinct tokens in the session.
    pub tokens: usize,
    /// Input entries not copied (binary, oversized, symlink, excluded,
    /// non-UTF-8 name), sorted.
    pub not_copied: Vec<String>,
}

/// The result of a restore run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RestoreReport {
    /// The session used for `missing`; `None` if the vault has no sessions.
    pub session_id: Option<SessionId>,
    /// Files written to the output folder.
    pub files_written: usize,
    /// Token occurrences replaced by their values.
    pub tokens_replaced: usize,
    /// Secrets found in the input: introduced by the AI (previews only).
    pub new_secrets: Vec<Finding>,
    /// Token-shaped strings that are not in the vault, sorted, deduplicated.
    pub unknown: Vec<String>,
    /// Tokens of the session that never appear in the input, sorted.
    pub missing: Vec<Token>,
    /// Input entries not copied (symlink, excluded, non-UTF-8 name,
    /// changed during the walk), sorted.
    pub not_copied: Vec<String>,
    /// Vault tokens left in copied binary/oversized files (D71).
    pub tokens_in_unscanned: usize,
    /// Distinct replaced tokens from sessions other than the chosen one (D71).
    pub foreign_session_tokens: usize,
    /// The session and its unused entries were deleted (D60).
    pub session_forgotten: bool,
    /// Why a session was kept; `None` if forgotten or there was no session.
    pub kept_reason: Option<KeptReason>,
}

/// Why restore kept the session (D60).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum KeptReason {
    /// `keep = true` was given.
    KeepRequested,
    /// The restore was not clean.
    NotClean {
        missing: usize,
        unknown: usize,
        new_secrets: usize,
        not_copied: usize,
        tokens_in_unscanned: usize,
    },
}
