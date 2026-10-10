//! Text Mode (SPEC §6.3): mask and restore pasted text with the same
//! detectors, tokens and vault as folders.

use crate::error::{CoreError, Result};
use crate::mask::{Haystack, apply, plan_spans};
use crate::report::RestoreReport;
use crate::restore::{finish, replace_tokens, require_session};
use crate::scan::{self, RuleSet, ScanOptions};
use crate::vault::{DEFAULT_TTL_DAYS, SessionId, Vault};

/// The session label for Text Mode (D53).
const TEXT_LABEL: &str = "text";

/// Masks every finding in `text`, records a `"text"` session and saves the
/// vault. D2 and D3 apply to pasted text whatever its origin.
pub fn mask_text(text: &str, vault: &mut Vault) -> Result<(String, SessionId)> {
    let rules = RuleSet::load()?;
    let content = text.as_bytes();
    let findings = scan::scan_pasted(&rules, content);
    let selected: Vec<_> = findings.iter().collect();
    let hay = Haystack {
        content,
        all: &[content],
    };
    let mut tokens = Vec::new();
    let plan = plan_spans(vault, &hay, &selected, &mut tokens)?;
    let masked = apply(content, &plan);
    let masked = String::from_utf8(masked.to_vec()).map_err(|_| CoreError::TextNotUtf8)?;
    let id = vault.add_session(TEXT_LABEL, tokens, DEFAULT_TTL_DAYS, ScanOptions::default())?;
    vault.save()?;
    Ok((masked, id))
}

/// Replaces every vault token in `text` with its value. The result holds
/// real secrets (the GUI shows the clipboard warning). `session` defaults
/// to the newest `"text"` session; a clean restore forgets it unless
/// `keep` (D58 note, D60).
pub fn restore_text(
    text: &str,
    vault: &mut Vault,
    session: Option<&SessionId>,
    keep: bool,
) -> Result<(String, RestoreReport)> {
    let session = require_session(vault, session, Some(TEXT_LABEL))?;
    let rules = RuleSet::load()?;
    let content = text.as_bytes();
    let new_secrets = scan::scan_pasted(&rules, content);
    let mut restored = replace_tokens(content, vault);
    if std::str::from_utf8(&restored.bytes).is_err() {
        return Err(CoreError::TextNotUtf8);
    }
    let bytes = std::mem::take(&mut *restored.bytes);
    let out = String::from_utf8(bytes).map_err(|_| CoreError::TextNotUtf8)?;
    let mut unknown = restored.unknown;
    unknown.sort();
    unknown.dedup();
    let report = RestoreReport {
        tokens_replaced: restored.seen.len(),
        new_secrets,
        unknown,
        ..RestoreReport::default()
    };
    let report = finish(vault, session, keep, report, &restored.seen)?;
    Ok((out, report))
}

#[cfg(test)]
mod tests;
