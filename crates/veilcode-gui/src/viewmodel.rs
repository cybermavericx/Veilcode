//! What the screens display: ids, paths, counts and D25 previews only, so
//! `Debug` of any of these can never print a secret value (G2). Text Mode
//! is the one exception and does not use these types.

use std::collections::{BTreeMap, BTreeSet};
use veilcode_core::{Finding, KeptReason, MaskReport, RestoreReport, Session, VaultStatus};

/// One finding as shown in the review list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub id: String,
    pub preview: String,
    pub rel_path: String,
    pub line: usize,
    /// The key name for D2/D3/D5 findings, otherwise the rule id.
    pub key_or_rule: String,
    pub ticked: bool,
    pub ignored: bool,
}

impl FindingRow {
    fn new(f: &Finding, ticked: bool) -> Self {
        FindingRow {
            id: f.id.clone(),
            preview: f.preview.clone(),
            rel_path: f.rel_path.clone(),
            line: f.line,
            key_or_rule: f.key_name.clone().unwrap_or_else(|| f.rule_id.clone()),
            ticked,
            ignored: f.ignored.is_some(),
        }
    }
}

/// Findings that share a key name or rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewGroup {
    pub label: String,
    pub rows: Vec<FindingRow>,
}

/// The review dialog (D80).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewView {
    pub groups: Vec<ReviewGroup>,
    /// Findings the profile ignores ("Ignored (false positives)").
    pub ignored: Vec<FindingRow>,
    /// Number of ticked findings.
    pub selected: usize,
    pub confirm_label: String,
}

/// The confirm button text for `n` selected findings.
pub fn confirm_label(n: usize) -> String {
    format!("Mask {n} secrets")
}

/// Builds the review model; `ticked` is the current selection.
pub fn review_view(findings: &[Finding], ticked: &BTreeSet<String>) -> ReviewView {
    let mut groups: BTreeMap<String, Vec<FindingRow>> = BTreeMap::new();
    let mut ignored = Vec::new();
    for f in findings {
        let row = FindingRow::new(f, ticked.contains(&f.id));
        if row.ignored {
            ignored.push(row);
        } else {
            groups.entry(row.key_or_rule.clone()).or_default().push(row);
        }
    }
    let selected = findings.iter().filter(|f| ticked.contains(&f.id)).count();
    ReviewView {
        groups: groups
            .into_iter()
            .map(|(label, rows)| ReviewGroup { label, rows })
            .collect(),
        ignored,
        selected,
        confirm_label: confirm_label(selected),
    }
}

/// The mask result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskView {
    pub session_id: String,
    pub files_written: usize,
    pub secrets_masked: usize,
    pub tokens: usize,
    pub ignored_by_profile: usize,
    pub not_copied: usize,
    /// Set when the mask went into a separate per-project vault (D64).
    pub vault: Option<String>,
}

/// Builds the mask result model.
pub fn mask_view(r: &MaskReport, vault: Option<String>) -> MaskView {
    MaskView {
        session_id: r.session_id.as_str().to_string(),
        files_written: r.files_written,
        secrets_masked: r.secrets_masked,
        tokens: r.tokens,
        ignored_by_profile: r.ignored_by_profile,
        not_copied: r.not_copied.len(),
        vault,
    }
}

/// The restore result (also used for Text Mode restore counts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreView {
    pub files_written: usize,
    pub tokens_replaced: usize,
    pub new_secrets: Vec<FindingRow>,
    pub ignored_new_secrets: usize,
    pub unknown: usize,
    pub missing: usize,
    pub not_copied: usize,
    pub tokens_in_unscanned: usize,
    pub session_forgotten: bool,
    /// "session forgotten" or why the session was kept (D60).
    pub outcome: String,
}

/// Builds the restore result model.
pub fn restore_view(r: &RestoreReport) -> RestoreView {
    RestoreView {
        files_written: r.files_written,
        tokens_replaced: r.tokens_replaced,
        new_secrets: r
            .new_secrets
            .iter()
            .map(|f| FindingRow::new(f, false))
            .collect(),
        ignored_new_secrets: r.ignored_new_secrets,
        unknown: r.unknown.len(),
        missing: r.missing.len(),
        not_copied: r.not_copied.len(),
        tokens_in_unscanned: r.tokens_in_unscanned,
        session_forgotten: r.session_forgotten,
        outcome: outcome(r),
    }
}

fn outcome(r: &RestoreReport) -> String {
    match (&r.kept_reason, r.session_forgotten) {
        (_, true) => "session forgotten".to_string(),
        (Some(KeptReason::KeepRequested), _) => "session kept: keep requested".to_string(),
        (
            Some(KeptReason::NotClean {
                missing,
                unknown,
                new_secrets,
                not_copied,
                tokens_in_unscanned,
            }),
            _,
        ) => format!(
            "session kept: not clean ({missing} missing, {unknown} unknown, \
             {new_secrets} new secrets, {not_copied} not copied, \
             {tokens_in_unscanned} tokens in unscanned files)"
        ),
        (None, false) => "session kept".to_string(),
    }
}

/// One row of the Sessions screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub label: String,
    pub age: String,
    pub expires_in: String,
    pub tokens: usize,
}

/// The Sessions screen (D63).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionsView {
    pub rows: Vec<SessionRow>,
    pub summary: String,
}

/// Builds the Sessions screen model at time `now` (unix seconds).
pub fn sessions_view(sessions: &[Session], status: &VaultStatus, now: u64) -> SessionsView {
    let rows = sessions
        .iter()
        .map(|s| SessionRow {
            id: s.id.as_str().to_string(),
            label: s.source_label.clone(),
            age: duration(now.saturating_sub(s.created)),
            expires_in: duration(s.expires_at.saturating_sub(now)),
            tokens: s.tokens.len(),
        })
        .collect();
    let oldest = status
        .oldest_created
        .map_or("-".to_string(), |c| duration(now.saturating_sub(c)));
    let next = status
        .next_expiry
        .map_or("-".to_string(), |e| duration(e.saturating_sub(now)));
    SessionsView {
        rows,
        summary: format!(
            "{} sessions; oldest {oldest} old; next expiry in {next}",
            status.sessions
        ),
    }
}

/// `secs` as "Nd Nh", "Nh Nm" or "Nm".
pub fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::duration;

    #[test]
    fn duration_formats() {
        assert_eq!(duration(59), "0m");
        assert_eq!(duration(3 * 3600 + 120), "3h 2m");
        assert_eq!(duration(2 * 86_400 + 5 * 3600), "2d 5h");
    }
}
