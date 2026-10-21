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
    /// Findings skipped because they already were tokens (D138).
    pub already_tokens: usize,
    pub not_copied: usize,
    /// The output folder.
    pub out: String,
    /// Set when the mask went into a separate per-project vault (D64).
    pub vault: Option<String>,
}

/// Builds the mask result model.
pub fn mask_view(r: &MaskReport, out: String, vault: Option<String>) -> MaskView {
    MaskView {
        session_id: r.session_id.as_str().to_string(),
        files_written: r.files_written,
        secrets_masked: r.secrets_masked,
        tokens: r.tokens,
        ignored_by_profile: r.ignored_by_profile,
        already_tokens: r.already_tokens,
        not_copied: r.not_copied.len(),
        out,
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
    /// The output folder (`None` for Text Mode).
    pub out: Option<String>,
}

/// Builds the restore result model.
pub fn restore_view(r: &RestoreReport, out: Option<String>) -> RestoreView {
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
        out,
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

/// The one-line hint on the Unlock screen (D127).
pub const UNLOCK_HINT: &str =
    "Create or open a vault first. The other tabs become available after that.";

/// Labels of the vault password fields (D144).
pub const PASS_LABEL: &str = "Vault password:";
pub const CONFIRM_LABEL: &str = "Repeat vault password:";
pub const SEPARATE_PASS_LABEL: &str = "Its vault password:";

/// The line under the profile field (D144).
pub const PROFILE_HINT: &str = "The profile tunes detection: extra key names to find and findings to ignore. \
     It is a plain text file that holds key names and file paths, never secret values.";

/// The header byline after the tagline (D144).
pub const BYLINE: &str = "by Cybermavericx";

/// The licence, as `Cargo.toml` states it.
const LICENSE: &str = env!("CARGO_PKG_LICENSE");

/// The right side of the status bar (D144).
pub fn status_line() -> String {
    format!(
        "Veilcode {} · Open source ({LICENSE})",
        env!("CARGO_PKG_VERSION")
    )
}

/// The About section of the Help screen (D144). The copyright line is the
/// one in `LICENSE-MIT`; no links (D127).
pub fn about_lines() -> Vec<String> {
    vec![
        format!("Veilcode {}", env!("CARGO_PKG_VERSION")),
        "Open source: licensed under either of the Apache License, Version 2.0 \
         or the MIT license, at your option."
            .to_string(),
        "Copyright (c) 2026 Muhammed Noufal (Cybermavericx)".to_string(),
        "Third-party licences are listed in THIRD_PARTY_NOTICES, installed with Veilcode."
            .to_string(),
    ]
}

/// The "How Veilcode works" guide and the Help screen (D127). Fixed text
/// and default file locations only: no values and no links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guide {
    pub steps: [&'static str; 5],
    pub safety: [&'static str; 4],
    pub storage: Vec<String>,
}

/// Builds the guide; `vault` and `profile` are the default locations.
pub fn guide(vault: Option<&std::path::Path>, profile: Option<&std::path::Path>) -> Guide {
    let at = |p: Option<&std::path::Path>| {
        p.map_or("no default location on this system".to_string(), |p| {
            p.display().to_string()
        })
    };
    Guide {
        steps: [
            "Create or open a vault. It holds the real values, encrypted with a key derived from your vault password.",
            "Scan a project folder.",
            "Review what will be masked, and untick false positives.",
            "Mask into a new folder, then give that folder to the AI.",
            "Restore the AI's folder into another new folder.",
        ],
        safety: [
            "Your input folder is never modified.",
            "Every output must be a new folder that does not exist yet.",
            "Keep the vault and the profile outside the project folder.",
            "Try Veilcode first with a throwaway copy of a project.",
        ],
        storage: vec![
            format!("Default vault: {}", at(vault)),
            format!("Default profile: {}", at(profile)),
        ],
    }
}

/// The five workflow steps of the rail (D131).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Vault,
    Scan,
    Review,
    Mask,
    Restore,
}

impl Step {
    pub const ALL: [Step; 5] = [
        Step::Vault,
        Step::Scan,
        Step::Review,
        Step::Mask,
        Step::Restore,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Step::Vault => "Vault",
            Step::Scan => "Scan",
            Step::Review => "Review",
            Step::Mask => "Mask",
            Step::Restore => "Restore",
        }
    }
}

/// How a rail step is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    /// Finished in this unlocked session.
    Done,
    /// Must be finished before the later steps open: the vault while
    /// locked, the review of an unconfirmed scan (D80).
    Current,
    /// Can be started.
    Available,
    /// Needs an earlier step first.
    Locked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailStep {
    pub step: Step,
    /// 1 to 5.
    pub number: usize,
    pub state: StepState,
}

/// The step rail under the header (D131).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRail {
    pub steps: Vec<RailStep>,
}

#[cfg(test)]
impl WorkflowRail {
    /// The state of `step`.
    pub fn state(&self, step: Step) -> StepState {
        self.steps
            .iter()
            .find(|s| s.step == step)
            .map_or(StepState::Locked, |s| s.state)
    }
}

/// What the app state knows about the workflow.
#[derive(Debug, Clone, Copy, Default)]
pub struct Progress {
    pub unlocked: bool,
    pub scanned: bool,
    pub confirmed: bool,
    /// The current scan was masked.
    pub masked: bool,
    pub restored: bool,
}

/// Derives the rail from `p`.
pub fn workflow_rail(p: &Progress) -> WorkflowRail {
    let steps = Step::ALL
        .iter()
        .enumerate()
        .map(|(i, &step)| RailStep {
            step,
            number: i + 1,
            state: step_state(step, p),
        })
        .collect();
    WorkflowRail { steps }
}

fn step_state(step: Step, p: &Progress) -> StepState {
    use StepState::{Available, Current, Done, Locked};
    let done = match step {
        Step::Vault => p.unlocked,
        Step::Scan => p.unlocked && p.scanned,
        Step::Review => p.scanned && (p.confirmed || p.masked),
        Step::Mask => p.masked && !p.confirmed,
        Step::Restore => p.unlocked && p.restored,
    };
    let open = match step {
        Step::Vault => true,
        Step::Scan | Step::Restore => p.unlocked,
        Step::Review => p.scanned,
        Step::Mask => p.confirmed,
    };
    let gate = matches!(step, Step::Vault | Step::Review);
    match (done, open) {
        (true, _) => Done,
        (false, false) => Locked,
        (false, true) if gate => Current,
        (false, true) => Available,
    }
}

/// A result card under an action (D131): counts, folders and outcomes,
/// never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultCard {
    pub error: bool,
    pub title: String,
    /// The folder the result is in, with its label.
    pub folder: Option<(&'static str, String)>,
    pub lines: Vec<String>,
    /// The "Next: <step>" button.
    pub next: Option<Step>,
}

/// The card after a scan.
pub fn scan_card(input: &str, files: usize, findings: usize) -> ResultCard {
    ResultCard {
        error: false,
        title: format!("Scanned {files} files: {findings} findings"),
        folder: Some(("Scanned folder", input.to_string())),
        lines: vec!["Review what will be masked before masking.".to_string()],
        next: Some(Step::Review),
    }
}

/// The card after a mask.
pub fn mask_card(m: &MaskView) -> ResultCard {
    let mut lines = vec![
        "Give this folder to the AI.".to_string(),
        format!("Session {}", m.session_id),
        format!("Tokens: {}", m.tokens),
        format!("Ignored by profile (not masked): {}", m.ignored_by_profile),
        format!(
            "Already placeholder tokens (not masked again): {}",
            m.already_tokens
        ),
        format!("Files not copied (binary or oversized): {}", m.not_copied),
    ];
    if let Some(v) = &m.vault {
        lines.push(format!("Stored in the separate vault {v}"));
    }
    ResultCard {
        error: false,
        title: format!(
            "Masked {} secrets; wrote {} files",
            m.secrets_masked, m.files_written
        ),
        folder: Some(("Output folder", m.out.clone())),
        lines,
        next: Some(Step::Restore),
    }
}

/// The card after a folder restore.
pub fn restore_card(r: &RestoreView) -> ResultCard {
    ResultCard {
        error: false,
        title: format!(
            "Restored {} tokens; wrote {} files",
            r.tokens_replaced, r.files_written
        ),
        folder: r.out.clone().map(|o| ("Output folder", o)),
        lines: vec![
            r.outcome.clone(),
            format!("New secrets (added since masking): {}", r.new_secrets.len()),
            format!("New secrets ignored by profile: {}", r.ignored_new_secrets),
            format!("Unknown tokens: {}", r.unknown),
            format!("Missing tokens: {}", r.missing),
            format!("Files not copied: {}", r.not_copied),
            format!("Tokens in unscanned files: {}", r.tokens_in_unscanned),
        ],
        next: None,
    }
}

/// An error in the card style. `msg` is a `GuiError` text (no values).
pub fn error_card(msg: String) -> ResultCard {
    ResultCard {
        error: true,
        title: msg,
        folder: None,
        lines: Vec::new(),
        next: None,
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
