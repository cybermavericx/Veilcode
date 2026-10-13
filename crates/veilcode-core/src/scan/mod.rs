//! Scanner (SPEC §5): walk the input read-only, run D1–D5, resolve overlaps,
//! mark profile-ignored findings (D78).

mod detect;
mod finding;
mod resolve;
pub(crate) mod walk;

#[cfg(test)]
mod tests;

use crate::error::Result;
use crate::hex;
use crate::profile::Profile;
pub(crate) use detect::gitleaks::RuleSet;
pub use finding::{Detector, Finding, IgnoreReason, ScanReport, ScannedFile, Skipped, to_json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use walk::Class;

/// Scan options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Also scan `node_modules`, `vendor`, `target`, `.venv`, `venv`, `__pycache__`.
    /// `.git` is always excluded.
    pub no_default_excludes: bool,
}

/// Scans `input` (read-only) and reports findings without values.
/// The profile is only ever the one passed in, never read from `input` (D75).
pub fn scan(input: &Path, opts: &ScanOptions, profile: &Profile) -> Result<ScanReport> {
    let scanner = Scanner::new(profile)?;
    let rules = &scanner.rules;
    let mut report = ScanReport {
        warnings: [rules.warnings.as_slice(), &rules.allowlist_warnings].concat(),
        options: opts.clone(),
        ..ScanReport::default()
    };
    for file in walk::walk(input, opts, &mut report)?.files {
        match walk::classify(&file.path, file.ident)? {
            Class::Binary => report.skipped.binary.push(file.rel_path),
            Class::Oversized => report.skipped.oversized.push(file.rel_path),
            Class::Changed => report.skipped.changed_during_scan.push(file.rel_path),
            Class::Text(content) => scan_text(&scanner, &file, &content, &mut report),
        }
    }
    report
        .findings
        .sort_by(|a, b| (&a.rel_path, a.start).cmp(&(&b.rel_path, b.start)));
    report
        .scanned_files
        .sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    let s = &mut report.skipped;
    for list in [
        &mut s.binary,
        &mut s.oversized,
        &mut s.symlink,
        &mut s.excluded,
        &mut s.changed_during_scan,
        &mut s.non_utf8_name,
    ] {
        list.sort();
    }
    Ok(report)
}

/// The rules and the profile of one scan, compiled once.
pub(crate) struct Scanner<'p> {
    pub(crate) rules: RuleSet,
    extra: detect::custom::ExtraKeys,
    profile: &'p Profile,
}

impl<'p> Scanner<'p> {
    pub(crate) fn new(profile: &'p Profile) -> Result<Scanner<'p>> {
        Ok(Scanner {
            rules: RuleSet::load()?,
            extra: detect::custom::ExtraKeys::new(profile.extra_keys())?,
            profile,
        })
    }
}

/// Scans one text file into `report` (also used by restore).
pub(crate) fn scan_text(
    scanner: &Scanner<'_>,
    file: &walk::FileEntry,
    content: &[u8],
    report: &mut ScanReport,
) {
    let sha256 = hex::encode(&Sha256::digest(content));
    let cands = detect::detect_file(
        &scanner.rules,
        &scanner.extra,
        &file.rel_path,
        &file.file_name,
        content,
    );
    let lines = finding::LineIndex::new(content);
    let ctx = finding::FileCtx {
        rel_path: &file.rel_path,
        content,
        sha256: &sha256,
        lines: &lines,
    };
    for c in resolve::resolve(content, cands) {
        let mut f = finding::build(&ctx, &c);
        f.ignored = scanner.profile.mark(&f);
        report.findings.push(f);
    }
    report.scanned_files.push(ScannedFile {
        rel_path: file.rel_path.clone(),
        sha256,
    });
}

/// Text Mode: D1–D4 on pasted text, with no file-name gating for D2/D3.
/// Findings are sorted by start and never overlap.
pub(crate) fn scan_pasted(rules: &RuleSet, content: &[u8]) -> Vec<Finding> {
    let sha256 = hex::encode(&Sha256::digest(content));
    let cands = detect::detect_all(rules, content);
    let lines = finding::LineIndex::new(content);
    let ctx = finding::FileCtx {
        rel_path: "",
        content,
        sha256: &sha256,
        lines: &lines,
    };
    let found = resolve::resolve(content, cands);
    found.iter().map(|c| finding::build(&ctx, c)).collect()
}
