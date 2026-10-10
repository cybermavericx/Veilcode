//! Scanner (SPEC §5): walk the input read-only, run D1–D4, resolve overlaps.

mod detect;
mod finding;
mod resolve;
pub(crate) mod walk;

#[cfg(test)]
mod tests;

use crate::error::Result;
use crate::hex;
pub(crate) use detect::gitleaks::RuleSet;
pub use finding::{Detector, Finding, ScanReport, ScannedFile, Skipped};
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
pub fn scan(input: &Path, opts: &ScanOptions) -> Result<ScanReport> {
    let rules = RuleSet::load()?;
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
            Class::Text(content) => scan_text(&rules, &file, &content, &mut report),
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

/// Scans one text file into `report` (also used by restore).
pub(crate) fn scan_text(
    rules: &RuleSet,
    file: &walk::FileEntry,
    content: &[u8],
    report: &mut ScanReport,
) {
    let sha256 = hex::encode(&Sha256::digest(content));
    let cands = detect::detect_file(rules, &file.rel_path, &file.file_name, content);
    let lines = finding::LineIndex::new(content);
    let ctx = finding::FileCtx {
        rel_path: &file.rel_path,
        content,
        sha256: &sha256,
        lines: &lines,
    };
    for c in resolve::resolve(content, cands) {
        report.findings.push(finding::build(&ctx, &c));
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
