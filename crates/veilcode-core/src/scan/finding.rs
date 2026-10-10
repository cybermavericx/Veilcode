//! Finding and ScanReport (SPEC §5, D12, D13). None of these types can hold a
//! secret value: only offsets, ids, names, hashes and D25 previews.

use crate::hex;
use crate::scan::ScanOptions;
use crate::scan::detect::Candidate;
use crate::secret::SecretBytes;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Which detector produced a finding, in SPEC §5 run order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Detector {
    /// gitleaks rules.
    D1,
    /// env files.
    D2,
    /// PHP `define`.
    D3,
    /// URL credentials.
    D4,
}

/// One detected secret, located by byte offsets. Never contains the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// First 16 hex chars of sha256("rel_path|start|end|rule_id").
    pub id: String,
    /// `/`-separated path relative to the input root.
    pub rel_path: String,
    /// 1-based line of `start`.
    pub line: usize,
    /// 1-based byte column of `start`.
    pub column: usize,
    /// Byte offset of the first secret byte.
    pub start: usize,
    /// Byte offset one past the last secret byte.
    pub end: usize,
    /// gitleaks rule id, or the D2–D4 rule id (D37).
    pub rule_id: String,
    /// The detector.
    pub detector: Detector,
    /// The key name for D2/D3.
    pub key_name: Option<String>,
    /// D25 preview of the value.
    pub preview: String,
    /// Lowercase hex sha256 of the whole file at scan time.
    pub file_sha256: String,
}

/// A text file that was scanned, with its hash (D13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScannedFile {
    /// `/`-separated relative path.
    pub rel_path: String,
    /// Lowercase hex sha256 of the file content.
    pub sha256: String,
}

/// Files that were not scanned, by reason (relative paths).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// A NUL byte in the first 8 KiB.
    pub binary: Vec<String>,
    /// Larger than 5 MiB.
    pub oversized: Vec<String>,
    /// Symlinks (never followed).
    pub symlink: Vec<String>,
    /// `.git`, default excludes, `.veilcodeignore` matches, special files.
    pub excluded: Vec<String>,
    /// Changed between the walk and the open (D45).
    pub changed_during_scan: Vec<String>,
    /// Names that are not valid UTF-8, shown escaped (D46).
    pub non_utf8_name: Vec<String>,
}

/// The result of a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// Findings sorted by (rel_path, start).
    pub findings: Vec<Finding>,
    /// Every text file, sorted by rel_path.
    pub scanned_files: Vec<ScannedFile>,
    /// Skipped files.
    pub skipped: Skipped,
    /// Rule-load and ignore-file warnings (never contain values).
    pub warnings: Vec<String>,
    /// The options the scan ran with; mask re-walks with these (D51).
    pub options: ScanOptions,
}

/// SPEC §5 finding id.
pub(crate) fn finding_id(rel_path: &str, start: usize, end: usize, rule_id: &str) -> String {
    let digest = Sha256::digest(format!("{rel_path}|{start}|{end}|{rule_id}").as_bytes());
    let mut id = hex::encode(&digest);
    id.truncate(16);
    id
}

/// Sorted newline offsets of one file, for O(log n) line/column lookups (D42).
pub(crate) struct LineIndex(Vec<usize>);

impl LineIndex {
    pub(crate) fn new(content: &[u8]) -> Self {
        let newlines = content.iter().enumerate().filter(|(_, b)| **b == b'\n');
        LineIndex(newlines.map(|(i, _)| i).collect())
    }

    /// 1-based line and 1-based byte column of `offset` (D12).
    pub(crate) fn line_col(&self, offset: usize) -> (usize, usize) {
        let before = self.0.partition_point(|&nl| nl < offset);
        let line_start = if before == 0 {
            0
        } else {
            self.0[before - 1] + 1
        };
        (before + 1, offset - line_start + 1)
    }
}

/// One text file being turned into findings.
pub(crate) struct FileCtx<'a> {
    pub(crate) rel_path: &'a str,
    pub(crate) content: &'a [u8],
    pub(crate) sha256: &'a str,
    pub(crate) lines: &'a LineIndex,
}

/// Builds the Finding for an accepted candidate.
pub(crate) fn build(file: &FileCtx<'_>, c: &Candidate) -> Finding {
    let (rel_path, content, file_sha256) = (file.rel_path, file.content, file.sha256);
    let (line, column) = file.lines.line_col(c.start);
    let value = SecretBytes::new(content[c.start..c.end].to_vec());
    Finding {
        id: finding_id(rel_path, c.start, c.end, &c.rule_id),
        rel_path: rel_path.to_string(),
        line,
        column,
        start: c.start,
        end: c.end,
        rule_id: c.rule_id.clone(),
        detector: c.detector,
        key_name: c.key_name.clone(),
        preview: value.preview(),
        file_sha256: file_sha256.to_string(),
    }
}
