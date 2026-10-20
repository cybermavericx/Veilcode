//! Read-only finding viewer (D137): the lines around a finding, read again
//! from the scanned folder with the scanner's path rules. Nothing here
//! launches a program or writes a file. A finding's value is read into the
//! view only by `reveal_finding`, after the user asked for it.

use crate::error::{CoreError, Result};
use crate::hex;
use crate::paths::RelPath;
use crate::scan::walk::{identity, read_wiped};
use crate::scan::{Finding, ScanReport};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Larger files are not shown (D137).
pub const VIEW_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Lines shown before the first and after the last line of the finding.
pub const VIEW_CONTEXT_LINES: usize = 15;
/// The mark shown where a line was cut.
pub const ELLIPSIS: &str = "…";
/// A line without the finding is cut after this many bytes.
const LINE_MAX: usize = 240;
/// Bytes kept on each side of the finding on its line.
const AROUND: usize = 120;
/// A shown value is cut after this many bytes.
const VALUE_MAX: usize = 256;

/// What the viewer can show for one finding.
#[derive(Debug)]
pub enum FindingView {
    /// The context lines.
    Lines(Vec<ViewLine>),
    /// The file is over `VIEW_MAX_BYTES`.
    TooLarge,
    /// The file is not the one that was scanned (sha256 differs).
    Changed,
}

impl FindingView {
    /// Drops (and so wipes) the text of every `Selected` part: back to
    /// offsets and lengths only (D137 hide).
    pub fn hide_values(&mut self) {
        if let FindingView::Lines(lines) = self {
            let parts = lines.iter_mut().flat_map(|l| l.parts.iter_mut());
            for p in parts.filter(|p| p.kind == PartKind::Selected) {
                p.text = Zeroizing::new(String::new());
            }
        }
    }
}

/// One line of the context.
#[derive(Debug)]
pub struct ViewLine {
    /// 1-based line number.
    pub number: usize,
    /// The line holds part of the viewed finding.
    pub hit: bool,
    pub parts: Vec<ViewPart>,
}

/// What a part of a line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PartKind {
    /// File text around the findings.
    Plain,
    /// The `ELLIPSIS` mark where the line was cut.
    Cut,
    /// (Part of) the viewed finding's value; text only after Reveal.
    Selected,
    /// Another finding of the file; its text is never read into the view.
    Other,
}

/// A piece of a line, held in a buffer that is wiped on drop.
pub struct ViewPart {
    pub kind: PartKind,
    /// Where the part is in the file (byte offsets).
    pub start: usize,
    pub end: usize,
    text: Zeroizing<String>,
}

impl ViewPart {
    fn new(kind: PartKind, content: &[u8], start: usize, end: usize) -> ViewPart {
        let text = lossy(&content[start..end]);
        ViewPart {
            kind,
            start,
            end,
            text,
        }
    }

    /// A part whose text is not held: a value (offsets only).
    fn bare(kind: PartKind, start: usize, end: usize) -> ViewPart {
        let text = Zeroizing::new(String::new());
        ViewPart {
            kind,
            start,
            end,
            text,
        }
    }

    fn cut(at: usize) -> ViewPart {
        let text = Zeroizing::new(ELLIPSIS.to_string());
        ViewPart {
            kind: PartKind::Cut,
            start: at,
            end: at,
            text,
        }
    }

    /// The text: empty for `Other`, and for `Selected` until revealed.
    /// File content: show it, never log it.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for ViewPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ViewPart({:?}, {}..{}, <redacted>, len={})",
            self.kind,
            self.start,
            self.end,
            self.text.len()
        )
    }
}

/// `bytes` as lossy UTF-8 (as `String::from_utf8_lossy`) in a wiped buffer
/// sized for the worst case, every byte becoming the 3-byte U+FFFD, so it
/// never reallocates and leaves no unwiped copy behind (Info 2).
fn lossy(bytes: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(3)));
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            text.push(char::REPLACEMENT_CHARACTER);
        }
    }
    text
}

/// The lines around finding `id` of `report`, read from `root` (the folder
/// that was scanned). Every finding span holds offsets only: other findings
/// are `Other` parts, the viewed one `Selected` parts without text.
pub fn view_finding(root: &Path, report: &ScanReport, id: &str) -> Result<FindingView> {
    build(root, report, id, false)
}

/// As `view_finding`, after the user pressed Reveal: the file is read and
/// checked again, and only the `Selected` parts get their text.
pub fn reveal_finding(root: &Path, report: &ScanReport, id: &str) -> Result<FindingView> {
    build(root, report, id, true)
}

fn build(root: &Path, report: &ScanReport, id: &str, reveal: bool) -> Result<FindingView> {
    let f = report.findings.iter().find(|f| f.id == id);
    let f = f.ok_or_else(|| CoreError::UnknownFinding { id: id.to_string() })?;
    let Some(content) = read_view_file(root, &f.rel_path)? else {
        return Ok(FindingView::TooLarge);
    };
    let same_file = hex::encode(&Sha256::digest(&content)) == f.file_sha256;
    if !same_file || f.start >= f.end || f.end > content.len() {
        return Ok(FindingView::Changed);
    }
    let mut spans = vec![(f.start, f.end, PartKind::Selected)];
    let others = report.findings.iter().filter(|o| o.rel_path == f.rel_path);
    for o in others.filter(|o| o.id != f.id && o.start < o.end && o.end <= content.len()) {
        spans.push((o.start, o.end, PartKind::Other));
    }
    spans.sort();
    let text = Text {
        content: &content,
        spans: &spans,
        reveal,
    };
    Ok(FindingView::Lines(context(&text, f)))
}

/// One kind of span over the file: start, end, kind.
type Span = (usize, usize, PartKind);

/// The file and its finding spans (sorted by start).
struct Text<'a> {
    content: &'a [u8],
    spans: &'a [Span],
    /// Fill the `Selected` parts with their text.
    reveal: bool,
}

/// The context lines of `f`, each split into parts.
fn context(text: &Text<'_>, f: &Finding) -> Vec<ViewLine> {
    let lines = line_ranges(text.content);
    let line_of = |at: usize| lines.partition_point(|&(s, _)| s <= at).saturating_sub(1);
    let (first, last) = (line_of(f.start), line_of(f.end - 1));
    let from = first.saturating_sub(VIEW_CONTEXT_LINES);
    let to = (last + VIEW_CONTEXT_LINES).min(lines.len().saturating_sub(1));
    (from..=to)
        .map(|i| {
            let (s, e) = lines[i];
            let parts = line_parts(text, s, e);
            let hit = parts.iter().any(|p| p.kind == PartKind::Selected);
            ViewLine {
                number: i + 1,
                hit,
                parts,
            }
        })
        .collect()
}

/// (start, end) of every line, without `\n` and a `\r` before it. A final
/// line ending does not start another line.
fn line_ranges(content: &[u8]) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, _) in content.iter().enumerate().filter(|(_, b)| **b == b'\n') {
        lines.push((start, trim_cr(content, start, i)));
        start = i + 1;
    }
    if start < content.len() || lines.is_empty() {
        lines.push((start, content.len()));
    }
    lines
}

fn trim_cr(content: &[u8], start: usize, end: usize) -> usize {
    if end > start && content[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

/// The parts of line `s..e`: cut to a window (around the finding on its
/// line, else the first `LINE_MAX` bytes), then split at the spans. A span
/// that overlaps an earlier one is clamped to start after it (L2), so no
/// finding byte is ever a `Plain` part.
fn line_parts(text: &Text<'_>, s: usize, e: usize) -> Vec<ViewPart> {
    let clip = |&(a, b, k): &Span| (a.max(s), b.min(e), k);
    let here: Vec<Span> = text.spans.iter().map(clip).filter(|c| c.0 < c.1).collect();
    let (ws, we) = window(text.content, s, e, &here);
    let mut parts = Vec::new();
    if ws > s {
        parts.push(ViewPart::cut(ws));
    }
    let mut at = ws;
    for &(a, b, kind) in &here {
        let (a, b) = (a.max(at), b.min(we));
        if a >= b {
            continue;
        }
        if a > at {
            parts.push(ViewPart::new(PartKind::Plain, text.content, at, a));
        }
        parts.extend(span_parts(text, a, b, kind));
        at = b;
    }
    if we > at {
        parts.push(ViewPart::new(PartKind::Plain, text.content, at, we));
    }
    if we < e {
        parts.push(ViewPart::cut(we));
    }
    parts
}

/// The shown bytes `ws..we` of line `s..e`, moved onto character starts.
fn window(content: &[u8], s: usize, e: usize, here: &[Span]) -> (usize, usize) {
    let sel = here.iter().find(|c| c.2 == PartKind::Selected);
    let (mut ws, mut we) = match sel {
        Some(&(a, b, _)) => (a.saturating_sub(AROUND).max(s), (b + AROUND).min(e)),
        None => (s, (s + LINE_MAX).min(e)),
    };
    let keep_from = sel.map_or(e, |c| c.0);
    let keep_to = sel.map_or(s, |c| c.1);
    while ws < keep_from && ws < e && is_continuation(content[ws]) {
        ws += 1;
    }
    while we > keep_to && we < e && is_continuation(content[we]) {
        we -= 1;
    }
    (ws, we)
}

fn is_continuation(b: u8) -> bool {
    b & 0xC0 == 0x80
}

/// A span's parts. `Other` never holds text; `Selected` holds it only when
/// revealing, cut after `VALUE_MAX` bytes.
fn span_parts(text: &Text<'_>, a: usize, b: usize, kind: PartKind) -> Vec<ViewPart> {
    let mut end = b.min(a + VALUE_MAX);
    while end > a && end < b && is_continuation(text.content[end]) {
        end -= 1;
    }
    let shown = match kind {
        PartKind::Selected if text.reveal => ViewPart::new(kind, text.content, a, end),
        _ => ViewPart::bare(kind, a, end),
    };
    let mut parts = vec![shown];
    if end < b {
        parts.push(ViewPart::cut(end));
    }
    parts
}

/// D137: reads `rel` under `root` like the scanner would reach it: a valid
/// `rel_path`, real directories (no links) down to a regular file, inside
/// the canonical root, and the opened file is the one that was checked.
/// `None` if it is over `VIEW_MAX_BYTES`.
fn read_view_file(root: &Path, rel: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let checked = RelPath::parse(rel)?;
    let refuse = || CoreError::NotViewable {
        rel_path: rel.to_string(),
    };
    let root = std::fs::canonicalize(root).map_err(|e| CoreError::io(root, &e))?;
    let (path, meta) = walk_down(&root, checked.as_str(), &refuse)?;
    let real = std::fs::canonicalize(&path).map_err(|e| CoreError::io(&path, &e))?;
    if !real.starts_with(&root) {
        return Err(refuse());
    }
    if meta.len() > VIEW_MAX_BYTES as u64 {
        return Ok(None);
    }
    let mut file = open_no_follow(&path).map_err(|e| CoreError::io(&path, &e))?;
    let opened = file.metadata().map_err(|e| CoreError::io(&path, &e))?;
    if !opened.is_file() || is_reparse_point(&opened) || identity(&opened) != identity(&meta) {
        return Err(refuse());
    }
    let hint = usize::try_from(opened.len()).unwrap_or(VIEW_MAX_BYTES);
    let bytes =
        read_wiped(&mut file, hint, VIEW_MAX_BYTES + 1).map_err(|e| CoreError::io(&path, &e))?;
    Ok((bytes.len() <= VIEW_MAX_BYTES).then_some(bytes))
}

/// Opens read-only. On Windows the reparse point itself is opened, never
/// its target (`FILE_FLAG_OPEN_REPARSE_POINT`, L1), so a link swapped in
/// after the checks is refused by `is_reparse_point`.
#[cfg(windows)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Unix: `O_NOFOLLOW | O_NONBLOCK` (Info 4), so a link swapped in for the
/// file is not followed and a FIFO does not block the open; the caller then
/// checks that a regular file was opened. Values from libc 0.2.190
/// (VERIFY_LOG 2026-10-19); libc is not a dependency of this crate.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_OPEN_FLAGS)
        .open(path)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const UNIX_OPEN_FLAGS: i32 = 0x20000 | 0x800;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const UNIX_OPEN_FLAGS: i32 = 0x8000 | 0x800;
#[cfg(target_os = "macos")]
const UNIX_OPEN_FLAGS: i32 = 0x100 | 0x4;
/// Other Unix targets: no extra flags (not a shipped or CI target).
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
const UNIX_OPEN_FLAGS: i32 = 0;

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// Windows: `FILE_ATTRIBUTE_REPARSE_POINT` (L1).
#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Follows `rel` from `root` one component at a time without following
/// links: every parent must be a directory and the last a regular file.
fn walk_down(
    root: &Path,
    rel: &str,
    refuse: &dyn Fn() -> CoreError,
) -> Result<(PathBuf, std::fs::Metadata)> {
    let parts: Vec<&str> = rel.split('/').collect();
    let mut path = root.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| CoreError::io(&path, &e))?;
        let kind = meta.file_type();
        if i + 1 == parts.len() {
            return if kind.is_file() {
                Ok((path, meta))
            } else {
                Err(refuse())
            };
        }
        if !kind.is_dir() {
            return Err(refuse());
        }
    }
    Err(refuse())
}

#[cfg(test)]
mod tests;
