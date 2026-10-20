//! Restore: AI-modified masked folder → new folder with tokens replaced by
//! their values (SPEC §6.2, D29, D55).

use crate::error::{CoreError, Result};
use crate::mask::skipped_paths;
use crate::paths::{self, OutputDir, RelPath};
use crate::profile::Profile;
use crate::report::{KeptReason, RestoreReport};
use crate::scan::walk::{self, Class, FileEntry};
use crate::scan::{self, ScanOptions, ScanReport, Scanner};
use crate::secret::SecretBytes;
use crate::token::{KnownPrefixes, MAX_TOKEN_LEN, Token, shape_ends};
use crate::vault::{Session, SessionId, Vault};
use std::collections::BTreeSet;
use std::path::Path;
use zeroize::Zeroizing;

/// A walked regular file with its validated path.
type InputFile = (RelPath, FileEntry);

/// One text with its tokens replaced.
pub(crate) struct Restored {
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    /// Vault tokens that were replaced, one per occurrence.
    pub(crate) seen: Vec<Token>,
    /// Token-shaped strings not in the vault.
    pub(crate) unknown: Vec<String>,
}

/// Restores `input` into a new `out` (SPEC §6.2). Every vault token is
/// replaced; `session` (default: newest, D53) decides the walk options
/// (D57r) and what counts as missing. A clean restore forgets the session
/// unless `keep` (D60), and only after every output is written and synced.
/// New secrets the `profile` ignores are only counted (D78).
pub fn restore(
    input: &Path,
    out: &Path,
    vault: &mut Vault,
    session: Option<&SessionId>,
    keep: bool,
    profile: &Profile,
) -> Result<RestoreReport> {
    let session = require_session(vault, session, None)?;
    let scanner = Scanner::with_prefixes(profile, vault.known_prefixes())?;
    let mut scanned = ScanReport::default();
    let (dirs, files) = walk_input(input, &session.scan_options, &mut scanned)?;
    let out = OutputDir::prepare(out, input)?;
    let tree = Tree {
        dirs: &dirs,
        files: &files,
        scanner: &scanner,
    };
    let (report, seen) = restore_tree(&tree, &out, vault, scanned).map_err(|e| out.discard(e))?;
    finish(vault, session, keep, report, &seen)
}

/// The validated walk of the restore input.
struct Tree<'a> {
    dirs: &'a [RelPath],
    files: &'a [InputFile],
    scanner: &'a Scanner<'a>,
}

/// Writes and syncs the whole output; session fields are left unset.
fn restore_tree(
    tree: &Tree<'_>,
    out: &OutputDir,
    vault: &Vault,
    mut scanned: ScanReport,
) -> Result<(RestoreReport, Vec<Token>)> {
    for dir in tree.dirs {
        paths::create_dir(out, dir)?;
    }
    let mut acc = Totals::default();
    let ctx = FileCtx {
        out,
        scanner: tree.scanner,
        vault,
        known: tree.scanner.known(),
    };
    for (rel, file) in tree.files {
        restore_file(&ctx, rel, file, &mut scanned, &mut acc)?;
    }
    paths::sync_dirs(out, tree.dirs)?;
    let mut not_copied = skipped_paths(&scanned.skipped);
    not_copied.extend(acc.changed);
    not_copied.sort();
    // D78: secrets the profile ignores are counted, not reported as new.
    let (ignored, mut new_secrets): (Vec<_>, Vec<_>) = scanned
        .findings
        .into_iter()
        .partition(|f| f.ignored.is_some());
    new_secrets.sort_by(|a, b| (&a.rel_path, a.start).cmp(&(&b.rel_path, b.start)));
    let report = RestoreReport {
        files_written: acc.written,
        tokens_replaced: acc.seen.len(),
        new_secrets,
        ignored_new_secrets: ignored.len(),
        unknown: acc.unknown.into_iter().collect(),
        not_copied,
        tokens_in_unscanned: acc.tokens_in_unscanned,
        ..RestoreReport::default()
    };
    Ok((report, acc.seen))
}

/// The walk, with every path validated before anything is written.
fn walk_input(
    input: &Path,
    opts: &ScanOptions,
    scanned: &mut ScanReport,
) -> Result<(Vec<RelPath>, Vec<InputFile>)> {
    let walked = walk::walk(input, opts, scanned)?;
    let dirs = walked
        .dirs
        .iter()
        .map(|d| RelPath::parse(d))
        .collect::<Result<_>>()?;
    let files = walked
        .files
        .into_iter()
        .map(|f| Ok((RelPath::parse(&f.rel_path)?, f)))
        .collect::<Result<_>>()?;
    Ok((dirs, files))
}

/// The given session (unknown id: error), or the newest by (created, id)
/// among sessions with `label` (if given). D73: none at all is an error.
pub(crate) fn require_session(
    vault: &Vault,
    id: Option<&SessionId>,
    label: Option<&str>,
) -> Result<Session> {
    let sessions = vault.sessions();
    let Some(id) = id else {
        let candidates = sessions
            .iter()
            .filter(|s| label.is_none_or(|l| s.source_label == l));
        let newest = candidates.max_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        return newest.cloned().ok_or(CoreError::NoSession);
    };
    match sessions.iter().find(|s| &s.id == id) {
        Some(s) => Ok(s.clone()),
        None => Err(CoreError::UnknownSession {
            id: id.as_str().to_string(),
        }),
    }
}

/// Fills the session fields and applies D60/D71: forget only if clean and
/// not `keep`. Runs after all outputs are written (any earlier error
/// returns before this, leaving the vault untouched).
pub(crate) fn finish(
    vault: &mut Vault,
    session: Session,
    keep: bool,
    mut report: RestoreReport,
    seen: &[Token],
) -> Result<RestoreReport> {
    report.missing = missing(&session, seen);
    report.session_id = Some(session.id.clone());
    let distinct: BTreeSet<&Token> = seen.iter().collect();
    report.foreign_session_tokens = distinct
        .iter()
        .filter(|t| !session.tokens.contains(t))
        .count();
    let counts = [
        report.missing.len(),
        report.unknown.len(),
        report.new_secrets.len(),
        report.not_copied.len(),
        report.tokens_in_unscanned,
    ];
    if keep {
        report.kept_reason = Some(KeptReason::KeepRequested);
    } else if counts.iter().any(|&n| n > 0) {
        let [
            missing,
            unknown,
            new_secrets,
            not_copied,
            tokens_in_unscanned,
        ] = counts;
        report.kept_reason = Some(KeptReason::NotClean {
            missing,
            unknown,
            new_secrets,
            not_copied,
            tokens_in_unscanned,
        });
    } else {
        vault.forget(&session.id)?;
        report.session_forgotten = true;
    }
    Ok(report)
}

/// SPEC §6.2 step 4: the session's tokens that never appeared, sorted.
fn missing(session: &Session, seen: &[Token]) -> Vec<Token> {
    let seen: BTreeSet<&Token> = seen.iter().collect();
    let gone = session.tokens.iter().filter(|t| !seen.contains(t));
    let missing: BTreeSet<&Token> = gone.collect();
    missing.into_iter().cloned().collect()
}

#[derive(Default)]
struct Totals {
    written: usize,
    seen: Vec<Token>,
    unknown: BTreeSet<String>,
    changed: Vec<String>,
    tokens_in_unscanned: usize,
}

struct FileCtx<'a> {
    out: &'a OutputDir,
    scanner: &'a Scanner<'a>,
    vault: &'a Vault,
    known: &'a KnownPrefixes,
}

/// Restores one file: text gets tokens replaced (and is scanned for new
/// secrets), other regular files are copied as-is (SPEC §6.2 steps 2, 3, 5).
fn restore_file(
    ctx: &FileCtx<'_>,
    rel: &RelPath,
    file: &FileEntry,
    scanned: &mut ScanReport,
    acc: &mut Totals,
) -> Result<()> {
    match walk::classify(&file.path, file.ident)? {
        Class::Text(content) => {
            scan::scan_text(ctx.scanner, file, &content, scanned);
            let restored = replace_tokens(&content, ctx.vault, ctx.known);
            // D55: a file that received a real value is owner-only.
            let mode = if restored.seen.is_empty() {
                file.mode
            } else {
                file.mode & 0o700
            };
            paths::write_new(ctx.out, rel, &restored.bytes, mode)?;
            acc.seen.extend(restored.seen);
            acc.unknown.extend(restored.unknown);
        }
        Class::Binary | Class::Oversized => {
            let mut counter = TokenCounter::new(ctx.vault, ctx.known);
            paths::copy_new(ctx.out, rel, file, &mut |chunk| counter.feed(chunk))?;
            acc.tokens_in_unscanned += counter.count;
        }
        Class::Changed => {
            acc.changed.push(file.rel_path.clone());
            return Ok(());
        }
    }
    acc.written += 1;
    Ok(())
}

/// Replaces every vault token in `content` with its value, left to right
/// and non-overlapping. D29, D138: a match is tried at every offset where a
/// `known` prefix starts, and a candidate counts only if it is a vault key.
pub(crate) fn replace_tokens(content: &[u8], vault: &Vault, known: &KnownPrefixes) -> Restored {
    let found = vault_tokens(content, vault, known);
    // L1: exact size, so a buffer holding values never reallocates.
    let grow: usize = found.iter().map(|f| f.3.len()).sum();
    let shrink: usize = found.iter().map(|f| f.1 - f.0).sum();
    let mut bytes = Zeroizing::new(Vec::with_capacity(content.len() + grow - shrink));
    let mut copied = 0;
    for (start, end, _, value) in &found {
        bytes.extend_from_slice(&content[copied..*start]);
        bytes.extend_from_slice(value.expose());
        copied = *end;
    }
    bytes.extend_from_slice(&content[copied..]);
    let spans: Vec<(usize, usize)> = found.iter().map(|f| (f.0, f.1)).collect();
    let unknown = unknown_tokens(content, &spans, known);
    Restored {
        bytes,
        seen: found.into_iter().map(|f| f.2).collect(),
        unknown,
    }
}

/// One vault token found in a text: start, end, token and value.
type Found<'v> = (usize, usize, Token, &'v SecretBytes);

/// Every vault token in `content`, left to right and non-overlapping.
fn vault_tokens<'v>(content: &[u8], vault: &'v Vault, known: &KnownPrefixes) -> Vec<Found<'v>> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(start) = known.next_start(content, from) {
        match vault_token_at(content, start, vault, known) {
            Some((end, token, value)) => {
                found.push((start, end, token, value));
                from = end;
            }
            None => from = start + 1,
        }
    }
    found
}

/// D71: counts vault tokens in a copied file's chunks, carrying the last
/// `MAX_TOKEN_LEN - 1` bytes over so a token split across chunks is found.
struct TokenCounter<'v> {
    vault: &'v Vault,
    known: &'v KnownPrefixes,
    tail: Vec<u8>,
    count: usize,
}

impl<'v> TokenCounter<'v> {
    fn new(vault: &'v Vault, known: &'v KnownPrefixes) -> Self {
        TokenCounter {
            vault,
            known,
            tail: Vec::new(),
            count: 0,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        let mut buf = std::mem::take(&mut self.tail);
        let carried = buf.len();
        buf.extend_from_slice(chunk);
        let hits = vault_tokens(&buf, self.vault, self.known);
        self.count += hits.iter().filter(|f| f.1 > carried).count();
        let keep = buf.len().min(MAX_TOKEN_LEN - 1);
        self.tail = buf[buf.len() - keep..].to_vec();
    }
}

/// The longest vault token at offset `start`, over every known prefix that
/// starts there, with its end and value.
fn vault_token_at<'v>(
    content: &[u8],
    start: usize,
    vault: &'v Vault,
    known: &KnownPrefixes,
) -> Option<(usize, Token, &'v SecretBytes)> {
    let mut best: Option<(usize, Token, &'v SecretBytes)> = None;
    for prefix in known.at(content, start) {
        let name_at = start + prefix.as_str().len();
        let hit = shape_ends(content, name_at, prefix)
            .into_iter()
            .find_map(|end| {
                let text = std::str::from_utf8(&content[start..end]).ok()?;
                let token = Token::parse_with(text, prefix)?;
                vault.value(&token).map(|v| (end, token, v))
            });
        if let Some(hit) = hit
            && best.as_ref().is_none_or(|b| hit.0 > b.0)
        {
            best = Some(hit);
        }
    }
    best
}

/// Token-shaped strings of a known prefix that overlap no replaced span
/// (SPEC §6.2 step 3); at each start, the longest shape is taken.
fn unknown_tokens(content: &[u8], spans: &[(usize, usize)], known: &KnownPrefixes) -> Vec<String> {
    let mut unknown = Vec::new();
    let mut from = 0;
    while let Some(start) = known.next_start(content, from) {
        let ends = known.at(content, start).filter_map(|p| {
            let name_at = start + p.as_str().len();
            shape_ends(content, name_at, p).first().copied()
        });
        let Some(end) = ends.max() else {
            from = start + 1;
            continue;
        };
        if !spans.iter().any(|&(s, e)| start < e && s < end) {
            unknown.push(String::from_utf8_lossy(&content[start..end]).into_owned());
        }
        from = end;
    }
    unknown
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod prefix_tests;
