//! Restore: AI-modified masked folder → new folder with tokens replaced by
//! their values (SPEC §6.2, D29, D55).

use crate::error::{CoreError, Result};
use crate::mask::skipped_paths;
use crate::paths::{self, OutputDir, RelPath};
use crate::report::{KeptReason, RestoreReport};
use crate::scan::walk::{self, Class, FileEntry};
use crate::scan::{self, RuleSet, ScanOptions, ScanReport};
use crate::secret::SecretBytes;
use crate::token::{NAME_MAX, Token, token_regex};
use crate::vault::{Session, SessionId, Vault};
use std::collections::BTreeSet;
use std::path::Path;
use zeroize::Zeroizing;

const PREFIX: &[u8] = b"VEILCODE_";
const HEX_LEN: usize = 8;

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
pub fn restore(
    input: &Path,
    out: &Path,
    vault: &mut Vault,
    session: Option<&SessionId>,
    keep: bool,
) -> Result<RestoreReport> {
    let session = require_session(vault, session, None)?;
    let rules = RuleSet::load()?;
    let mut scanned = ScanReport::default();
    let (dirs, files) = walk_input(input, &session.scan_options, &mut scanned)?;
    let out = OutputDir::prepare(out, input)?;
    let tree = Tree {
        dirs: &dirs,
        files: &files,
        rules: &rules,
    };
    let (report, seen) = restore_tree(&tree, &out, vault, scanned).map_err(|e| out.discard(e))?;
    finish(vault, session, keep, report, &seen)
}

/// The validated walk of the restore input.
struct Tree<'a> {
    dirs: &'a [RelPath],
    files: &'a [InputFile],
    rules: &'a RuleSet,
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
        rules: tree.rules,
        vault,
    };
    for (rel, file) in tree.files {
        restore_file(&ctx, rel, file, &mut scanned, &mut acc)?;
    }
    paths::sync_dirs(out, tree.dirs)?;
    let mut not_copied = skipped_paths(&scanned.skipped);
    not_copied.extend(acc.changed);
    not_copied.sort();
    let mut new_secrets = scanned.findings;
    new_secrets.sort_by(|a, b| (&a.rel_path, a.start).cmp(&(&b.rel_path, b.start)));
    let report = RestoreReport {
        files_written: acc.written,
        tokens_replaced: acc.seen.len(),
        new_secrets,
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
    rules: &'a RuleSet,
    vault: &'a Vault,
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
            scan::scan_text(ctx.rules, file, &content, scanned);
            let restored = replace_tokens(&content, ctx.vault);
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
            let mut counter = TokenCounter::new(ctx.vault);
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
/// and non-overlapping. D29: a match is tried at every `VEILCODE_` offset,
/// and a candidate counts only if it is a vault key.
pub(crate) fn replace_tokens(content: &[u8], vault: &Vault) -> Restored {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(off) = find(&content[from..], PREFIX) {
        let start = from + off;
        match vault_token_at(content, start, vault) {
            Some((end, token, value)) => {
                found.push((start, end, token, value));
                from = end;
            }
            None => from = start + 1,
        }
    }
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
    let unknown = unknown_tokens(content, &spans);
    Restored {
        bytes,
        seen: found.into_iter().map(|f| f.2).collect(),
        unknown,
    }
}

/// The longest possible token: prefix + 24 NAME chars + separator + 8 hex.
const MAX_TOKEN_LEN: usize = PREFIX.len() + NAME_MAX + 1 + HEX_LEN;

/// D71: counts vault tokens (token regex) in a copied file's chunks,
/// carrying the last bytes over so a token split across chunks is found.
struct TokenCounter<'v> {
    vault: &'v Vault,
    tail: Vec<u8>,
    count: usize,
}

impl<'v> TokenCounter<'v> {
    fn new(vault: &'v Vault) -> Self {
        TokenCounter {
            vault,
            tail: Vec::new(),
            count: 0,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        let mut buf = std::mem::take(&mut self.tail);
        let carried = buf.len();
        buf.extend_from_slice(chunk);
        if let Some(re) = token_regex() {
            let vault = self.vault;
            let is_vault_token = |m: &[u8]| {
                let token = std::str::from_utf8(m).ok().and_then(Token::parse);
                token.is_some_and(|t| vault.value(&t).is_some())
            };
            let hits = re.find_iter(&buf).filter(|m| m.end() > carried);
            self.count += hits.filter(|m| is_vault_token(m.as_bytes())).count();
        }
        let keep = buf.len().min(MAX_TOKEN_LEN - 1);
        self.tail = buf[buf.len() - keep..].to_vec();
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The longest vault token starting at `start`, with its end and value.
fn vault_token_at<'v>(
    content: &[u8],
    start: usize,
    vault: &'v Vault,
) -> Option<(usize, Token, &'v SecretBytes)> {
    let name_at = start + PREFIX.len();
    let is_name = |b: &&u8| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b'_';
    let run = content
        .get(name_at..)?
        .iter()
        .take(NAME_MAX)
        .take_while(is_name)
        .count();
    for name_len in (1..=run).rev() {
        let end = name_at + name_len + 1 + HEX_LEN;
        let Some(candidate) = content.get(start..end) else {
            continue;
        };
        let token = std::str::from_utf8(candidate).ok().and_then(Token::parse);
        if let Some(token) = token
            && let Some(value) = vault.value(&token)
        {
            return Some((end, token, value));
        }
    }
    None
}

/// Token-shaped matches that overlap no replaced span (SPEC §6.2 step 3).
fn unknown_tokens(content: &[u8], spans: &[(usize, usize)]) -> Vec<String> {
    let Some(re) = token_regex() else {
        return Vec::new();
    };
    re.find_iter(content)
        .filter(|m| !spans.iter().any(|&(s, e)| m.start() < e && s < m.end()))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .collect()
}

#[cfg(test)]
mod tests;
