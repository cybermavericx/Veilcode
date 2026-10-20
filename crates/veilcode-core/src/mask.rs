//! Mask: input folder → new folder with secrets replaced by tokens (SPEC §6.1).

use crate::error::{CoreError, Result};
use crate::hex;
use crate::paths::{self, OutputDir, RelPath};
use crate::report::MaskReport;
use crate::scan::walk::{self, Class, FileEntry};
use crate::scan::{Finding, ScanReport, Skipped};
use crate::secret::SecretBytes;
use crate::token::{KnownPrefixes, Token, TokenPrefix};
use crate::vault::{DEFAULT_TTL_DAYS, ProjectKey, Vault, ttl_secs};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zeroize::Zeroizing;

/// Which findings to mask (D51).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Selection {
    /// The default: every finding the profile does not ignore (D78).
    #[default]
    All,
    /// Only these finding ids, ignored ones included (user override, D78).
    Ids(BTreeSet<String>),
}

/// Mask options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskOptions {
    /// Also copy binary and oversized files (never symlinks or excluded paths).
    pub include_unscanned: bool,
    /// Session lifetime in days, 1–365 (D61).
    pub ttl_days: u32,
    /// The placeholder prefix of new tokens (D138; default `VEILCODE_`).
    pub token_prefix: TokenPrefix,
}

impl Default for MaskOptions {
    fn default() -> Self {
        MaskOptions {
            include_unscanned: false,
            ttl_days: DEFAULT_TTL_DAYS,
            token_prefix: TokenPrefix::default(),
        }
    }
}

/// A text file of the input, read once; the masked output is built from
/// exactly these bytes, so they are the bytes that were hash-checked.
struct TextFile {
    rel: RelPath,
    content: Zeroizing<Vec<u8>>,
    sha256: String,
    mode: u32,
}

/// The input as re-walked at mask time.
struct Input {
    text: Vec<TextFile>,
    unscanned: Vec<(RelPath, FileEntry)>,
    dirs: Vec<RelPath>,
    skipped: Skipped,
}

/// A secret span to replace and its token.
pub(crate) struct Replacement {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) token: Token,
}

/// Masks the selected findings of `report` from `input` into a new `out`.
pub fn mask(
    report: &ScanReport,
    selection: &Selection,
    input: &Path,
    out: &Path,
    vault: &mut Vault,
    opts: &MaskOptions,
) -> Result<MaskReport> {
    ttl_secs(opts.ttl_days)?;
    validate_paths(report)?;
    let selected = select(report, selection)?;
    let ignored_by_profile = count_ignored(report, &selected);
    let tree = read_input(report, input)?;
    let by_file = check_findings(&tree, &selected)?;
    let project = ProjectKey::for_input(input)?;
    let out = OutputDir::prepare(out, input)?;
    // D69: on any later error remove our output; keep memory equal to disk.
    let before = vault.snapshot();
    let label = input
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let run = Run {
        report,
        tree: &tree,
        by_file: &by_file,
        label: &label,
        project,
        opts,
        ignored_by_profile,
    };
    mask_into(&run, &out, vault).map_err(|e| {
        vault.restore_snapshot(before);
        out.discard(e)
    })
}

/// Everything checked before the output folder was created.
struct Run<'a> {
    report: &'a ScanReport,
    tree: &'a Input,
    by_file: &'a [Vec<&'a Finding>],
    label: &'a str,
    /// The input's project key: its prefix is remembered on success (D141).
    project: ProjectKey,
    opts: &'a MaskOptions,
    ignored_by_profile: usize,
}

/// SPEC §6.1 steps 4–6 into the freshly created `out`.
fn mask_into(run: &Run<'_>, out: &OutputDir, vault: &mut Vault) -> Result<MaskReport> {
    let prefix = &run.opts.token_prefix;
    let (plans, session_tokens, already_tokens) =
        assign_tokens(vault, run.tree, run.by_file, prefix)?;
    let mut files_written = write_dirs_and_text(out, run.tree, &plans)?;
    let mut not_copied = skipped_paths(&run.tree.skipped);
    for (rel, entry) in &run.tree.unscanned {
        if run.opts.include_unscanned {
            paths::copy_new(out, rel, entry, &mut |_| {})?;
            files_written += 1;
        } else {
            not_copied.push(rel.as_str().to_string());
        }
    }
    not_copied.sort();
    let tokens = session_tokens.len();
    let options = run.report.options.clone();
    let session_id = vault.add_session(run.label, session_tokens, run.opts.ttl_days, options)?;
    vault.remember_prefix(run.project.clone(), prefix);
    vault.save()?;
    Ok(MaskReport {
        session_id,
        files_written,
        secrets_masked: plans.iter().map(Vec::len).sum(),
        tokens,
        not_copied,
        ignored_by_profile: run.ignored_by_profile,
        already_tokens,
    })
}

/// SPEC §6.1 step 2: every `rel_path` in the report is valid, before any I/O.
fn validate_paths(report: &ScanReport) -> Result<()> {
    let finding_paths = report.findings.iter().map(|f| f.rel_path.as_str());
    let scanned = report.scanned_files.iter().map(|s| s.rel_path.as_str());
    for rel in finding_paths.chain(scanned) {
        RelPath::parse(rel)?;
    }
    Ok(())
}

/// D51: the selected findings; an id not in the report is an error. The
/// default leaves out findings the profile ignores (D78).
fn select<'a>(report: &'a ScanReport, selection: &Selection) -> Result<Vec<&'a Finding>> {
    let Selection::Ids(ids) = selection else {
        let not_ignored = report.findings.iter().filter(|f| f.ignored.is_none());
        return Ok(not_ignored.collect());
    };
    let known: BTreeSet<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    if let Some(id) = ids.iter().find(|id| !known.contains(id.as_str())) {
        return Err(CoreError::UnknownFinding { id: id.clone() });
    }
    Ok(report
        .findings
        .iter()
        .filter(|f| ids.contains(&f.id))
        .collect())
}

/// D78: findings the profile ignores that are not selected.
fn count_ignored(report: &ScanReport, selected: &[&Finding]) -> usize {
    let chosen: BTreeSet<&str> = selected.iter().map(|f| f.id.as_str()).collect();
    let ignored = report.findings.iter().filter(|f| f.ignored.is_some());
    ignored.filter(|f| !chosen.contains(f.id.as_str())).count()
}

/// SPEC §6.1 step 3 / D13 / D51: re-walk with the report's options. Every
/// text file must match `scanned_files` by sha256, and no other may exist.
fn read_input(report: &ScanReport, input: &Path) -> Result<Input> {
    let expected: BTreeMap<&str, &str> = report
        .scanned_files
        .iter()
        .map(|s| (s.rel_path.as_str(), s.sha256.as_str()))
        .collect();
    let mut walk_report = ScanReport::default();
    let walked = walk::walk(input, &report.options, &mut walk_report)?;
    let mut tree = Input {
        text: Vec::new(),
        unscanned: Vec::new(),
        dirs: walked
            .dirs
            .iter()
            .map(|d| RelPath::parse(d))
            .collect::<Result<_>>()?,
        skipped: walk_report.skipped,
    };
    for file in walked.files {
        let rel = RelPath::parse(&file.rel_path)?;
        match walk::classify(&file.path, file.ident)? {
            Class::Text(content) => {
                let sha256 = hex::encode(&Sha256::digest(&content));
                if expected.get(rel.as_str()) != Some(&sha256.as_str()) {
                    return Err(CoreError::Rescan);
                }
                let mode = file.mode;
                tree.text.push(TextFile {
                    rel,
                    content,
                    sha256,
                    mode,
                });
            }
            Class::Binary | Class::Oversized => tree.unscanned.push((rel, file)),
            Class::Changed => return Err(CoreError::Rescan),
        }
    }
    if tree.text.len() != expected.len() {
        return Err(CoreError::Rescan);
    }
    Ok(tree)
}

/// Groups the selected findings by text file (index into `tree.text`),
/// sorted by start. Each must fit its file: same hash, in bounds, non-empty,
/// non-overlapping.
fn check_findings<'a>(tree: &Input, selected: &[&'a Finding]) -> Result<Vec<Vec<&'a Finding>>> {
    let index: BTreeMap<&str, usize> = tree
        .text
        .iter()
        .enumerate()
        .map(|(i, t)| (t.rel.as_str(), i))
        .collect();
    let mut by_file: Vec<Vec<&Finding>> = vec![Vec::new(); tree.text.len()];
    for f in selected {
        let bad = || CoreError::BadFinding { id: f.id.clone() };
        let i = *index.get(f.rel_path.as_str()).ok_or_else(bad)?;
        let file = &tree.text[i];
        if f.file_sha256 != file.sha256 || f.start >= f.end || f.end > file.content.len() {
            return Err(bad());
        }
        by_file[i].push(f);
    }
    for list in &mut by_file {
        list.sort_by_key(|f| f.start);
        if let Some(w) = list.windows(2).find(|w| w[0].end > w[1].start) {
            return Err(CoreError::BadFinding {
                id: w[1].id.clone(),
            });
        }
    }
    Ok(by_file)
}

/// The replacements per file, the session's tokens and the number of
/// selected spans that already were tokens.
type Assigned = (Vec<Vec<Replacement>>, Vec<Token>, usize);

/// SPEC §6.1 step 4: a `prefix` token per selected span (deduplicated by
/// value and prefix in the vault). Also returns the session's distinct
/// tokens in first-seen order and how many spans were skipped as tokens.
fn assign_tokens(
    vault: &mut Vault,
    tree: &Input,
    by_file: &[Vec<&Finding>],
    prefix: &TokenPrefix,
) -> Result<Assigned> {
    let haystacks: Vec<&[u8]> = tree.text.iter().map(|t| t.content.as_slice()).collect();
    // G4: a span that is already a token of the chosen prefix or of any
    // prefix in the vault is never masked again (as D48a in the scanner).
    let known = vault.known_prefixes().with(prefix);
    let mut session = Vec::new();
    let mut plans = Vec::with_capacity(by_file.len());
    let mut already = 0;
    for (file, findings) in tree.text.iter().zip(by_file) {
        let ctx = Haystack {
            content: &file.content,
            all: &haystacks,
        };
        let real = not_tokens(&file.content, findings, &known);
        already += findings.len() - real.len();
        plans.push(plan_spans(vault, &ctx, &real, prefix, &mut session)?);
    }
    Ok((plans, session, already))
}

/// The findings whose span is not exactly a `known` token.
fn not_tokens<'f>(
    content: &[u8],
    findings: &[&'f Finding],
    known: &KnownPrefixes,
) -> Vec<&'f Finding> {
    let real = |f: &&&Finding| !known.is_exact(&content[f.start..f.end]);
    findings.iter().filter(real).copied().collect()
}

/// One text and every input text (for the token collision check, SPEC §4).
pub(crate) struct Haystack<'a> {
    pub(crate) content: &'a [u8],
    pub(crate) all: &'a [&'a [u8]],
}

/// Gets or creates the `prefix` token for each finding's span of
/// `text.content`, adding new ones to `session`. Values are held only in
/// `SecretBytes`.
pub(crate) fn plan_spans(
    vault: &mut Vault,
    text: &Haystack<'_>,
    findings: &[&Finding],
    prefix: &TokenPrefix,
    session: &mut Vec<Token>,
) -> Result<Vec<Replacement>> {
    let mut plan = Vec::with_capacity(findings.len());
    for f in findings {
        let value = SecretBytes::new(text.content[f.start..f.end].to_vec());
        let name = f.key_name.as_deref().unwrap_or("");
        let token = vault.get_or_create_token_with(&value, name, &f.rule_id, prefix, text.all)?;
        if !session.contains(&token) {
            session.push(token.clone());
        }
        plan.push(Replacement {
            start: f.start,
            end: f.end,
            token,
        });
    }
    Ok(plan)
}

/// SPEC §6.1 step 5: recreate the directories (D56), then write each text
/// file with its spans replaced. Returns the number of files written.
fn write_dirs_and_text(out: &OutputDir, tree: &Input, plans: &[Vec<Replacement>]) -> Result<usize> {
    for dir in &tree.dirs {
        paths::create_dir(out, dir)?;
    }
    for (file, plan) in tree.text.iter().zip(plans) {
        let masked = apply(&file.content, plan);
        paths::write_new(out, &file.rel, &masked, file.mode)?;
    }
    Ok(tree.text.len())
}

/// `content` with each (sorted, non-overlapping) span replaced by its token.
/// Building left to right into a new buffer is equivalent to replacing
/// right to left in place; every byte outside the spans is kept.
pub(crate) fn apply(content: &[u8], plan: &[Replacement]) -> Zeroizing<Vec<u8>> {
    // Exact size, so the buffer never reallocates (L1).
    let grow: usize = plan.iter().map(|r| r.token.as_str().len()).sum();
    let shrink: usize = plan.iter().map(|r| r.end - r.start).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(content.len() + grow - shrink));
    let mut at = 0;
    for r in plan {
        out.extend_from_slice(&content[at..r.start]);
        out.extend_from_slice(r.token.as_str().as_bytes());
        at = r.end;
    }
    out.extend_from_slice(&content[at..]);
    out
}

/// Every walked entry that is never copied, as listed by the walk.
pub(crate) fn skipped_paths(s: &Skipped) -> Vec<String> {
    let lists = [
        &s.symlink,
        &s.excluded,
        &s.non_utf8_name,
        &s.changed_during_scan,
    ];
    lists.into_iter().flatten().cloned().collect()
}

#[cfg(test)]
mod tests;
