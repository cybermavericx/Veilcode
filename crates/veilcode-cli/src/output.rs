//! Human summaries (stderr; listings on stdout) and JSON report files.
//! Only ids, counts, paths, rule ids, key names and D25 previews are printed.

use anyhow::{Context, Result, bail};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use veilcode_core::{
    Finding, IgnoreReason, KeptReason, MaskReport, Profile, RestoreReport, ScanReport, Session,
    VaultStatus,
};

/// Writes a JSON report file (created or replaced).
/// D89: writes a report file. Refuses a path inside the canonicalised
/// `input` (hard rule 7); replaces an existing path only if it is a regular
/// file, via a new tmp file and rename (a symlink is never followed).
pub fn write_file(path: &Path, input: Option<&Path>, bytes: &[u8]) -> Result<()> {
    check_target(path, input)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let context = || format!("cannot write {}", path.display());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    // The tmp file is ours from here on; remove it on any failure.
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(context)
}

/// D89 checks, also run before a command does any work.
pub fn check_target(path: &Path, input: Option<&Path>) -> Result<()> {
    if input.is_some_and(|dir| inside(path, dir)) {
        bail!(
            "refusing to write {} inside the input folder",
            path.display()
        );
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => {
            bail!("refusing to replace {}: not a regular file", path.display())
        }
        _ => Ok(()),
    }
}

/// True if `path`'s parent, canonicalised, is the input folder or below it.
fn inside(path: &Path, input: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(input) else {
        return false;
    };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or(Path::new("."));
    std::fs::canonicalize(parent).is_ok_and(|dir| dir.starts_with(&root))
}

fn finding_line(f: &Finding) -> String {
    let key = f.key_name.as_deref().unwrap_or("-");
    let ignored = match f.ignored {
        Some(IgnoreReason::ProfileKey) => "  [ignored: profile key]",
        Some(IgnoreReason::ProfileEntry) => "  [ignored: profile entry]",
        None => "",
    };
    let (path, line, col) = (&f.rel_path, f.line, f.column);
    format!(
        "{path}:{line}:{col}  {}  {key}  {}{ignored}",
        f.rule_id, f.preview
    )
}

pub fn scan(r: &ScanReport) {
    for f in &r.findings {
        eprintln!("{}", finding_line(f));
    }
    let ignored = r.findings.iter().filter(|f| f.ignored.is_some()).count();
    let (n, files) = (r.findings.len(), r.scanned_files.len());
    eprintln!("{n} findings in {files} scanned files ({ignored} ignored by profile)");
    let s = &r.skipped;
    let skipped = [
        (s.binary.len(), "binary"),
        (s.oversized.len(), "oversized"),
        (s.symlink.len(), "symlink"),
        (s.excluded.len(), "excluded"),
        (s.changed_during_scan.len(), "changed during scan"),
        (s.non_utf8_name.len(), "non-UTF-8 name"),
    ];
    for (count, why) in skipped.iter().filter(|(c, _)| *c > 0) {
        eprintln!("not scanned: {count} {why}");
    }
    if !r.warnings.is_empty() {
        eprintln!(
            "{} rule or ignore-file warnings (see --json)",
            r.warnings.len()
        );
    }
}

pub fn mask(r: &MaskReport, ttl_days: u32) {
    let id = r.session_id.as_str();
    eprintln!(
        "masked {} secrets in {} files (session {id}, expires in {ttl_days} days)",
        r.secrets_masked, r.files_written
    );
    if r.ignored_by_profile > 0 {
        eprintln!(
            "{} findings ignored by profile (not masked)",
            r.ignored_by_profile
        );
    }
    if r.already_tokens > 0 {
        eprintln!(
            "{} findings already were placeholder tokens (not masked again)",
            r.already_tokens
        );
    }
    if !r.not_copied.is_empty() {
        eprintln!(
            "{} entries not copied (binary/oversized need --include-unscanned)",
            r.not_copied.len()
        );
    }
}

pub fn restore(r: &RestoreReport, vault_removed: bool) {
    eprintln!(
        "restored {} files, {} tokens replaced",
        r.files_written, r.tokens_replaced
    );
    for f in &r.new_secrets {
        eprintln!("new secret: {}", finding_line(f));
    }
    let counts = [
        (r.ignored_new_secrets, "new secrets ignored by profile"),
        (r.unknown.len(), "unknown tokens"),
        (r.missing.len(), "missing tokens"),
        (r.not_copied.len(), "entries not copied"),
        (r.tokens_in_unscanned, "tokens left in unscanned files"),
        (r.foreign_session_tokens, "tokens from other sessions"),
    ];
    for (n, what) in counts.iter().filter(|(n, _)| *n > 0) {
        eprintln!("{n} {what}");
    }
    match &r.kept_reason {
        _ if r.session_forgotten && vault_removed => {
            eprintln!("session forgotten; vault file removed (no sessions left)");
        }
        _ if r.session_forgotten => eprintln!("session forgotten"),
        Some(KeptReason::KeepRequested) => eprintln!("session kept: keep requested"),
        Some(KeptReason::NotClean { .. }) => {
            eprintln!("session kept: restore not clean (see the counts above)");
        }
        None => {}
    }
}

/// Seconds as whole days, rounded.
fn days(secs: u64) -> u64 {
    (secs + 43_200) / 86_400
}

pub fn status(s: &VaultStatus, now: u64) {
    println!("sessions: {}", s.sessions);
    match s.oldest_created {
        Some(t) => println!(
            "oldest created: {t} ({} days ago)",
            days(now.saturating_sub(t))
        ),
        None => println!("oldest created: -"),
    }
    match s.next_expiry {
        Some(t) => println!("next expiry: {t} (in {} days)", days(t.saturating_sub(now))),
        None => println!("next expiry: -"),
    }
}

pub fn sessions(list: &[Session]) {
    if list.is_empty() {
        println!("no sessions");
    }
    for s in list {
        println!(
            "{}  created {}  expires {}  {}  {} tokens",
            s.id.as_str(),
            s.created,
            s.expires_at,
            s.source_label,
            s.tokens.len()
        );
    }
}

fn joined(list: &[String]) -> String {
    if list.is_empty() {
        "(none)".to_string()
    } else {
        list.join(", ")
    }
}

pub fn profile(p: &Profile, path: &Path) {
    println!("profile: {}", path.display());
    println!("extra keys: {}", joined(p.extra_keys()));
    println!("ignored keys: {}", joined(p.ignored_keys()));
    if p.ignored().is_empty() {
        println!("ignored entries: (none)");
    } else {
        println!("ignored entries:");
    }
    for e in p.ignored() {
        match (&e.key_name, &e.rule_id) {
            (Some(k), _) => println!("  {} key {k}", e.rel_path),
            (None, Some(r)) => println!("  {} rule {r}", e.rel_path),
            (None, None) => {}
        }
    }
}
