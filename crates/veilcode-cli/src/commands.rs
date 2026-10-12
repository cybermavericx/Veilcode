//! One function per command. All logic lives in veilcode-core; this file
//! resolves paths, asks for passphrases and prints summaries.

use crate::args::{Cli, Cmd, EntryArgs, MaskArgs, ProfileCmd, SessionCmd, VaultCmd};
use crate::{output, passphrase};
use anyhow::{Context, Result, anyhow, bail};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use veilcode_core::{
    CoreError, IgnoreEntry, MaskOptions, Profile, ScanOptions, ScanReport, Selection, SessionId,
    Vault, to_json,
};

pub fn run(cli: &Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Scan {
            dir,
            json,
            no_default_excludes,
        } => scan(cli, dir, json.as_deref(), *no_default_excludes),
        Cmd::Mask(args) => mask(cli, args),
        Cmd::Restore {
            dir,
            out,
            session,
            keep,
        } => restore(cli, dir, out, session.as_deref(), *keep),
        Cmd::Session(cmd) => session(cli, cmd),
        Cmd::Vault(VaultCmd::Status) => status(cli),
        Cmd::Vault(VaultCmd::Purge { yes }) => purge(cli, *yes),
        Cmd::Profile(cmd) => profile(cli, cmd),
    }
}

fn vault_path(cli: &Cli) -> Result<PathBuf> {
    let path = cli.vault.clone().or_else(veilcode_core::default_vault_path);
    path.ok_or_else(|| anyhow!("no local data directory found; use --vault FILE"))
}

/// D75: only `--profile` or the user's config dir, never the input folder.
fn profile_path(cli: &Cli) -> Result<PathBuf> {
    let path = cli
        .profile
        .clone()
        .or_else(veilcode_core::default_profile_path);
    path.ok_or_else(|| anyhow!("no local config directory found; use --profile FILE"))
}

fn load_profile(cli: &Cli) -> Result<(Profile, PathBuf)> {
    let path = profile_path(cli)?;
    let profile = Profile::load(&path).with_context(|| format!("profile {}", path.display()))?;
    Ok((profile, path))
}

/// Writes `--report` (D89: never inside `input`).
fn write_report(cli: &Cli, input: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match &cli.report {
        Some(path) => output::write_file(path, input, bytes),
        None => Ok(()),
    }
}

/// D89: checks `--report` and `extra` before any work is done.
fn check_outputs(cli: &Cli, input: Option<&Path>, extra: Option<&Path>) -> Result<()> {
    let paths = cli.report.as_deref().into_iter().chain(extra);
    paths
        .into_iter()
        .try_for_each(|p| output::check_target(p, input))
}

fn no_report(cli: &Cli) -> Result<()> {
    if cli.report.is_some() {
        bail!("--report is not supported by this command");
    }
    Ok(())
}

/// Opens an existing vault and reports expired sessions (D61).
fn open_vault(cli: &Cli) -> Result<(Vault, PathBuf)> {
    let path = vault_path(cli)?;
    if std::fs::symlink_metadata(&path).is_err() {
        bail!("no vault at {}", path.display());
    }
    let pass = passphrase::read(cli.passphrase_stdin)?;
    let vault = Vault::open(&path, &pass)?;
    report_expired(&vault);
    Ok((vault, path))
}

fn report_expired(vault: &Vault) {
    let n = vault.expired_removed();
    if n > 0 {
        eprintln!("{n} expired sessions removed");
    }
}

/// Mask opens the vault, or creates it if missing (D17).
fn open_or_create(cli: &Cli) -> Result<Vault> {
    let path = vault_path(cli)?;
    if std::fs::symlink_metadata(&path).is_ok() {
        return open_vault(cli).map(|(v, _)| v);
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    eprintln!("creating a new vault at {}", path.display());
    let pass = passphrase::read_new(cli.passphrase_stdin)?;
    Ok(Vault::create(&path, &pass)?)
}

fn scan(cli: &Cli, dir: &Path, json: Option<&Path>, no_default_excludes: bool) -> Result<()> {
    check_outputs(cli, Some(dir), json)?;
    let (profile, _) = load_profile(cli)?;
    let opts = ScanOptions {
        no_default_excludes,
    };
    let report = veilcode_core::scan(dir, &opts, &profile)?;
    output::scan(&report);
    let bytes = to_json(&report)?;
    if let Some(path) = json {
        output::write_file(path, Some(dir), &bytes)?;
    }
    write_report(cli, Some(dir), &bytes)
}

fn mask(cli: &Cli, a: &MaskArgs) -> Result<()> {
    check_outputs(cli, Some(&a.dir), None)?;
    let report = match &a.findings {
        Some(file) => ScanReport::from_json(&read_findings(file)?)?,
        None => {
            let (profile, _) = load_profile(cli)?;
            let opts = ScanOptions {
                no_default_excludes: a.no_default_excludes,
            };
            veilcode_core::scan(&a.dir, &opts, &profile)?
        }
    };
    let mut vault = open_or_create(cli)?;
    let opts = MaskOptions {
        include_unscanned: a.include_unscanned,
        ttl_days: a.ttl_days,
    };
    let rep = veilcode_core::mask(&report, &Selection::All, &a.dir, &a.out, &mut vault, &opts)?;
    output::mask(&rep, a.ttl_days);
    write_report(cli, Some(&a.dir), &to_json(&rep)?)
}

/// D89: the findings file, read through `take(64 MiB)`.
fn read_findings(file: &Path) -> Result<Vec<u8>> {
    const MAX: u64 = 64 * 1024 * 1024;
    let context = || format!("cannot read {}", file.display());
    let mut bytes = Vec::new();
    let f = std::fs::File::open(file).with_context(context)?;
    f.take(MAX + 1)
        .read_to_end(&mut bytes)
        .with_context(context)?;
    if bytes.len() as u64 > MAX {
        bail!("findings file {} is larger than 64 MiB", file.display());
    }
    Ok(bytes)
}

fn parse_session(id: &str) -> Result<SessionId> {
    SessionId::try_from(id.to_string()).map_err(|_| anyhow!("invalid session id {id:?}"))
}

fn restore(cli: &Cli, dir: &Path, out: &Path, session: Option<&str>, keep: bool) -> Result<()> {
    check_outputs(cli, Some(dir), None)?;
    let session = session.map(parse_session).transpose()?;
    let (profile, _) = load_profile(cli)?;
    let (mut vault, path) = open_vault(cli)?;
    let existed = out.exists();
    let result = veilcode_core::restore(dir, out, &mut vault, session.as_ref(), keep, &profile);
    let rep = result.map_err(|e| forget_hint(e, existed, out))?;
    output::restore(&rep, !path.exists());
    write_report(cli, Some(dir), &to_json(&rep)?)
}

/// D67: if the outputs were written but forgetting the session failed,
/// say that the vault on disk still holds the session.
fn forget_hint(e: CoreError, existed: bool, out: &Path) -> anyhow::Error {
    let written = !existed && out.exists() && !matches!(e, CoreError::PartialOutput { .. });
    let e = anyhow::Error::from(e);
    if written {
        e.context(
            "the restored folder is complete, but forgetting the session failed; \
             the vault file still holds it — run `veilcode session list` to see its state",
        )
    } else {
        e
    }
}

fn session(cli: &Cli, cmd: &SessionCmd) -> Result<()> {
    match cmd {
        SessionCmd::List => {
            let (vault, _) = open_vault(cli)?;
            output::sessions(vault.sessions());
            write_report(cli, None, &to_json(&vault.sessions())?)
        }
        SessionCmd::Delete { id } => {
            no_report(cli)?;
            let id = parse_session(id)?;
            let (mut vault, path) = open_vault(cli)?;
            vault.delete_session(&id)?;
            eprintln!("session {} deleted", id.as_str());
            if !path.exists() {
                eprintln!("vault file removed (no sessions left)");
            }
            Ok(())
        }
    }
}

fn now() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |d| d.as_secs())
}

fn status(cli: &Cli) -> Result<()> {
    let (vault, _) = open_vault(cli)?;
    let status = vault.status();
    output::status(&status, now());
    write_report(cli, None, &to_json(&status)?)
}

/// D63: purge asks first unless `--yes`; with no terminal it refuses.
fn purge(cli: &Cli, yes: bool) -> Result<()> {
    check_outputs(cli, None, None)?;
    if !yes {
        confirm_purge()?;
    }
    let (mut vault, _) = open_vault(cli)?;
    let r = vault.purge()?;
    eprintln!(
        "purged {} sessions and {} entries; vault file removed",
        r.sessions_removed, r.entries_removed
    );
    write_report(cli, None, &to_json(&r)?)
}

fn confirm_purge() -> Result<()> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!("purge cancelled: no terminal to confirm; use --yes");
    }
    eprint!("Delete all sessions and the vault file? [y/N] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    stdin.lock().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        bail!("purge cancelled")
    }
}

fn entry(a: &EntryArgs) -> IgnoreEntry {
    IgnoreEntry {
        rel_path: a.path.clone(),
        key_name: a.key.clone(),
        rule_id: a.rule.clone(),
    }
}

fn profile(cli: &Cli, cmd: &ProfileCmd) -> Result<()> {
    no_report(cli)?;
    let (mut p, path) = load_profile(cli)?;
    let (changed, done, noop) = match cmd {
        ProfileCmd::List => {
            output::profile(&p, &path);
            return Ok(());
        }
        ProfileCmd::AddKey { key } => (p.add_extra_key(key)?, "extra key added", "already present"),
        ProfileCmd::RemoveKey { key } => {
            (p.remove_extra_key(key)?, "extra key removed", "not present")
        }
        ProfileCmd::IgnoreKey { key } => (p.ignore_key(key)?, "key ignored", "already ignored"),
        ProfileCmd::UnignoreKey { key } => (p.unignore_key(key)?, "key unignored", "not ignored"),
        ProfileCmd::Ignore(a) => (
            p.ignore_entry(entry(a))?,
            "entry ignored",
            "already ignored",
        ),
        ProfileCmd::Unignore(a) => (p.unignore_entry(&entry(a))?, "entry removed", "not ignored"),
    };
    if changed {
        p.save(&path)?;
        eprintln!("{done} ({})", path.display());
    } else {
        eprintln!("{noop}; no change");
    }
    Ok(())
}
