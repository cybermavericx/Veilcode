//! Command-line arguments (PLAN P4, clap 4.6.7 derive; see VERIFY_LOG).

use clap::{ArgGroup, Args, Parser, Subcommand, value_parser};
use std::path::PathBuf;
use veilcode_core::{DEFAULT_PREFIX, TokenPrefix};

const AFTER_HELP: &str = "\
Veilcode works offline. It never modifies the input folder and never prints secret values.

Recommended: one vault per project, for example `--vault <project>.vc`,
so finishing a project leaves no secrets behind (a clean restore forgets its session).

Exit codes: 0 ok, 2 error.";

/// Mask secrets in a code folder before sharing it with an AI assistant,
/// and restore them afterwards.
#[derive(Parser)]
#[command(name = "veilcode", version, after_help = AFTER_HELP)]
pub struct Cli {
    /// Vault file (default: vault.vc in the local data dir).
    #[arg(long, global = true, value_name = "FILE")]
    pub vault: Option<PathBuf>,
    /// Read the passphrase as one line from stdin instead of the terminal.
    #[arg(long, global = true)]
    pub passphrase_stdin: bool,
    /// Write the JSON report of mask, restore, session list or vault status to FILE.
    #[arg(long, global = true, value_name = "FILE")]
    pub report: Option<PathBuf>,
    /// Detection profile (default: profile.toml in the local config dir).
    /// Never read from the input folder.
    #[arg(long, global = true, value_name = "FILE")]
    pub profile: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Scan a folder and list findings (previews only; no vault needed).
    Scan {
        dir: PathBuf,
        /// Write the scan report (findings file for `mask --findings`).
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,
        /// Also scan node_modules, vendor, target, .venv, venv, __pycache__.
        #[arg(long)]
        no_default_excludes: bool,
    },
    /// Copy a folder to a new folder with secrets replaced by tokens.
    Mask(MaskArgs),
    /// Copy a masked (AI-edited) folder to a new folder with tokens replaced by values.
    Restore {
        dir: PathBuf,
        /// New output folder (must not exist).
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Session id (default: the newest).
        #[arg(long, value_name = "ID")]
        session: Option<String>,
        /// Keep the session even after a clean restore.
        #[arg(long)]
        keep: bool,
    },
    /// List or delete vault sessions.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Show vault status or purge the whole vault.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Edit the detection profile (extra key names and false positives).
    #[command(subcommand)]
    Profile(ProfileCmd),
}

#[derive(Args)]
pub struct MaskArgs {
    pub dir: PathBuf,
    /// New output folder (must not exist).
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
    /// Mask exactly the findings in this edited `scan --json` file.
    #[arg(long, value_name = "FILE")]
    pub findings: Option<PathBuf>,
    /// Also copy binary and oversized files (unscanned).
    #[arg(long)]
    pub include_unscanned: bool,
    /// Also scan node_modules, vendor, target, .venv, venv, __pycache__.
    #[arg(long, conflicts_with = "findings")]
    pub no_default_excludes: bool,
    /// Days until the session expires (1–365).
    #[arg(long, default_value_t = 30, value_parser = value_parser!(u32).range(1..=365))]
    pub ttl_days: u32,
    /// Placeholder prefix of new tokens: 2–16 ASCII characters, a letter
    /// first, then letters, digits or _, ending with _ (D138).
    #[arg(long, value_name = "PREFIX", default_value = DEFAULT_PREFIX, value_parser = TokenPrefix::parse)]
    pub token_prefix: TokenPrefix,
}

#[derive(Subcommand)]
pub enum SessionCmd {
    /// List sessions (id, created, expiry, label, token count).
    List,
    /// Delete a session and the vault entries only it uses.
    Delete { id: String },
}

#[derive(Subcommand)]
pub enum VaultCmd {
    /// Session count, oldest session and next expiry (no values).
    Status,
    /// Remove all sessions and delete the vault file.
    Purge {
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// Show the profile.
    List,
    /// Also detect this key name (D2, D3 and custom-key assignments).
    AddKey { key: String },
    /// Stop detecting this extra key name.
    RemoveKey { key: String },
    /// Never auto-select findings with this key name.
    IgnoreKey { key: String },
    /// Undo ignore-key.
    UnignoreKey { key: String },
    /// Remember a false positive in one file.
    Ignore(EntryArgs),
    /// Undo ignore.
    Unignore(EntryArgs),
}

#[derive(Args)]
#[command(group(ArgGroup::new("target").required(true).multiple(false).args(["key", "rule"])))]
pub struct EntryArgs {
    /// File path relative to the input folder, with `/` separators.
    #[arg(long, value_name = "REL_PATH")]
    pub path: String,
    /// Key name.
    #[arg(long)]
    pub key: Option<String>,
    /// Rule id.
    #[arg(long)]
    pub rule: Option<String>,
}
