//! Detection profile (SPEC §5.1, D74–D80): a user-editable TOML file that
//! adds key names to detect and marks known false positives. It never holds
//! secret values: entries are key- or location-based (D78, D79). It is only
//! read from an explicit path or the user's config dir, never from the
//! input folder (D75).

use crate::error::{CoreError, Result};
use crate::paths::RelPath;
use crate::scan::walk::identity;
use crate::scan::{Finding, IgnoreReason};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

/// The largest profile file read (D79).
pub(crate) const MAX_PROFILE: u64 = 1024 * 1024;
const VERSION: u32 = 1;
const NAME_MAX: usize = 64;
/// D88: list caps.
pub(crate) const MAX_KEYS: usize = 256;
pub(crate) const MAX_ENTRIES: usize = 4096;
const EXTRA: &str = "extra_keys";
const IGNORED_KEYS: &str = "ignored_keys";
const ENTRIES: &str = "[[ignored]] entries";

/// The detection profile. Edits validate their input and report whether
/// anything changed (D79: adding a present key or removing an absent one
/// is a no-op).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    version: u32,
    #[serde(default)]
    extra_keys: Vec<String>,
    #[serde(default)]
    ignored_keys: Vec<String>,
    #[serde(default)]
    ignored: Vec<IgnoreEntry>,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            version: VERSION,
            extra_keys: Vec::new(),
            ignored_keys: Vec::new(),
            ignored: Vec::new(),
        }
    }
}

/// One remembered false positive: a file plus exactly one of a key name or
/// a rule id (D74).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreEntry {
    /// `/`-separated path relative to the input root.
    pub rel_path: String,
    /// Matched after D76 normalisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    /// Matched exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

/// Where `ignore_finding` remembers a false positive (D80).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only in the finding's file (an `[[ignored]]` entry).
    ThisFile,
    /// Its key name in every file (`ignored_keys`).
    Everywhere,
}

/// D76: uppercase, and `-`, `.` and space become `_`.
pub(crate) fn normalise_key(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '-' | '.' | ' ' => '_',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}

/// D79: `[A-Za-z0-9_.\- ]{1,64}`, with at least one ASCII letter or digit
/// (D88). Also used for rule ids.
fn check_name(name: &str) -> Result<()> {
    let ok_char = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b' ');
    let has_alnum = name.bytes().any(|c| c.is_ascii_alphanumeric());
    if (1..=NAME_MAX).contains(&name.len()) && name.bytes().all(ok_char) && has_alnum {
        Ok(())
    } else {
        Err(CoreError::BadKeyName)
    }
}

/// True if `list` holds `key` after D76 normalisation.
fn contains_key(list: &[String], key: &str) -> bool {
    let want = normalise_key(key);
    list.iter().any(|k| normalise_key(k) == want)
}

/// Adds `key` unless an equal (normalised) key is present.
/// D88: a list longer than `max` is an error.
fn check_cap(len: usize, max: usize, what: &'static str) -> Result<()> {
    if len > max {
        return Err(CoreError::ProfileTooLarge { what, max });
    }
    Ok(())
}

fn add_key(list: &mut Vec<String>, key: &str, what: &'static str) -> Result<bool> {
    check_name(key)?;
    if contains_key(list, key) {
        return Ok(false);
    }
    check_cap(list.len() + 1, MAX_KEYS, what)?;
    list.push(key.to_string());
    Ok(true)
}

/// Removes every key equal (normalised) to `key`.
fn remove_key(list: &mut Vec<String>, key: &str) -> Result<bool> {
    check_name(key)?;
    let want = normalise_key(key);
    let before = list.len();
    list.retain(|k| normalise_key(k) != want);
    Ok(list.len() != before)
}

impl IgnoreEntry {
    fn validate(&self) -> Result<()> {
        RelPath::parse(&self.rel_path)?;
        match (&self.key_name, &self.rule_id) {
            (Some(name), None) | (None, Some(name)) => check_name(name),
            _ => Err(CoreError::BadIgnoreEntry),
        }
    }

    /// True if this entry applies to `f` (same file and key or rule).
    fn matches(&self, f: &Finding) -> bool {
        if self.rel_path != f.rel_path {
            return false;
        }
        match (&self.key_name, &self.rule_id, &f.key_name) {
            (Some(k), _, Some(fk)) => normalise_key(k) == normalise_key(fk),
            (None, Some(r), _) => *r == f.rule_id,
            _ => false,
        }
    }

    /// The entry that ignores `f` in its own file: by key name if it has
    /// one, otherwise by rule id.
    fn for_finding(f: &Finding) -> IgnoreEntry {
        IgnoreEntry {
            rel_path: f.rel_path.clone(),
            key_name: f.key_name.clone(),
            rule_id: f.key_name.is_none().then(|| f.rule_id.clone()),
        }
    }

    /// The same entry, compared with normalised key names.
    fn same_as(&self, other: &IgnoreEntry) -> bool {
        let norm = |k: &Option<String>| k.as_deref().map(normalise_key);
        self.rel_path == other.rel_path
            && norm(&self.key_name) == norm(&other.key_name)
            && self.rule_id == other.rule_id
    }
}

impl Profile {
    /// Loads the profile at `path` (D79). A missing file is an empty
    /// profile; anything but a regular file of at most 1 MiB in strict TOML
    /// with valid names and paths is an error.
    pub fn load(path: &Path) -> Result<Profile> {
        let Some(bytes) = read_limited(path)? else {
            return Ok(Profile::default());
        };
        let text = String::from_utf8_lossy(&bytes);
        let profile: Profile = toml::from_str(&text).map_err(|e| CoreError::ProfileParse {
            line: e.span().map_or(0, |s| line_of(&text, s.start)),
        })?;
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            return Err(CoreError::ProfileVersion {
                version: self.version,
            });
        }
        check_cap(self.extra_keys.len(), MAX_KEYS, EXTRA)?;
        check_cap(self.ignored_keys.len(), MAX_KEYS, IGNORED_KEYS)?;
        check_cap(self.ignored.len(), MAX_ENTRIES, ENTRIES)?;
        let keys = self.extra_keys.iter().chain(&self.ignored_keys);
        keys.into_iter().try_for_each(|k| check_name(k))?;
        self.ignored.iter().try_for_each(IgnoreEntry::validate)
    }

    /// Atomically writes the profile to `path` (tmp file, fsync, rename),
    /// creating missing parent directories.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = toml::to_string(self).map_err(|_| CoreError::ReportEncode)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, &e))?;
        }
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        let result = write_tmp(&tmp, text.as_bytes())
            .and_then(|()| std::fs::rename(&tmp, path).map_err(|e| CoreError::io(path, &e)));
        if result.is_err() && !matches!(result, Err(CoreError::ProfileSaveLocked { .. })) {
            // We created the tmp file, so it is ours to remove.
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Key names also detected (D2, D3, D5), as written by the user.
    pub fn extra_keys(&self) -> &[String] {
        &self.extra_keys
    }

    /// Key names never auto-selected.
    pub fn ignored_keys(&self) -> &[String] {
        &self.ignored_keys
    }

    /// Per-file false positives.
    pub fn ignored(&self) -> &[IgnoreEntry] {
        &self.ignored
    }

    /// Adds a key name to detect; `false` if already present (normalised).
    pub fn add_extra_key(&mut self, key: &str) -> Result<bool> {
        add_key(&mut self.extra_keys, key, EXTRA)
    }

    /// Removes a key name to detect; `false` if absent.
    pub fn remove_extra_key(&mut self, key: &str) -> Result<bool> {
        remove_key(&mut self.extra_keys, key)
    }

    /// Never auto-select this key name in any file.
    pub fn ignore_key(&mut self, key: &str) -> Result<bool> {
        add_key(&mut self.ignored_keys, key, IGNORED_KEYS)
    }

    /// Undoes `ignore_key`.
    pub fn unignore_key(&mut self, key: &str) -> Result<bool> {
        remove_key(&mut self.ignored_keys, key)
    }

    /// Adds an `[[ignored]]` entry; `false` if an equal one is present.
    pub fn ignore_entry(&mut self, entry: IgnoreEntry) -> Result<bool> {
        entry.validate()?;
        if self.ignored.iter().any(|e| e.same_as(&entry)) {
            return Ok(false);
        }
        check_cap(self.ignored.len() + 1, MAX_ENTRIES, ENTRIES)?;
        self.ignored.push(entry);
        Ok(true)
    }

    /// Removes the `[[ignored]]` entries equal to `entry`.
    pub fn unignore_entry(&mut self, entry: &IgnoreEntry) -> Result<bool> {
        entry.validate()?;
        let before = self.ignored.len();
        self.ignored.retain(|e| !e.same_as(entry));
        Ok(self.ignored.len() != before)
    }

    /// Remembers `f` as a false positive in its file, or (by key name)
    /// everywhere. A finding without a key name can only be ignored in its file.
    pub fn ignore_finding(&mut self, f: &Finding, scope: Scope) -> Result<bool> {
        match (scope, &f.key_name) {
            (Scope::ThisFile, _) => self.ignore_entry(IgnoreEntry::for_finding(f)),
            (Scope::Everywhere, Some(key)) => self.ignore_key(key),
            (Scope::Everywhere, None) => Err(CoreError::NoKeyName),
        }
    }

    /// Removes everything that marks `f` as ignored: its key in
    /// `ignored_keys` and every `[[ignored]]` entry that matches it.
    pub fn unignore_finding(&mut self, f: &Finding) -> Result<bool> {
        let before = (self.ignored_keys.len(), self.ignored.len());
        if let Some(key) = f.key_name.as_deref().filter(|k| check_name(k).is_ok()) {
            remove_key(&mut self.ignored_keys, key)?;
        }
        self.ignored.retain(|e| !e.matches(f));
        Ok(before != (self.ignored_keys.len(), self.ignored.len()))
    }

    /// D78: why the profile ignores `f`, if it does. A key in
    /// `ignored_keys` wins over a per-file entry.
    pub(crate) fn mark(&self, f: &Finding) -> Option<IgnoreReason> {
        let by_key = f
            .key_name
            .as_deref()
            .is_some_and(|k| contains_key(&self.ignored_keys, k));
        if by_key {
            Some(IgnoreReason::ProfileKey)
        } else if self.ignored.iter().any(|e| e.matches(f)) {
            Some(IgnoreReason::ProfileEntry)
        } else {
            None
        }
    }
}

/// D79 (as D44): the bytes of `path` if it is a regular file of at most
/// 1 MiB, read through `take`; `None` if it does not exist.
fn read_limited(path: &Path) -> Result<Option<Vec<u8>>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CoreError::io(path, &e)),
    };
    if !meta.is_file() || meta.len() > MAX_PROFILE {
        return Err(CoreError::UnsafeProfile);
    }
    let file = File::open(path).map_err(|e| CoreError::io(path, &e))?;
    // D88 (as D45): still a regular file, and on Unix the one lstat saw.
    let same = |m: &std::fs::Metadata| m.is_file() && identity(m) == identity(&meta);
    if !file.metadata().is_ok_and(|m| same(&m)) {
        return Err(CoreError::UnsafeProfile);
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CoreError::io(path, &e))?;
    if bytes.len() as u64 > MAX_PROFILE {
        return Err(CoreError::UnsafeProfile);
    }
    Ok(Some(bytes))
}

/// 1-based line of byte `offset` in `text`.
fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Writes `bytes` to a new `tmp` (never over an existing file) and syncs it.
fn write_tmp(tmp: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            return Err(CoreError::ProfileSaveLocked {
                path: tmp.to_path_buf(),
            });
        }
        Err(e) => return Err(CoreError::io(tmp, &e)),
    };
    file.write_all(bytes).map_err(|e| CoreError::io(tmp, &e))?;
    file.sync_all().map_err(|e| CoreError::io(tmp, &e))
}

/// D81: the default profile, `profile.toml` in the local (non-roaming)
/// config dir. `None` if the OS reports no home directory.
pub fn default_profile_path() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Cybermavericx", "Veilcode")?;
    Some(dirs.config_local_dir().join("profile.toml"))
}

#[cfg(test)]
mod tests;
