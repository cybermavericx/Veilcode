//! Retention (SPEC §6.4, §7; D60–D63): forget, expiry, delete, purge,
//! status. Leaving zero sessions removes `vault.vc` instead of saving an
//! empty file (D62).

use super::model::{MAX_TTL_SECS, Session, SessionId, VaultData};
use super::{Vault, create_tmp, sync_parent_dir};
use crate::error::{CoreError, Result};
use serde::Serialize;
use std::io::ErrorKind;

/// Default session lifetime (D61).
pub(crate) const DEFAULT_TTL_DAYS: u32 = 30;
const DAY_SECS: u64 = 86_400;

/// `ttl_days` in seconds; anything outside 1–365 is an error (D61).
pub(crate) fn ttl_secs(days: u32) -> Result<u64> {
    let secs = u64::from(days) * DAY_SECS;
    if days >= 1 && secs <= MAX_TTL_SECS {
        Ok(secs)
    } else {
        Err(CoreError::BadTtl)
    }
}

/// Vault summary (D63): counts and unix times only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VaultStatus {
    /// Number of sessions.
    pub sessions: usize,
    /// The oldest session's `created`.
    pub oldest_created: Option<u64>,
    /// The soonest `expires_at`.
    pub next_expiry: Option<u64>,
}

/// What `purge` removed (D63): counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PurgeResult {
    pub sessions_removed: usize,
    pub entries_removed: usize,
}

/// Removes the sessions matching `gone` and every entry they used that no
/// remaining session uses. Returns (sessions, entries) removed.
fn drop_sessions(data: &mut VaultData, gone: impl Fn(&Session) -> bool) -> (usize, usize) {
    let all = std::mem::take(&mut data.sessions);
    let (removed, kept): (Vec<Session>, Vec<Session>) = all.into_iter().partition(gone);
    data.sessions = kept;
    let mut entries = 0;
    for token in removed.iter().flat_map(|s| &s.tokens) {
        let used = data.sessions.iter().any(|s| s.tokens.contains(token));
        if !used && data.entries.remove(token).is_some() {
            entries += 1;
        }
    }
    (removed.len(), entries)
}

impl Vault {
    /// Removes session `id` and every entry no remaining session uses, then
    /// saves, or removes the file if no session is left (SPEC §6.4, D62).
    /// An unknown id is an error and changes nothing.
    pub fn delete_session(&mut self, id: &SessionId) -> Result<()> {
        if !self.data.sessions.iter().any(|s| &s.id == id) {
            return Err(CoreError::UnknownSession {
                id: id.as_str().to_string(),
            });
        }
        self.commit(|d| drop_sessions(d, |s| &s.id == id))?;
        Ok(())
    }

    /// D60: forget a session after a clean restore.
    pub(crate) fn forget(&mut self, id: &SessionId) -> Result<()> {
        self.delete_session(id)
    }

    /// D61: drops sessions with `expires_at <= now` and their unused
    /// entries, persisting if any were dropped. Returns how many.
    pub(crate) fn purge_expired(&mut self, now: u64) -> Result<usize> {
        if !self.data.sessions.iter().any(|s| s.expires_at <= now) {
            return Ok(0);
        }
        let (sessions, _) = self.commit(|d| drop_sessions(d, |s| s.expires_at <= now))?;
        Ok(sessions)
    }

    /// D63: removes every session and entry, then the file (D62).
    pub fn purge(&mut self) -> Result<PurgeResult> {
        let (sessions_removed, entries_removed) = self.commit(|d| {
            let counts = (d.sessions.len(), d.entries.len());
            d.sessions.clear();
            d.entries.clear();
            counts
        })?;
        Ok(PurgeResult {
            sessions_removed,
            entries_removed,
        })
    }

    /// D63: session count, oldest `created`, soonest `expires_at`.
    pub fn status(&self) -> VaultStatus {
        let s = &self.data.sessions;
        VaultStatus {
            sessions: s.len(),
            oldest_created: s.iter().map(|x| x.created).min(),
            next_expiry: s.iter().map(|x| x.expires_at).min(),
        }
    }

    /// D72: applies `change` to a copy, persists the copy (save, or D62
    /// removal when no session is left), and only then swaps it in. On
    /// failure memory is left equal to disk.
    fn commit<R>(&mut self, change: impl FnOnce(&mut VaultData) -> R) -> Result<R> {
        let mut next = self.data.clone();
        let out = change(&mut next);
        if next.sessions.is_empty() {
            next.entries.clear();
        }
        let old = std::mem::replace(&mut self.data, next);
        let persisted = if self.data.sessions.is_empty() {
            self.remove_file()
        } else {
            self.save()
        };
        match persisted {
            Ok(()) => Ok(out),
            Err(e) => {
                self.data = old;
                Err(e)
            }
        }
    }

    /// D62 under the D28 lock: D7 hash check, remove, unlock, fsync the
    /// parent (Unix). If removing fails the file is left as it was.
    fn remove_file(&mut self) -> Result<()> {
        let tmp = self.tmp_path();
        let lock = create_tmp(&tmp)?;
        let result = self.remove_locked();
        drop(lock);
        let unlocked = std::fs::remove_file(&tmp).map_err(|e| CoreError::io(&tmp, &e));
        result?;
        unlocked?;
        sync_parent_dir(&self.path)
    }

    fn remove_locked(&mut self) -> Result<()> {
        self.check_unchanged()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::io(&self.path, &e)),
        }
        self.file_hash = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
