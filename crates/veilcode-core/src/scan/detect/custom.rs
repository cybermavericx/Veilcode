//! D5: custom-key assignment, only for profile `extra_keys` (SPEC §5, D76, D77).
//!
//! An optionally quoted key, not preceded by `[A-Za-z0-9_]`, then optional
//! blanks, `:` or `=`, optional blanks, and the value. A quoted value is the
//! bytes up to the matching quote on the same line; an unquoted one runs up
//! to whitespace, `,`, `;`, `#`, `}`, `)` or the end.
//!
//! The "not followed by `[A-Za-z0-9_]`" boundary needs no separate check:
//! the key must be followed by an optional quote, blanks and `:`/`=`.
//!
//! Linear time (D87): a key match inside the previous accepted value is
//! skipped, and each line's end and next quotes are searched once.

use super::{CUSTOM_RULE_ID, Candidate};
use crate::error::{CoreError, Result};
use crate::profile::normalise_key;
use crate::scan::finding::Detector;
use regex::bytes::{Regex, RegexBuilder};

/// The profile's `extra_keys`, compiled once per scan.
#[derive(Default)]
pub(crate) struct ExtraKeys {
    /// D76-normalised names, for the D2/D3 key filter.
    normalised: Vec<String>,
    /// Every key in any spelling that normalises to it, longest first.
    key_re: Option<Regex>,
}

impl ExtraKeys {
    /// D88: a pattern that fails to compile is an error, never a silent
    /// disable.
    pub(crate) fn new(keys: &[String]) -> Result<ExtraKeys> {
        let mut normalised: Vec<String> = keys.iter().map(|k| normalise_key(k)).collect();
        normalised.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        normalised.dedup();
        if normalised.is_empty() {
            return Ok(ExtraKeys::default());
        }
        let alts: Vec<String> = normalised.iter().map(|k| key_pattern(k)).collect();
        // D41: byte mode, ASCII-only classes and case folding.
        let pattern = format!("(?i:{})", alts.join("|"));
        let re = RegexBuilder::new(&pattern).unicode(false).build();
        let key_re = Some(re.map_err(|_| CoreError::ProfileRegex)?);
        Ok(ExtraKeys { normalised, key_re })
    }

    /// D76: `key` equals an extra key after normalisation.
    pub(crate) fn contains(&self, key: &[u8]) -> bool {
        let key = normalise_key(&String::from_utf8_lossy(key));
        self.normalised.contains(&key)
    }
}

/// A normalised key as a pattern: each `_` matches any separator that D76
/// maps to `_`; other characters match literally (any case via `(?i)`).
fn key_pattern(normalised: &str) -> String {
    let parts: Vec<String> = normalised.split('_').map(regex::escape).collect();
    parts.join("[-_. ]")
}

/// Adds one candidate per extra-key assignment with a usable value.
pub(crate) fn detect(extra: &ExtraKeys, content: &[u8], out: &mut Vec<Candidate>) {
    let Some(re) = extra.key_re.as_ref() else {
        return;
    };
    let mut scan = LineScan::new(content);
    let mut accepted_end = 0;
    for m in re.find_iter(content) {
        if m.start() < accepted_end {
            continue;
        }
        let Some((start, end)) = scan.assignment(m.start(), m.end()) else {
            continue;
        };
        accepted_end = end;
        out.push(Candidate {
            start,
            end,
            detector: Detector::D5,
            rule_idx: 0,
            rule_id: CUSTOM_RULE_ID.to_string(),
            key_name: Some(String::from_utf8_lossy(m.as_bytes()).into_owned()),
        });
    }
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_blanks(c: &[u8], mut i: usize) -> usize {
    while matches!(c.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    i
}

/// Forward-only searches over one file. Positions passed in never go
/// backwards, so each cached search result is reused until passed (D87).
struct LineScan<'a> {
    c: &'a [u8],
    /// End of the line containing the last position asked about.
    line_end: usize,
    /// Per quote (`"`, `'`): the next occurrence at or after the last
    /// search start, or `None` meaning "none before `line_end`".
    next_quote: [(usize, Option<usize>); 2],
}

impl<'a> LineScan<'a> {
    fn new(c: &'a [u8]) -> LineScan<'a> {
        LineScan {
            c,
            line_end: 0,
            next_quote: [(usize::MAX, None); 2],
        }
    }

    /// The value span of the assignment whose key is `c[ks..ke]`, if any.
    fn assignment(&mut self, ks: usize, ke: usize) -> Option<(usize, usize)> {
        let c = self.c;
        if ks.checked_sub(1).is_some_and(|i| is_word(c[i])) {
            return None;
        }
        let mut i = ke;
        if matches!(c.get(i), Some(b'"' | b'\'')) {
            i += 1;
        }
        i = skip_blanks(c, i);
        if !matches!(c.get(i), Some(b':' | b'=')) {
            return None;
        }
        self.value_span(skip_blanks(c, i + 1))
    }

    /// A quoted value up to its matching quote on the same line; with no
    /// closing quote, the opening one is dropped and the unquoted rule
    /// applies (as D38 for D2). Empty values and values starting with `${`
    /// or `$(` are rejected before any scan, so a rejected value is O(1).
    fn value_span(&mut self, i: usize) -> Option<(usize, usize)> {
        let q = match self.c.get(i) {
            Some(b'"') => 0,
            Some(b'\'') => 1,
            _ => return unquoted(self.c, i),
        };
        if is_reference(&self.c[i + 1..]) {
            return None;
        }
        match self.find_quote(q, i + 1) {
            Some(close) if close > i + 1 => Some((i + 1, close)),
            Some(_) => None,
            None => unquoted(self.c, i + 1),
        }
    }

    /// The end of the line containing `from` (`\n`, `\r` or the end).
    fn line_end(&mut self, from: usize) -> usize {
        if from >= self.line_end {
            let rest = &self.c[from..];
            let len = rest.iter().position(|&b| b == b'\n' || b == b'\r');
            self.line_end = from + len.unwrap_or(rest.len());
            self.next_quote = [(usize::MAX, None); 2];
        }
        self.line_end
    }

    /// The first quote `q` at or after `from` on the same line.
    fn find_quote(&mut self, q: usize, from: usize) -> Option<usize> {
        let end = self.line_end(from);
        let (searched_from, found) = self.next_quote[q];
        let reuse = searched_from <= from && found.is_none_or(|p| p >= from);
        if reuse {
            return found;
        }
        let byte = b"\"'"[q];
        let hit = self.c[from..end].iter().position(|&b| b == byte);
        let found = hit.map(|p| from + p);
        self.next_quote[q] = (from, found);
        found
    }
}

/// `${` or `$(`: an environment or command reference, not a secret.
fn is_reference(v: &[u8]) -> bool {
    v.starts_with(b"${") || v.starts_with(b"$(")
}

/// An unquoted value; `None` if empty or a reference.
fn unquoted(c: &[u8], i: usize) -> Option<(usize, usize)> {
    if is_reference(&c[i..]) {
        return None;
    }
    let stop = |b: &u8| b.is_ascii_whitespace() || matches!(b, b',' | b';' | b'#' | b'}' | b')');
    let len = c[i..].iter().position(stop).unwrap_or(c.len() - i);
    (len > 0).then_some((i, i + len))
}
