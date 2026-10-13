//! D2: env files (SPEC §5, D9; D38/D39 PROPOSED).

use super::{Candidate, ENV_RULE_ID, ExtraKeys, is_secret_key};
use crate::scan::finding::Detector;
use regex::bytes::{Regex, RegexBuilder};
use std::sync::LazyLock;

const PATTERN: &str = r"^[ \t]*(export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*([^\r\n]*)$";

/// `(?m)` per SPEC §5, CRLF mode so `$` also matches before `\r` (D39), and
/// byte-wise classes so invalid UTF-8 in a value is matched (D41).
static ENV_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    RegexBuilder::new(PATTERN)
        .multi_line(true)
        .crlf(true)
        .unicode(false)
        .unicode(false)
        .build()
        .ok()
});

/// Files named `.env`, `.env.*` or `*.env`.
pub(crate) fn applies(file_name: &str) -> bool {
    file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env")
}

/// Adds one candidate per secret-named key with a usable value.
pub(crate) fn detect(content: &[u8], extra: &ExtraKeys, out: &mut Vec<Candidate>) {
    let Some(re) = ENV_RE.as_ref() else { return };
    for caps in re.captures_iter(content) {
        let (Some(key), Some(value)) = (caps.get(2), caps.get(3)) else {
            continue;
        };
        if !is_secret_key(key.as_bytes(), extra) {
            continue;
        }
        let (s, e) = value_span(value.as_bytes());
        let secret = &value.as_bytes()[s..e];
        if secret.is_empty() || secret.starts_with(b"${") || secret.starts_with(b"$(") {
            continue;
        }
        out.push(Candidate {
            start: value.start() + s,
            end: value.start() + e,
            detector: Detector::D2,
            rule_idx: 0,
            rule_id: ENV_RULE_ID.to_string(),
            key_name: Some(String::from_utf8_lossy(key.as_bytes()).into_owned()),
        });
    }
}

/// D9 value boundaries, relative to the start of the raw value.
fn value_span(v: &[u8]) -> (usize, usize) {
    if let Some(&q) = v.first().filter(|&&c| c == b'"' || c == b'\'') {
        if let Some(close) = v[1..].iter().position(|&c| c == q) {
            return (1, 1 + close);
        }
        // D38: no closing quote, so drop the opening one and use the unquoted rules.
        let (s, e) = unquoted_span(&v[1..]);
        return (1 + s, 1 + e);
    }
    unquoted_span(v)
}

/// Cut at the first ` #`, then trim trailing spaces and tabs.
fn unquoted_span(v: &[u8]) -> (usize, usize) {
    let mut end = v.windows(2).position(|w| w == b" #").unwrap_or(v.len());
    while end > 0 && matches!(v[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (0, end)
}
