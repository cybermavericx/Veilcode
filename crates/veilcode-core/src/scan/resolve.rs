//! Post-processing (SPEC §5, D10, D48): drop empty spans and spans that are
//! exactly a token, then merge overlapping candidates into their union span,
//! credited to the D10 winner. O(k log k) (D42).

use crate::scan::detect::Candidate;
use crate::token::TOKEN_PATTERN;
use regex::bytes::Regex;
use std::cmp::Ordering;
use std::sync::LazyLock;

/// The token regex anchored at both ends (D48a: only an exact token is dropped).
static EXACT_TOKEN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(&format!("^(?:{TOKEN_PATTERN})$")).ok());

/// D10 order: length desc, detector D1<D2<D3<D4, rule index asc, start asc.
fn d10_order(a: &Candidate, b: &Candidate) -> Ordering {
    (b.end - b.start)
        .cmp(&(a.end - a.start))
        .then(a.detector.cmp(&b.detector))
        .then(a.rule_idx.cmp(&b.rule_idx))
        .then(a.start.cmp(&b.start))
}

/// The accepted candidates of one file, sorted by start, never overlapping.
pub(crate) fn resolve(content: &[u8], cands: Vec<Candidate>) -> Vec<Candidate> {
    let mut cands: Vec<Candidate> = cands
        .into_iter()
        .filter(|c| c.start < c.end && !is_token(&content[c.start..c.end]))
        .collect();
    cands.sort_by_key(|c| c.start);
    // Sweep by start: a candidate starting before the current group's end
    // overlaps the group, so D48b merges the whole connected group.
    // Each group is (winner with its own span, union start, union end).
    let mut groups: Vec<(Candidate, usize, usize)> = Vec::new();
    for c in cands {
        match groups.last_mut() {
            Some((win, _, end)) if c.start < *end => {
                *end = (*end).max(c.end);
                if d10_order(&c, win) == Ordering::Less {
                    *win = c;
                }
            }
            _ => {
                let (start, end) = (c.start, c.end);
                groups.push((c, start, end));
            }
        }
    }
    groups
        .into_iter()
        .map(|(mut win, start, end)| {
            win.start = start;
            win.end = end;
            win
        })
        .collect()
}

/// True if the span is exactly a placeholder token (SPEC §4, D48a).
fn is_token(span: &[u8]) -> bool {
    EXACT_TOKEN.as_ref().is_some_and(|re| re.is_match(span))
}
