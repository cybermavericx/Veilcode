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
    let mut groups: Vec<Group> = Vec::new();
    for c in cands {
        match groups.last_mut() {
            Some(g) if c.start < g.end => g.add(c),
            _ => groups.push(Group::new(c)),
        }
    }
    groups.into_iter().map(Group::finish).collect()
}

/// One connected group of overlapping candidates (D48b).
struct Group {
    /// The D10 winner, with its own span.
    win: Candidate,
    /// D86: the key name of the first keyed candidate in D10 order.
    keyed: Option<(Candidate, String)>,
    start: usize,
    end: usize,
}

impl Group {
    fn new(c: Candidate) -> Group {
        let mut g = Group {
            start: c.start,
            end: c.end,
            keyed: None,
            win: c.clone(),
        };
        g.note_key(c);
        g
    }

    fn add(&mut self, c: Candidate) {
        self.end = self.end.max(c.end);
        if d10_order(&c, &self.win) == Ordering::Less {
            self.win = c.clone();
        }
        self.note_key(c);
    }

    fn note_key(&mut self, c: Candidate) {
        let Some(key) = c.key_name.clone() else {
            return;
        };
        let first = match &self.keyed {
            Some((k, _)) => d10_order(&c, k) == Ordering::Less,
            None => true,
        };
        if first {
            self.keyed = Some((c, key));
        }
    }

    /// The winner over the union span, carrying the D86 key name.
    fn finish(self) -> Candidate {
        let mut win = self.win;
        win.start = self.start;
        win.end = self.end;
        if let Some((_, key)) = self.keyed {
            win.key_name = Some(key);
        }
        win
    }
}

/// True if the span is exactly a placeholder token (SPEC §4, D48a).
fn is_token(span: &[u8]) -> bool {
    EXACT_TOKEN.as_ref().is_some_and(|re| re.is_match(span))
}
