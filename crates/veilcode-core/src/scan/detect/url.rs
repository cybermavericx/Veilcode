//! D4: credentials in URLs, `scheme://user:password@` (SPEC §5). Only the password.

use super::{Candidate, URL_RULE_ID};
use crate::scan::finding::Detector;
use regex::bytes::{Regex, RegexBuilder};
use std::sync::LazyLock;

/// D50: the password is greedy up to the last `@` before the first `/` or whitespace.
const PATTERN: &str = r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s/]+)@";

/// D41: byte-wise, so passwords holding invalid UTF-8 are matched.
static URL_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| RegexBuilder::new(PATTERN).unicode(false).build().ok());

/// Adds one candidate per URL password.
pub(crate) fn detect(content: &[u8], out: &mut Vec<Candidate>) {
    let Some(re) = URL_RE.as_ref() else { return };
    for caps in re.captures_iter(content) {
        let Some(pw) = caps.get(1) else { continue };
        out.push(Candidate {
            start: pw.start(),
            end: pw.end(),
            detector: Detector::D4,
            rule_idx: 0,
            rule_id: URL_RULE_ID.to_string(),
            key_name: None,
        });
    }
}
