//! D3: PHP `define('KEY', 'value')` (SPEC §5). Values holding a quote are not detected.

use super::{Candidate, PHP_RULE_ID, is_secret_key};
use crate::scan::finding::Detector;
use regex::bytes::{Regex, RegexBuilder};
use std::sync::LazyLock;

/// D49: whitespace is allowed between `define` and `(`.
const PATTERN: &str = r#"define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)"#;

/// D41: byte-wise, so values holding invalid UTF-8 are matched.
static PHP_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| RegexBuilder::new(PATTERN).unicode(false).build().ok());

/// Files named `*.php`.
pub(crate) fn applies(file_name: &str) -> bool {
    file_name.ends_with(".php")
}

/// Adds one candidate per secret-named constant.
pub(crate) fn detect(content: &[u8], out: &mut Vec<Candidate>) {
    let Some(re) = PHP_RE.as_ref() else { return };
    for caps in re.captures_iter(content) {
        let (Some(key), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if !is_secret_key(key.as_bytes()) {
            continue;
        }
        out.push(Candidate {
            start: value.start(),
            end: value.end(),
            detector: Detector::D3,
            rule_idx: 0,
            rule_id: PHP_RULE_ID.to_string(),
            key_name: Some(String::from_utf8_lossy(key.as_bytes()).into_owned()),
        });
    }
}
