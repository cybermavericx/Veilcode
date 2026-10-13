//! Detectors D1–D5 (SPEC §5). Each produces candidate spans; resolve.rs picks.

pub(crate) mod custom;
pub(crate) mod env;
pub(crate) mod gitleaks;
pub(crate) mod php;
pub(crate) mod url;

use crate::scan::finding::Detector;
use custom::ExtraKeys;

/// D37 (PROPOSED): rule ids for the built-in detectors.
pub(crate) const ENV_RULE_ID: &str = "env-file";
pub(crate) const PHP_RULE_ID: &str = "php-define";
pub(crate) const URL_RULE_ID: &str = "url-credentials";
/// D77: rule id for D5.
pub(crate) const CUSTOM_RULE_ID: &str = "custom-key";

/// The key names D2 and D3 accept (case-insensitive substring, SPEC §5).
const KEY_WORDS: [&str; 10] = [
    "PASS",
    "PWD",
    "SECRET",
    "TOKEN",
    "KEY",
    "SALT",
    "AUTH",
    "CREDENTIAL",
    "DSN",
    "PRIVATE",
];

/// A candidate secret span in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) detector: Detector,
    /// Index of the rule in gitleaks.toml (D1); 0 for D2–D5.
    pub(crate) rule_idx: usize,
    pub(crate) rule_id: String,
    pub(crate) key_name: Option<String>,
}

/// True if `key` contains one of the SPEC §5 key words, ignoring case, or
/// equals a profile extra key after D76 normalisation.
pub(crate) fn is_secret_key(key: &[u8], extra: &ExtraKeys) -> bool {
    let upper = key.to_ascii_uppercase();
    let builtin = KEY_WORDS
        .iter()
        .any(|w| upper.windows(w.len()).any(|win| win == w.as_bytes()));
    builtin || extra.contains(key)
}

/// Runs D1 → D5 on one text file.
pub(crate) fn detect_file(
    rules: &gitleaks::RuleSet,
    extra: &ExtraKeys,
    rel_path: &str,
    file_name: &str,
    content: &[u8],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    rules.detect(rel_path, content, &mut out);
    if env::applies(file_name) {
        env::detect(content, extra, &mut out);
    }
    if php::applies(file_name) {
        php::detect(content, extra, &mut out);
    }
    url::detect(content, &mut out);
    custom::detect(extra, content, &mut out);
    out
}

/// Runs D1 → D4 on pasted text: D2 and D3 apply regardless of file name.
pub(crate) fn detect_all(rules: &gitleaks::RuleSet, content: &[u8]) -> Vec<Candidate> {
    let mut out = Vec::new();
    rules.detect("", content, &mut out);
    let none = ExtraKeys::default();
    env::detect(content, &none, &mut out);
    php::detect(content, &none, &mut out);
    url::detect(content, &mut out);
    out
}
