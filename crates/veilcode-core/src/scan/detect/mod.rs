//! Detectors D1–D4 (SPEC §5). Each produces candidate spans; resolve.rs picks.

pub(crate) mod env;
pub(crate) mod gitleaks;
pub(crate) mod php;
pub(crate) mod url;

use crate::scan::finding::Detector;

/// D37 (PROPOSED): rule ids for the built-in detectors.
pub(crate) const ENV_RULE_ID: &str = "env-file";
pub(crate) const PHP_RULE_ID: &str = "php-define";
pub(crate) const URL_RULE_ID: &str = "url-credentials";

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
    /// Index of the rule in gitleaks.toml (D1); 0 for D2–D4.
    pub(crate) rule_idx: usize,
    pub(crate) rule_id: String,
    pub(crate) key_name: Option<String>,
}

/// True if `key` contains one of the SPEC §5 key words, ignoring case.
pub(crate) fn is_secret_key(key: &[u8]) -> bool {
    let upper = key.to_ascii_uppercase();
    KEY_WORDS
        .iter()
        .any(|w| upper.windows(w.len()).any(|win| win == w.as_bytes()))
}

/// Runs D1 → D4 on one text file.
pub(crate) fn detect_file(
    rules: &gitleaks::RuleSet,
    rel_path: &str,
    file_name: &str,
    content: &[u8],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    rules.detect(rel_path, content, &mut out);
    if env::applies(file_name) {
        env::detect(content, &mut out);
    }
    if php::applies(file_name) {
        php::detect(content, &mut out);
    }
    url::detect(content, &mut out);
    out
}
