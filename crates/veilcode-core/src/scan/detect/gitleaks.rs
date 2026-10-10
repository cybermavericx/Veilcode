//! D1: the vendored gitleaks rules (SPEC §5, D11, D31–D34).
//!
//! Ported from gitleaks v8.30.1, commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e
//! (`detect/detect.go` detectRule, `detect/utils.go` shannonEntropy,
//! `config/allowlist.go`); see docs/VERIFY_LOG.md.
//!
//! Supported rule fields: `id`, `regex`, `secretGroup`, `entropy`, `keywords`,
//! `path`, and `[[rules.allowlists]]` with `regexes`, `regexTarget`,
//! `stopwords`, `paths` and `condition`. Allowlists with `regexTarget = "line"`
//! are dropped with a warning (D47).
//! Ignored: `description`, `tags`, `skipReport`, `required`, the deprecated
//! `[rules.allowlist]` table (absent at the pinned commit), allowlist
//! `description`, the `gitleaks:allow` line marker, decoding passes, and the
//! top-level `title`, `minVersion` and global `[allowlist]` (SPEC §5).
//! Allowlist `commits` can never match (there are no commits here).

use super::Candidate;
use crate::error::{CoreError, Result};
use crate::scan::finding::Detector;
use regex::bytes::{Regex, RegexBuilder, RegexSet, SetMatches};
use serde::Deserialize;

use zeroize::Zeroizing;

/// The vendored rule file (rules/README.md has the tag, commit and sha256).
pub(crate) const RULES_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rules/gitleaks.toml"
));

/// D31: regex's default compiled-size limit is 10 MiB, at which 218 of the 221
/// rule regexes compile; at 50 MiB all 221 do.
const SIZE_LIMIT: usize = 50 * (1 << 20);

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRule {
    id: String,
    regex: Option<String>,
    secret_group: Option<usize>,
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    path: Option<String>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAllowlist {
    regex_target: Option<String>,
    condition: Option<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Secret,
    Match,
}

/// A rule-level allowlist. `*_declared` keeps a criterion whose entries all
/// failed to compile from silently disappearing (D33: never "allow everything").
struct Allowlist {
    target: Target,
    and: bool,
    has_commits: bool,
    paths_declared: bool,
    paths: Vec<Regex>,
    regexes_declared: bool,
    regexes: Vec<Regex>,
    stopwords: Vec<Vec<u8>>,
}

/// A compiled rule.
pub(crate) struct Rule {
    /// Position in gitleaks.toml (overlap tie-break, D10).
    pub(crate) idx: usize,
    pub(crate) id: String,
    pub(crate) entropy: f64,
    regex: Regex,
    secret_group: usize,
    /// Indexes into `RuleSet::keywords`; empty means the rule always runs.
    keywords: Vec<usize>,
    path: Option<Regex>,
    allowlists: Vec<Allowlist>,
}

/// All compiled rules plus load statistics.
pub(crate) struct RuleSet {
    pub(crate) rules: Vec<Rule>,
    /// Rules with a `regex`.
    pub(crate) supported: usize,
    /// Path-only rules (no `regex`), skipped.
    pub(crate) unsupported: usize,
    /// Rules or allowlist entries that failed to compile.
    pub(crate) warnings: Vec<String>,
    /// Allowlist tables or entries dropped (D33, D47).
    pub(crate) allowlist_warnings: Vec<String>,
    keywords: RegexSet,
}

#[cfg(test)]
thread_local! {
    static EVALS: std::cell::RefCell<std::collections::BTreeMap<String, u32>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

/// Number of times rule `id` was run on a file on this thread (S6).
#[cfg(test)]
pub(crate) fn rule_evals(id: &str) -> u32 {
    EVALS.with(|m| m.borrow().get(id).copied().unwrap_or(0))
}

/// D32: ASCII-only classes and the D31 size limit, like Go RE2.
fn build_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(SIZE_LIMIT)
        .unicode(false)
        .build()
}

impl RuleSet {
    /// Parses and compiles the vendored rules. Bad rules become warnings.
    pub(crate) fn load() -> Result<RuleSet> {
        let raw: RawConfig = toml::from_str(RULES_TOML).map_err(|_| CoreError::RulesLoad)?;
        let mut kw = Keywords::default();
        let mut set = RuleSet {
            rules: Vec::new(),
            supported: 0,
            unsupported: 0,
            warnings: Vec::new(),
            allowlist_warnings: Vec::new(),
            keywords: RegexSet::empty(),
        };
        for (idx, r) in raw.rules.into_iter().enumerate() {
            set.add_rule(idx, r, &mut kw);
        }
        set.keywords = RegexSet::new(kw.list.iter().map(|k| regex::escape(k)))
            .map_err(|_| CoreError::RulesLoad)?;
        Ok(set)
    }

    fn add_rule(&mut self, idx: usize, r: RawRule, kw: &mut Keywords) {
        let Some(pattern) = r.regex.as_deref() else {
            self.unsupported += 1;
            return;
        };
        self.supported += 1;
        let regex = build_regex(pattern);
        let path = r.path.as_deref().map(build_regex).transpose();
        let (Ok(regex), Ok(path)) = (regex, path) else {
            self.warnings.push(format!(
                "gitleaks rule `{}` skipped: regex does not compile",
                r.id
            ));
            return;
        };
        let allowlists = r
            .allowlists
            .iter()
            .filter_map(|a| compile_allowlist(&r.id, a, &mut self.allowlist_warnings))
            .collect();
        self.rules.push(Rule {
            idx,
            entropy: r.entropy.unwrap_or(0.0),
            regex,
            secret_group: r.secret_group.unwrap_or(0),
            keywords: r.keywords.iter().map(|k| kw.index(k)).collect(),
            path,
            allowlists,
            id: r.id,
        });
    }

    /// Runs every applicable rule on one text file.
    pub(crate) fn detect(&self, rel_path: &str, content: &[u8], out: &mut Vec<Candidate>) {
        // Upstream lowercases the content and the keywords (Unicode ToLower);
        // the keywords are ASCII, so ASCII lowercasing finds the same hits.
        let lower = Zeroizing::new(content.to_ascii_lowercase());
        let hits = self.keywords.matches(&lower);
        for rule in &self.rules {
            if rule.keyword_hit(&hits) && rule.file_applies(rel_path) {
                rule.find(rel_path, content, out);
            }
        }
    }
}

/// Unique lowercased keywords across all rules.
#[derive(Default)]
struct Keywords {
    list: Vec<String>,
}

impl Keywords {
    fn index(&mut self, k: &str) -> usize {
        let k = k.to_lowercase();
        if let Some(i) = self.list.iter().position(|x| *x == k) {
            return i;
        }
        self.list.push(k);
        self.list.len() - 1
    }
}

impl Rule {
    fn keyword_hit(&self, hits: &SetMatches) -> bool {
        self.keywords.is_empty() || self.keywords.iter().any(|&k| hits.matched(k))
    }

    /// Rule-allowlist path check, then the rule `path` (detect.go l.388-424).
    fn file_applies(&self, rel_path: &str) -> bool {
        if self.allowlists.iter().any(|a| a.file_allowed(rel_path)) {
            return false;
        }
        self.path
            .as_ref()
            .is_none_or(|p| p.is_match(rel_path.as_bytes()))
    }

    fn find(&self, rel_path: &str, content: &[u8], out: &mut Vec<Candidate>) {
        #[cfg(test)]
        EVALS.with(|m| *m.borrow_mut().entry(self.id.clone()).or_insert(0) += 1);
        for m in self.regex.find_iter(content) {
            let (s, e) = trim_newlines(content, m.start(), m.end());
            let matched = &content[s..e];
            let Some((gs, ge)) = self.select_secret(matched) else {
                continue;
            };
            let secret = &matched[gs..ge];
            if self.entropy != 0.0 && shannon(secret) <= self.entropy {
                continue;
            }
            let ctx = Ctx {
                rel_path,
                secret,
                matched,
            };
            if self.allowlists.iter().any(|a| a.finding_allowed(&ctx)) {
                continue;
            }
            out.push(Candidate {
                start: s + gs,
                end: s + ge,
                detector: Detector::D1,
                rule_idx: self.idx,
                rule_id: self.id.clone(),
                key_name: None,
            });
        }
    }

    /// D34: re-run the regex on the match text and pick the secret group.
    /// `None` skips the match (out-of-range or empty group).
    fn select_secret(&self, matched: &[u8]) -> Option<(usize, usize)> {
        let whole = Some((0, matched.len()));
        let Some(caps) = self.regex.captures(matched) else {
            return whole;
        };
        if caps.len() < 2 {
            return whole;
        }
        if self.secret_group > 0 {
            let g = caps.get(self.secret_group)?;
            return (!g.is_empty()).then(|| (g.start(), g.end()));
        }
        (1..caps.len())
            .filter_map(|i| caps.get(i))
            .find(|g| !g.is_empty())
            .map_or(whole, |g| Some((g.start(), g.end())))
    }
}

/// `strings.Trim(match, "\n")` as offsets.
fn trim_newlines(content: &[u8], mut s: usize, mut e: usize) -> (usize, usize) {
    while s < e && content[s] == b'\n' {
        s += 1;
    }
    while e > s && content[e - 1] == b'\n' {
        e -= 1;
    }
    (s, e)
}

/// Shannon entropy as upstream computes it (D34): counts per char of the
/// lossy-UTF-8 string, divided by the byte length. The chars are counted as
/// runs of a sorted, zeroized buffer, so no frequency table outlives the call.
pub(crate) fn shannon(secret: &[u8]) -> f64 {
    if secret.is_empty() {
        return 0.0;
    }
    let text = Zeroizing::new(String::from_utf8_lossy(secret).into_owned());
    let mut chars: Zeroizing<Vec<u32>> = Zeroizing::new(text.chars().map(u32::from).collect());
    chars.sort_unstable();
    let inv = 1.0 / secret.len() as f64;
    chars.chunk_by(|a, b| a == b).fold(0.0, |h, run| {
        let freq = run.len() as f64 * inv;
        h - freq * freq.log2()
    })
}

/// What a finding-level allowlist check looks at.
struct Ctx<'a> {
    rel_path: &'a str,
    secret: &'a [u8],
    matched: &'a [u8],
}

impl Allowlist {
    fn path_hit(&self, rel_path: &str) -> bool {
        self.paths.iter().any(|p| p.is_match(rel_path.as_bytes()))
    }

    /// checkCommitOrPathAllowed (detect.go l.767-821).
    fn file_allowed(&self, rel_path: &str) -> bool {
        if !self.and {
            return self.path_hit(rel_path);
        }
        if self.regexes_declared || !self.stopwords.is_empty() {
            return false; // checked per finding
        }
        !self.has_commits && (!self.paths_declared || self.path_hit(rel_path))
    }

    /// checkFindingAllowed (detect.go l.823-891).
    fn finding_allowed(&self, ctx: &Ctx<'_>) -> bool {
        let target = match self.target {
            Target::Secret => ctx.secret,
            Target::Match => ctx.matched,
        };
        let regex_hit = !target.is_empty() && self.regexes.iter().any(|r| r.is_match(target));
        let stop_hit = self.stopword_hit(ctx.secret);
        if !self.and {
            return regex_hit || stop_hit;
        }
        !self.has_commits
            && (!self.paths_declared || self.path_hit(ctx.rel_path))
            && (!self.regexes_declared || regex_hit)
            && (self.stopwords.is_empty() || stop_hit)
    }

    /// Stopwords are always tested against the lowercased secret.
    fn stopword_hit(&self, secret: &[u8]) -> bool {
        if secret.is_empty() {
            return false;
        }
        let lower = Zeroizing::new(secret.to_ascii_lowercase());
        self.stopwords
            .iter()
            .any(|w| lower.windows(w.len()).any(|win| win == w.as_slice()))
    }
}

/// regexTarget and condition as upstream parses them; `None` if either is unknown.
fn parse_mode(a: &RawAllowlist) -> Option<(Target, bool)> {
    let target = match a.regex_target.as_deref() {
        None | Some("") | Some("secret") => Target::Secret,
        Some("match") => Target::Match,
        Some(_) => return None,
    };
    let and = match a.condition.as_deref().map(str::to_uppercase).as_deref() {
        Some("AND" | "&&") => true,
        None | Some("" | "OR" | "||") => false,
        Some(_) => return None,
    };
    Some((target, and))
}

/// Compiles one allowlist; `None` (with a warning) if it is unusable.
fn compile_allowlist(id: &str, a: &RawAllowlist, warnings: &mut Vec<String>) -> Option<Allowlist> {
    if a.regex_target.as_deref() == Some("line") {
        // D47: line contents are attacker-controlled, so never suppress on them.
        warnings.push(format!(
            "gitleaks rule `{id}`: line-target allowlist dropped"
        ));
        return None;
    }
    let Some((target, and)) = parse_mode(a) else {
        warnings.push(format!(
            "gitleaks rule `{id}`: allowlist dropped (bad regexTarget or condition)"
        ));
        return None;
    };
    let mut compile = |list: &[String]| -> Vec<Regex> {
        list.iter()
            .filter_map(|p| allowlist_regex(id, p, warnings))
            .collect()
    };
    let (paths, regexes) = (compile(&a.paths), compile(&a.regexes));
    Some(Allowlist {
        target,
        and,
        has_commits: !a.commits.is_empty(),
        paths_declared: !a.paths.is_empty(),
        paths,
        regexes_declared: !a.regexes.is_empty(),
        regexes,
        stopwords: a
            .stopwords
            .iter()
            .map(|w| w.to_lowercase().into_bytes())
            .collect(),
    })
}

/// D33: compile, retry with literal `{` escaped, else drop the entry with a warning.
fn allowlist_regex(id: &str, pattern: &str, warnings: &mut Vec<String>) -> Option<Regex> {
    if let Ok(re) = build_regex(pattern) {
        return Some(re);
    }
    if let Ok(re) = build_regex(&escape_literal_braces(pattern)) {
        return Some(re);
    }
    warnings.push(format!(
        "gitleaks rule `{id}`: one allowlist regex dropped (does not compile)"
    ));
    None
}

/// Escapes every `{` that does not start `{n}`, `{n,}` or `{n,m}`.
pub(crate) fn escape_literal_braces(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut chars = pattern.char_indices();
    while let Some((i, c)) = chars.next() {
        out.push(c);
        if c == '\\' {
            if let Some((_, next)) = chars.next() {
                out.push(next);
            }
        } else if c == '{' && !is_quantifier(&pattern.as_bytes()[i..]) {
            out.pop();
            out.push_str("\\{");
        }
    }
    out
}

/// True if `s` starts with `{n}`, `{n,}` or `{n,m}`.
fn is_quantifier(s: &[u8]) -> bool {
    let Some(close) = s.iter().position(|&c| c == b'}') else {
        return false;
    };
    let inner = &s[1..close];
    let mut parts = inner.splitn(2, |&c| c == b',');
    let n = parts.next().unwrap_or_default();
    let m = parts.next();
    let digits = |p: &[u8]| p.iter().all(u8::is_ascii_digit);
    !n.is_empty() && digits(n) && m.is_none_or(digits)
}
