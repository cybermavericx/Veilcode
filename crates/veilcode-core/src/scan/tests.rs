//! P2 scanner tests S1–S19 (TEST_CASES.md). Secrets are generated at runtime.

use super::detect::gitleaks::{self, RULES_TOML, RuleSet};
use super::detect::{Candidate, ENV_RULE_ID};
use super::finding::finding_id;
use super::resolve::resolve;
use super::*;
use crate::rng::OsRandom;
use crate::test_support::{
    assert_no_secret, fake_github_pat, fake_password, random_alnum, write_tree,
};
use crate::token::TokenGen;
use std::path::Path;

fn run(dir: &Path) -> ScanReport {
    scan(dir, &ScanOptions::default(), &crate::Profile::default()).expect("scan")
}

fn json(report: &ScanReport) -> Vec<u8> {
    serde_json::to_vec(report).expect("json")
}

/// Fails unless the finding's span equals `want`; the message never shows bytes.
fn assert_span(dir: &Path, f: &Finding, want: impl AsRef<[u8]>) {
    let bytes = std::fs::read(dir.join(&f.rel_path)).expect("read");
    let got = bytes.get(f.start..f.end).unwrap_or_default();
    assert!(
        got == want.as_ref(),
        "span mismatch at {}:{}",
        f.rel_path,
        f.start
    );
}

/// The id of the vendored rule whose keywords contain `keyword`.
fn vendored_rule_id(keyword: &str) -> String {
    let table: toml::Table = toml::from_str(RULES_TOML).expect("toml");
    let rules = table["rules"].as_array().expect("rules");
    let rule = rules
        .iter()
        .find(|r| {
            r.get("keywords")
                .and_then(|k| k.as_array())
                .is_some_and(|k| k.iter().any(|v| v.as_str() == Some(keyword)))
                && r.get("regex").is_some()
        })
        .expect("rule with keyword");
    rule["id"].as_str().expect("id").to_string()
}

fn pat_rule_id() -> String {
    vendored_rule_id(&["gh", "p_"].concat())
}

#[test]
fn s1_env_detection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let body = format!("DB_PASSWORD={pw}\nAPP_NAME=demo\n");
    write_tree(dir.path(), &[(".env", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.detector, Detector::D2);
    assert_eq!(f.key_name.as_deref(), Some("DB_PASSWORD"));
    assert_eq!(f.rule_id, ENV_RULE_ID);
    assert_span(dir.path(), f, &pw);
    assert_no_secret(&json(&r), &[&pw]);
}

#[test]
fn s2_php_define() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pw, k) = (fake_password(), fake_password());
    let body = format!("<?php\ndefine('DB_PASSWORD','{pw}');\ndefine( \"AUTH_KEY\" , \"{k}\" );\n");
    write_tree(dir.path(), &[("wp-config.php", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 2);
    let keys: Vec<_> = r.findings.iter().map(|f| f.key_name.clone()).collect();
    assert_eq!(
        keys,
        vec![Some("DB_PASSWORD".into()), Some("AUTH_KEY".into())]
    );
    assert!(r.findings.iter().all(|f| f.detector == Detector::D3));
    assert_span(dir.path(), &r.findings[0], &pw);
    assert_span(dir.path(), &r.findings[1], &k);
    assert_no_secret(&json(&r), &[&pw, &k]);
}

#[test]
fn s3_url_credentials() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let body = format!("url: postgres://u:{pw}@h/db\n");
    write_tree(dir.path(), &[("config.yml", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.detector, Detector::D4);
    assert_eq!(f.key_name, None);
    assert_span(dir.path(), f, &pw);
    assert_no_secret(&json(&r), &[&pw]);
}

#[test]
fn s4_github_pat() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pat = fake_github_pat();
    let body = format!("const t = \"{pat}\";\n");
    write_tree(dir.path(), &[("config.js", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.detector, Detector::D1);
    assert_eq!(f.rule_id, pat_rule_id());
    assert_span(dir.path(), f, &pat);
    assert_no_secret(&json(&r), &[&pat]);
}

#[test]
fn s5_entropy_gate() {
    let id = pat_rule_id();
    let rules = RuleSet::load().expect("rules");
    let rule = rules.rules.iter().find(|r| r.id == id).expect("pat rule");
    assert!(rule.entropy > 0.0, "chosen rule must set entropy");
    let prefix = ["gh", "p_"].concat();
    let low = format!("{prefix}{}", "a".repeat(36));
    let high = fake_github_pat();
    assert!(gitleaks::shannon(low.as_bytes()) <= rule.entropy);
    assert!(gitleaks::shannon(high.as_bytes()) > rule.entropy);
    let dir = tempfile::tempdir().expect("tempdir");
    write_tree(dir.path(), &[("low.txt", format!("x {low}\n").as_bytes())]);
    write_tree(
        dir.path(),
        &[("high.txt", format!("x {high}\n").as_bytes())],
    );
    let r = run(dir.path());
    let hits: Vec<_> = r.findings.iter().filter(|f| f.rule_id == id).collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rel_path, "high.txt");
    assert_no_secret(&json(&r), &[&high]);
}

#[test]
fn s6_keyword_prefilter() {
    let id = pat_rule_id();
    let dir = tempfile::tempdir().expect("tempdir");
    write_tree(dir.path(), &[("a.txt", b"nothing to see here\n")]);
    let before = gitleaks::rule_evals(&id);
    run(dir.path());
    assert_eq!(gitleaks::rule_evals(&id), before);
    // Control: a file holding the keyword does evaluate the rule once.
    write_tree(dir.path(), &[("b.txt", ["gh", "p_\n"].concat().as_bytes())]);
    run(dir.path());
    assert_eq!(gitleaks::rule_evals(&id), before + 1);
}

fn cand(start: usize, end: usize, detector: Detector, rule_idx: usize) -> Candidate {
    Candidate {
        start,
        end,
        detector,
        rule_idx,
        rule_id: format!("r{rule_idx}"),
        key_name: None,
    }
}

#[test]
fn s7_overlap_resolution() {
    let content = vec![b'x'; 100];
    let input = vec![
        cand(2, 5, Detector::D1, 0),   // B inside a longer D2 span A
        cand(0, 10, Detector::D2, 0),  // A: longer, wins; union = A
        cand(20, 26, Detector::D3, 0), // same length as the D1 below: D1 wins
        cand(22, 28, Detector::D1, 9), // union 20..28
        cand(42, 46, Detector::D1, 1), // chain: B ⊂ A
        cand(40, 50, Detector::D4, 0), // A: longest of the chain, wins
        cand(45, 52, Detector::D1, 2), // C ∩ B (and A)
        cand(51, 58, Detector::D1, 3), // D ∩ C only: still merged, union 40..58
        cand(70, 75, Detector::D1, 5), // same span, higher rule index: loses
        cand(70, 75, Detector::D1, 4),
        cand(80, 80, Detector::D1, 0), // empty: dropped
        cand(90, 96, Detector::D2, 0), // partial overlap: longer D2 wins
        cand(94, 99, Detector::D1, 0), // union 90..99
        cand(60, 64, Detector::D1, 7), // touches nothing: kept as is
        cand(64, 66, Detector::D1, 8), // adjacent (not overlapping): kept
    ];
    let known = crate::token::KnownPrefixes::default();
    let got: Vec<_> = resolve(&content, input, &known)
        .into_iter()
        .map(|c| (c.start, c.end, c.detector, c.rule_idx))
        .collect();
    let want = vec![
        (0, 10, Detector::D2, 0),
        (20, 28, Detector::D1, 9),
        (40, 58, Detector::D4, 0),
        (60, 64, Detector::D1, 7),
        (64, 66, Detector::D1, 8),
        (70, 75, Detector::D1, 4),
        (90, 99, Detector::D2, 0),
    ];
    assert_eq!(got, want);
}

#[test]
fn s8_existing_tokens_ignored() {
    let token = TokenGen::new(OsRandom)
        .generate("API_KEY", &Default::default(), |_| false, &[])
        .expect("token");
    let dir = tempfile::tempdir().expect("tempdir");
    let body = format!("API_KEY={}\n", token.as_str());
    write_tree(dir.path(), &[(".env", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings, vec![]);
    assert_eq!(r.scanned_files.len(), 1);
}

#[test]
fn s9_binary_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pat = fake_github_pat();
    let mut body = b"head\0".to_vec();
    body.extend_from_slice(format!(" {pat}\n").as_bytes());
    write_tree(dir.path(), &[("bin.dat", &body)]);
    let r = run(dir.path());
    assert_eq!(r.findings, vec![]);
    assert_eq!(r.skipped.binary, vec!["bin.dat".to_string()]);
    assert_eq!(r.scanned_files, vec![]);
    assert_no_secret(&json(&r), &[&pat]);
}

#[test]
fn s10_oversized_skipped() {
    const LIMIT: usize = 5 * 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let pat = fake_github_pat();
    let tail = format!(" {pat}\n");
    let mut exact = vec![b'a'; LIMIT - tail.len()];
    exact.extend_from_slice(tail.as_bytes());
    assert_eq!(exact.len(), LIMIT);
    let big = vec![b'a'; LIMIT + 1];
    write_tree(dir.path(), &[("big.txt", &big), ("exact.txt", &exact)]);
    let r = run(dir.path());
    assert_eq!(r.skipped.oversized, vec!["big.txt".to_string()]);
    let scanned: Vec<_> = r
        .scanned_files
        .iter()
        .map(|s| s.rel_path.as_str())
        .collect();
    assert_eq!(scanned, vec!["exact.txt"]);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].rel_path, "exact.txt");
    assert_eq!(r.findings[0].start, LIMIT - pat.len() - 1);
    assert_no_secret(&json(&r), &[&pat]);
}

#[test]
fn s11_git_always_excluded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (p1, p2, p3) = (fake_github_pat(), fake_github_pat(), fake_github_pat());
    write_tree(
        dir.path(),
        &[
            (".git/config", format!("t = {p1}\n").as_bytes()),
            ("sub/.git/config", format!("t = {p2}\n").as_bytes()),
            ("node_modules/x.js", format!("t = {p3}\n").as_bytes()),
        ],
    );
    let opts = ScanOptions {
        no_default_excludes: true,
    };
    let r = scan(dir.path(), &opts, &crate::Profile::default()).expect("scan");
    let paths: Vec<_> = r.findings.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(paths, vec!["node_modules/x.js"]);
    assert_eq!(
        r.skipped.excluded,
        vec![".git".to_string(), "sub/.git".to_string()]
    );
    let r = run(dir.path());
    assert_eq!(r.findings, vec![]);
    assert_eq!(r.skipped.excluded, vec![".git", "node_modules", "sub/.git"]);
    assert_no_secret(&json(&r), &[&p1, &p2, &p3]);
}

#[test]
fn s12_veilcodeignore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pw1, pw2) = (fake_password(), fake_password());
    write_tree(
        dir.path(),
        &[
            (".veilcodeignore", b"# comment\n\nsecrets/**\n"),
            ("secrets/a.env", format!("DB_PASSWORD={pw1}\n").as_bytes()),
            ("other.env", format!("DB_PASSWORD={pw2}\n").as_bytes()),
        ],
    );
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].rel_path, "other.env");
    assert_eq!(r.skipped.excluded, vec!["secrets/a.env".to_string()]);
    assert_eq!(r.warnings.len(), {
        let rs = RuleSet::load().expect("rules");
        rs.warnings.len() + rs.allowlist_warnings.len()
    });
    assert_no_secret(&json(&r), &[&pw1, &pw2]);
}

#[cfg(unix)]
#[test]
fn s13_symlinks_not_followed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    let pat = fake_github_pat();
    write_tree(
        outside.path(),
        &[("real.js", format!("t = {pat}\n").as_bytes())],
    );
    std::os::unix::fs::symlink(outside.path().join("real.js"), dir.path().join("link.js"))
        .expect("symlink");
    std::os::unix::fs::symlink(outside.path(), dir.path().join("linkdir")).expect("symlink");
    let r = run(dir.path());
    assert_eq!(r.findings, vec![]);
    assert_eq!(
        r.skipped.symlink,
        vec!["link.js".to_string(), "linkdir".to_string()]
    );
    assert_eq!(r.scanned_files, vec![]);
    assert_no_secret(&json(&r), &[&pat]);
}

#[test]
fn s14_findings_json_holds_no_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pw, k, u, pat) = (
        fake_password(),
        fake_password(),
        fake_password(),
        fake_github_pat(),
    );
    write_tree(
        dir.path(),
        &[
            (".env", format!("DB_PASSWORD={pw}\n").as_bytes()),
            ("a.php", format!("define('AUTH_KEY', '{k}');\n").as_bytes()),
            (
                "b.txt",
                format!("x redis://me:{u}@host/ {pat}\n").as_bytes(),
            ),
        ],
    );
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 4);
    let out = json(&r);
    assert_no_secret(&out, &[&pw, &k, &u, &pat]);
    let debug = format!("{r:?}");
    assert_no_secret(debug.as_bytes(), &[&pw, &k, &u, &pat]);
}

#[test]
fn s15_gitleaks_rule_compile_rate() {
    let rules = RuleSet::load().expect("rules");
    let compiled = rules.rules.len();
    assert!(rules.supported > 0);
    assert!(compiled as f64 / rules.supported as f64 >= 0.95);
    assert_eq!(rules.supported - compiled, rules.warnings.len());
    assert_eq!(rules.unsupported, 1, "path-only rules at the pinned commit");
    // D31/D33 at the pinned commit: all 221 rules and every allowlist entry compile.
    assert_eq!((rules.supported, compiled), (221, 221));
    assert_eq!(rules.warnings, Vec::<String>::new());
}

#[test]
fn s16_non_utf8_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let mut body = b"# caf\xe9 \xff\xfe\n".to_vec();
    body.extend_from_slice(format!("DB_PASSWORD={pw}\n").as_bytes());
    write_tree(dir.path(), &[(".env", &body)]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    assert_span(dir.path(), &r.findings[0], &pw);
    assert_eq!(r.findings[0].line, 2);
    assert_no_secret(&json(&r), &[&pw]);
}

#[test]
fn s17_crlf_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let body = format!("DB_PASSWORD={pw}\r\nOTHER=1\r\n");
    write_tree(dir.path(), &[(".env", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!((f.start, f.end), (12, 12 + pw.len()));
    assert_span(dir.path(), f, &pw);
    assert_no_secret(&json(&r), &[&pw]);
}

#[test]
fn s18_env_value_forms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (v1, v2, v3) = (fake_password(), fake_password(), fake_password());
    let body = format!(
        "export TOKEN=\"{v1}\"\nSECRET='{v2}'\nKEY={v3} # note\nPASS=\nAUTH=${{FROM_ENV}}\nAUTH=$(cmd)\n"
    );
    write_tree(dir.path(), &[("app.env", body.as_bytes())]);
    let r = run(dir.path());
    let keys: Vec<_> = r.findings.iter().map(|f| f.key_name.as_deref()).collect();
    assert_eq!(keys, vec![Some("TOKEN"), Some("SECRET"), Some("KEY")]);
    for (f, v) in r.findings.iter().zip([&v1, &v2, &v3]) {
        assert_span(dir.path(), f, v);
    }
    assert_no_secret(&json(&r), &[&v1, &v2, &v3]);
}

#[test]
fn s19_position_format() {
    let dir = tempfile::tempdir().expect("tempdir");
    let v = random_alnum(4) + &fake_password();
    let body = format!("A=1\nB=2\nKEY={v}\n");
    write_tree(dir.path(), &[("sub/dir/.env", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!((f.line, f.column), (3, 5));
    assert_eq!(f.rel_path, "sub/dir/.env");
    assert_eq!(f.start, 12);
    assert_eq!(
        f.id,
        finding_id("sub/dir/.env", f.start, f.end, ENV_RULE_ID)
    );
    assert_eq!(f.id.len(), 16);
    let preview = format!("{}…({})", &v[..4], v.chars().count());
    assert_eq!(f.preview, preview);
    assert_no_secret(&json(&r), &[&v]);
}

#[test]
fn d33_literal_brace_escape() {
    use super::detect::gitleaks::escape_literal_braces;
    assert_eq!(escape_literal_braces("{{[^}]+}}"), r"\{\{[^}]+}}");
    assert_eq!(
        escape_literal_braces(r"a{2}b{3,}c{1,4}\{x"),
        r"a{2}b{3,}c{1,4}\{x"
    );
    assert_eq!(
        escape_literal_braces(r"import[ \t]+{[ \t\w,]+}"),
        r"import[ \t]+\{[ \t\w,]+}"
    );
}

#[test]
fn s2b_php_define_space_before_bracket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let body = format!("<?php define (\"DB_PASSWORD\" , \"{pw}\") ;\n");
    write_tree(dir.path(), &[("a.php", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].detector, Detector::D3);
    assert_span(dir.path(), &r.findings[0], &pw);
    assert_no_secret(&json(&r), &[&pw]);
}

#[test]
fn s3c_raw_at_in_url_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let body = format!("db = mysql://u:pa@ss{pw}@h/db\n");
    write_tree(dir.path(), &[("c.txt", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].detector, Detector::D4);
    assert_span(dir.path(), &r.findings[0], format!("pa@ss{pw}"));
    assert_no_secret(&json(&r), &[&pw]);
}

#[test]
fn s8b_token_plus_bytes_is_kept() {
    let token = TokenGen::new(OsRandom)
        .generate("X", &Default::default(), |_| false, &[])
        .expect("token");
    let rest = fake_password();
    let value = format!("{}{rest}", token.as_str());
    let dir = tempfile::tempdir().expect("tempdir");
    write_tree(
        dir.path(),
        &[
            ("a/.env", format!("TOKEN={value}\n").as_bytes()),
            ("b/.env", format!("TOKEN={}\n", token.as_str()).as_bytes()),
        ],
    );
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].rel_path, "a/.env");
    assert_span(dir.path(), &r.findings[0], &value);
    assert_no_secret(&json(&r), &[&rest]);
}

/// `fake_password()` with byte 0xE9 inserted after the first 6 characters.
fn latin1_secret() -> Vec<u8> {
    let pw = fake_password();
    let mut v = pw.as_bytes()[..6].to_vec();
    v.push(0xE9);
    v.extend_from_slice(&pw.as_bytes()[6..]);
    v
}

#[test]
fn s16b_invalid_utf8_inside_secret() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (e, p, u) = (latin1_secret(), latin1_secret(), latin1_secret());
    let env = [b"DB_PASSWORD=".as_slice(), &e, b"\n"].concat();
    let php = [b"define('DB_PASSWORD', '".as_slice(), &p, b"');\n"].concat();
    let url = [b"x postgres://u:".as_slice(), &u, b"@h/db\n"].concat();
    write_tree(
        dir.path(),
        &[(".env", &env), ("a.php", &php), ("u.txt", &url)],
    );
    let r = run(dir.path());
    let paths: Vec<_> = r.findings.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(paths, vec![".env", "a.php", "u.txt"]);
    for (f, want) in r.findings.iter().zip([&e, &p, &u]) {
        assert_span(dir.path(), f, want);
    }
    assert_no_secret(&json(&r), &[&e, &p, &u]);
}

#[test]
fn s20_hostile_input_stays_fast() {
    const MIB: usize = 1024 * 1024;
    let unit = b"a://b:c@";
    let urls = unit.repeat(5 * MIB / unit.len());
    let pat = fake_github_pat();
    let n = 4 * MIB / (pat.len() + 1);
    let line = format!("{pat} ").repeat(n);
    for (name, body, want) in [
        ("urls.txt", urls, 5 * MIB / unit.len()),
        ("pats.txt", line.into_bytes(), n),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        write_tree(dir.path(), &[(name, &body)]);
        let t = std::time::Instant::now();
        let r = run(dir.path());
        let secs = t.elapsed().as_secs_f64();
        eprintln!("s20 {name}: {secs:.2} s, {} findings", r.findings.len());
        assert!(secs < 30.0, "{name}: scan took {secs:.1} s");
        assert_eq!(r.findings.len(), want, "{name}");
        assert!(r.findings.windows(2).all(|w| w[0].end <= w[1].start));
    }
}

#[test]
fn s21_git_case_and_trailing_dot_variants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (p1, p2) = (fake_github_pat(), fake_github_pat());
    write_tree(
        dir.path(),
        &[
            (".GIT/config", format!("t = {p1}\n").as_bytes()),
            ("sub/.Git/config", format!("t = {p2}\n").as_bytes()),
        ],
    );
    // Windows strips trailing dots from names, so `.git.` is a Unix-only case.
    #[cfg(unix)]
    let (secrets, want) = {
        let p3 = fake_github_pat();
        write_tree(
            dir.path(),
            &[(".git./config", format!("t = {p3}\n").as_bytes())],
        );
        let want: Vec<String> = vec![".GIT".into(), ".git.".into(), "sub/.Git".into()];
        (vec![p1, p2, p3], want)
    };
    #[cfg(not(unix))]
    let (secrets, want) = (
        vec![p1, p2],
        vec![".GIT".to_string(), "sub/.Git".to_string()],
    );
    let opts = ScanOptions {
        no_default_excludes: true,
    };
    let r = scan(dir.path(), &opts, &crate::Profile::default()).expect("scan");
    assert_eq!(r.findings, vec![]);
    assert_eq!(r.skipped.excluded, want);
    assert_no_secret(&json(&r), &secrets);
}

// macOS (APFS) refuses to create non-UTF-8 file names, so only other Unixes can test D46.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn s23_non_utf8_file_name() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let pat = fake_github_pat();
    let name = std::ffi::OsStr::from_bytes(b"\xff.js");
    std::fs::write(dir.path().join(name), format!("t = {pat}\n")).expect("write");
    // The lossy form of the bad name, as a real (valid UTF-8) file.
    write_tree(dir.path(), &[("\u{FFFD}.js", b"x\n")]);
    let r = run(dir.path());
    assert_eq!(r.findings, vec![]);
    assert_eq!(r.skipped.non_utf8_name, vec![r"\xff.js".to_string()]);
    let scanned: Vec<_> = r
        .scanned_files
        .iter()
        .map(|s| s.rel_path.as_str())
        .collect();
    assert_eq!(scanned, vec!["\u{FFFD}.js"]);
    assert_no_secret(&json(&r), &[&pat]);
}

/// Letters and digits alternating: high entropy, and no gitleaks stopword
/// (each is a run of 3+ letters or digits) can occur in it.
fn alternating_secret(n: usize) -> String {
    let letters: Vec<char> = random_alnum(n * 4)
        .chars()
        .filter(char::is_ascii_alphabetic)
        .collect();
    let digits: Vec<char> = random_alnum(n * 12)
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                letters[i / 2]
            } else {
                digits[i / 2]
            }
        })
        .collect()
}

#[test]
fn s24_line_target_allowlists_ignored() {
    let rules = RuleSet::load().expect("rules");
    assert_eq!(
        rules.allowlist_warnings.len(),
        2,
        "line-target tables at the pinned commit"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let v = alternating_secret(32);
    let body = format!("RUN --mount=type=secret,id=x api_key=\"{v}\"\n");
    write_tree(dir.path(), &[("Dockerfile", body.as_bytes())]);
    let r = run(dir.path());
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].rule_id, "generic-api-key");
    assert_span(dir.path(), &r.findings[0], &v);
    assert_eq!(r.warnings.len(), rules.warnings.len() + 2);
    assert_no_secret(&json(&r), &[&v]);
}

#[cfg(unix)]
#[test]
fn d45_changed_file_identity_is_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_tree(dir.path(), &[("a.txt", b"x\n")]);
    let path = dir.path().join("a.txt");
    let real = walk::identity(&std::fs::symlink_metadata(&path).expect("meta"));
    let class = walk::classify(&path, real).expect("classify");
    assert!(matches!(class, walk::Class::Text(_)));
    let other = real.map(|(dev, ino)| (dev, ino.wrapping_add(1)));
    let class = walk::classify(&path, other).expect("classify");
    assert!(matches!(class, walk::Class::Changed));
    // A directory opened where a file was expected also counts as changed.
    let d = walk::identity(&std::fs::metadata(dir.path()).expect("meta"));
    let class = walk::classify(dir.path(), d).expect("classify");
    assert!(matches!(class, walk::Class::Changed));
}
