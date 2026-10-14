//! P4 detection-profile tests PF1–PF6 (TEST_CASES.md). Secrets are generated at runtime.

use super::*;
use crate::mask::{MaskOptions, Selection, mask};
use crate::scan::{Detector, ScanOptions, ScanReport, scan};
use crate::test_support::*;
use std::collections::BTreeSet;

fn scan_with(dir: &Path, profile: &Profile) -> ScanReport {
    scan(dir, &ScanOptions::default(), profile).expect("scan")
}

/// A profile parsed from TOML text (through `load`).
fn profile_from(dir: &Path, text: &str) -> Profile {
    let path = dir.join("profile.toml");
    std::fs::write(&path, text).expect("write profile");
    Profile::load(&path).expect("load profile")
}

fn in_file<'r>(r: &'r ScanReport, rel: &str) -> Vec<&'r Finding> {
    r.findings.iter().filter(|f| f.rel_path == rel).collect()
}

/// Fails unless the finding's span equals `want`; the message never shows bytes.
fn assert_span(dir: &Path, f: &Finding, want: &[u8]) {
    let bytes = std::fs::read(dir.join(&f.rel_path)).expect("read");
    let got = bytes.get(f.start..f.end).unwrap_or_default();
    assert!(got == want, "span mismatch at {}:{}", f.rel_path, f.start);
}

fn json(r: &ScanReport) -> Vec<u8> {
    serde_json::to_vec(r).expect("json")
}

#[test]
fn pf1_extra_keys_are_detected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    let v: Vec<String> = (0..5).map(|_| fake_password()).collect();
    let files: [(&str, String, &str, &str); 5] = [
        (
            ".env",
            format!("CUSTOMAPI_PASS={}\n", v[0]),
            ENV,
            "CUSTOMAPI_PASS",
        ),
        (
            "config.yml",
            format!("customapi-pass: {}\n", v[1]),
            CUSTOM,
            "customapi-pass",
        ),
        (
            "settings.json",
            format!("{{\n  \"customapi_pass\": \"{}\"\n}}\n", v[2]),
            CUSTOM,
            "customapi_pass",
        ),
        (
            "app.ini",
            format!("CustomApi.Pass = {}\n", v[3]),
            CUSTOM,
            "CustomApi.Pass",
        ),
        (
            "wp-config.php",
            format!("<?php\ndefine('CUSTOMAPI_PASS','{}');\n", v[4]),
            PHP,
            "CUSTOMAPI_PASS",
        ),
    ];
    let tree: Vec<(&str, &[u8])> = files.iter().map(|f| (f.0, f.1.as_bytes())).collect();
    write_tree(&input, &tree);
    let profile = profile_from(
        tmp.path(),
        "version = 1\nextra_keys = [\"customapi-pass\"]\n",
    );
    let r = scan_with(&input, &profile);
    for (i, (rel, _, rule, key)) in files.iter().enumerate() {
        let found = in_file(&r, rel);
        assert_eq!(found.len(), 1, "{rel}");
        assert_span(&input, found[0], v[i].as_bytes());
        assert_eq!(found[0].rule_id, *rule, "{rel}");
        assert_eq!(found[0].key_name.as_deref(), Some(*key), "{rel}");
        assert_eq!(found[0].ignored, None);
    }
    assert_eq!(in_file(&r, "config.yml")[0].detector, Detector::D5);
    let plain = scan_with(&input, &Profile::default());
    for rel in ["config.yml", "settings.json", "app.ini"] {
        assert_eq!(in_file(&plain, rel).len(), 0, "{rel} without profile");
    }
    assert_eq!(in_file(&plain, ".env").len(), 1);
    assert_no_secret(&json(&r), &v);
}

const ENV: &str = "env-file";
const PHP: &str = "php-define";
const CUSTOM: &str = "custom-key";

#[test]
fn pf2_d5_boundaries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    let v: Vec<String> = (0..7).map(|_| fake_password()).collect();
    let spaced = format!("{} with space", v[3]);
    let mut latin = random_alnum(10).into_bytes();
    latin.push(0xE9);
    latin.extend_from_slice(v[4].as_bytes());
    let mut latin_line = b"customapi-pass: ".to_vec();
    latin_line.extend_from_slice(&latin);
    latin_line.push(b'\n');
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "nob.yml",
            format!("my_customapi_pass_x: {}\n", v[0]).into_bytes(),
        ),
        (
            "post.yml",
            format!("customapi_pass_x: {}\n", v[0]).into_bytes(),
        ),
        (
            "xpre.yml",
            format!("xcustomapi_pass: {}\n", v[0]).into_bytes(),
        ),
        (
            "dot.yml",
            format!("my.customapi-pass: {}\n", v[5]).into_bytes(),
        ),
        (
            "paren.yml",
            format!("(customapi-pass: {}\n", v[6]).into_bytes(),
        ),
        ("env.yml", b"customapi-pass: ${ENV}\n".to_vec()),
        ("cmd.yml", b"customapi-pass: $(cmd)\n".to_vec()),
        ("empty.yml", b"customapi-pass:\nnext: 1\n".to_vec()),
        (
            "comma.yml",
            format!("customapi-pass: {}, other\n", v[1]).into_bytes(),
        ),
        (
            "semi.yml",
            format!("customapi-pass: {};\n", v[2]).into_bytes(),
        ),
        (
            "quoted.ini",
            format!("customapi-pass = \"{spaced}\"\n").into_bytes(),
        ),
        ("latin.yml", latin_line),
    ];
    let tree: Vec<(&str, &[u8])> = files.iter().map(|f| (f.0, f.1.as_slice())).collect();
    write_tree(&input, &tree);
    let profile = profile_from(
        tmp.path(),
        "version = 1\nextra_keys = [\"customapi-pass\"]\n",
    );
    let r = scan_with(&input, &profile);
    for rel in [
        "nob.yml",
        "xpre.yml",
        "post.yml",
        "env.yml",
        "cmd.yml",
        "empty.yml",
    ] {
        assert_eq!(in_file(&r, rel).len(), 0, "{rel}");
    }
    let want: [(&str, &[u8]); 6] = [
        ("dot.yml", v[5].as_bytes()),
        ("paren.yml", v[6].as_bytes()),
        ("comma.yml", v[1].as_bytes()),
        ("semi.yml", v[2].as_bytes()),
        ("quoted.ini", spaced.as_bytes()),
        ("latin.yml", &latin),
    ];
    for (rel, span) in want {
        let found = in_file(&r, rel);
        assert_eq!(found.len(), 1, "{rel}");
        assert_eq!(found[0].rule_id, CUSTOM);
        assert_span(&input, found[0], span);
    }
    assert_no_secret(&json(&r), &v);
}

/// PF3 tree: `.env` with DB_NAME=<a> and DB_PASSWORD=<b>.
fn pf3_setup(tmp: &Path) -> (std::path::PathBuf, String, String) {
    let input = tmp.join("in");
    let (a, b) = (fake_password(), fake_password());
    let env = format!("DB_NAME={a}\nDB_PASSWORD={b}\n");
    write_tree(&input, &[(".env", env.as_bytes())]);
    (input, a, b)
}

// DB_NAME holds none of the built-in key words, so without `extra_keys` no
// detector reports it; the profile lists it in both (see DECISIONS D83).
const PF3_PROFILE: &str = "version = 1\nextra_keys = [\"DB_NAME\"]\nignored_keys = [\"DB_NAME\"]\n";

#[test]
fn pf3_ignored_keys_reported_not_masked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (input, a, b) = pf3_setup(tmp.path());
    let profile = profile_from(tmp.path(), PF3_PROFILE);
    let r = scan_with(&input, &profile);
    assert_eq!(r.findings.len(), 2);
    let name = r
        .findings
        .iter()
        .find(|f| f.key_name.as_deref() == Some("DB_NAME"));
    let name = name.expect("DB_NAME finding");
    assert_eq!(name.ignored, Some(IgnoreReason::ProfileKey));
    assert_span(&input, name, a.as_bytes());
    let pass = r
        .findings
        .iter()
        .find(|f| f.key_name.as_deref() == Some("DB_PASSWORD"));
    assert_eq!(pass.expect("DB_PASSWORD").ignored, None);

    let mut vault = test_vault(tmp.path());
    let out = tmp.path().join("masked");
    let opts = MaskOptions::default();
    let m = mask(&r, &Selection::All, &input, &out, &mut vault, &opts).expect("mask");
    assert_eq!(m.secrets_masked, 1);
    assert_eq!(m.ignored_by_profile, 1);
    let masked = all_bytes(&out);
    assert!(
        masked.windows(a.len()).any(|w| w == a.as_bytes()),
        "<a> kept"
    );
    assert_no_secret(&masked, &[&b]);
    assert_no_secret(&serde_json::to_vec(&m).expect("json"), &[&a, &b]);

    // Restore applies the profile: the unmasked <a> is an ignored new secret.
    let restored = tmp.path().join("restored");
    let rep = crate::restore(&out, &restored, &mut vault, None, false, &profile).expect("restore");
    assert_eq!(rep.ignored_new_secrets, 1);
    assert_eq!(rep.new_secrets.len(), 0);
    assert!(rep.session_forgotten);
    assert_eq!(tree_hashes(&restored), tree_hashes(&input));

    // Explicitly selecting the ignored id masks <a> too (override).
    let ids: BTreeSet<String> = r.findings.iter().map(|f| f.id.clone()).collect();
    let out2 = tmp.path().join("masked2");
    let m2 = mask(&r, &Selection::Ids(ids), &input, &out2, &mut vault, &opts).expect("mask");
    assert_eq!((m2.secrets_masked, m2.ignored_by_profile), (2, 0));
    assert_no_secret(&all_bytes(&out2), &[&a, &b]);
}

#[test]
fn pf4_per_file_ignore_entries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    let (k1, k2) = (fake_password(), fake_password());
    let (p1, p2) = (fake_github_pat(), fake_github_pat());
    let js = |p: &str| format!("const t = \"{p}\";\n");
    write_tree(
        &input,
        &[
            ("a/.env", format!("API_KEY={k1}\n").as_bytes()),
            ("b/.env", format!("API_KEY={k2}\n").as_bytes()),
            ("c/app.js", js(&p1).as_bytes()),
            ("d/app.js", js(&p2).as_bytes()),
        ],
    );
    let plain = scan_with(&input, &Profile::default());
    let pat_rule = in_file(&plain, "c/app.js")[0].rule_id.clone();
    assert_eq!(in_file(&plain, "c/app.js")[0].detector, Detector::D1);
    let text = format!(
        "version = 1\n[[ignored]]\nrel_path = \"a/.env\"\nkey_name = \"API_KEY\"\n\
         [[ignored]]\nrel_path = \"c/app.js\"\nrule_id = \"{pat_rule}\"\n"
    );
    let r = scan_with(&input, &profile_from(tmp.path(), &text));
    let state = |rel: &str| in_file(&r, rel)[0].ignored;
    assert_eq!(state("a/.env"), Some(IgnoreReason::ProfileEntry));
    assert_eq!(state("b/.env"), None);
    assert_eq!(state("c/app.js"), Some(IgnoreReason::ProfileEntry));
    assert_eq!(state("d/app.js"), None);

    let mut vault = test_vault(tmp.path());
    let out = tmp.path().join("masked");
    let opts = MaskOptions::default();
    let m = mask(&r, &Selection::All, &input, &out, &mut vault, &opts).expect("mask");
    assert_eq!((m.secrets_masked, m.ignored_by_profile), (2, 2));
    assert_no_secret(&all_bytes(&out), &[&k2, &p2]);
    let masked = all_bytes(&out);
    for kept in [&k1, &p1] {
        assert!(masked.windows(kept.len()).any(|w| w == kept.as_bytes()));
    }
}

/// The (id, ignored) state of every finding.
fn states(r: &ScanReport) -> Vec<(String, Option<IgnoreReason>)> {
    r.findings
        .iter()
        .map(|f| (f.id.clone(), f.ignored))
        .collect()
}

/// Saves, reloads and re-scans; returns the reloaded profile and the scan.
fn roundtrip(p: &Profile, path: &Path, input: &Path) -> (Profile, ScanReport) {
    p.save(path).expect("save");
    let loaded = Profile::load(path).expect("load");
    assert_eq!(&loaded, p);
    let r = scan_with(input, &loaded);
    (loaded, r)
}

fn find<'r>(r: &'r ScanReport, key: &str) -> &'r Finding {
    let f = r
        .findings
        .iter()
        .find(|f| f.key_name.as_deref() == Some(key));
    f.expect("finding")
}

#[test]
fn pf5_profile_edits_roundtrip_without_secrets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    let path = tmp.path().join("cfg").join("profile.toml");
    let v: Vec<String> = (0..3).map(|_| fake_password()).collect();
    let env = format!("API_KEY={}\nDB_PASSWORD={}\n", v[0], v[1]);
    let yml = format!("customapi-pass: {}\n", v[2]);
    write_tree(
        &input,
        &[(".env", env.as_bytes()), ("config.yml", yml.as_bytes())],
    );
    let base = scan_with(&input, &Profile::default());
    assert_eq!(base.findings.len(), 2);

    let mut p = Profile::default();
    assert!(p.add_extra_key("customapi-pass").expect("add"));
    assert!(
        !p.add_extra_key("CUSTOMAPI_PASS").expect("add again"),
        "normalised dup"
    );
    let (mut p, r) = roundtrip(&p, &path, &input);
    assert_eq!(r.findings.len(), 3);
    let custom = find(&r, "customapi-pass").clone();

    assert!(p.ignore_key("DB_PASSWORD").expect("ignore"));
    assert!(!p.ignore_key("db-password").expect("ignore again"));
    assert!(
        p.ignore_finding(find(&r, "API_KEY"), Scope::ThisFile)
            .expect("this file")
    );
    assert!(
        !p.ignore_finding(find(&r, "API_KEY"), Scope::ThisFile)
            .expect("again")
    );
    assert!(
        p.ignore_finding(&custom, Scope::Everywhere)
            .expect("everywhere")
    );
    let (mut p, r) = roundtrip(&p, &path, &input);
    assert_eq!(
        find(&r, "DB_PASSWORD").ignored,
        Some(IgnoreReason::ProfileKey)
    );
    assert_eq!(
        find(&r, "API_KEY").ignored,
        Some(IgnoreReason::ProfileEntry)
    );
    assert_eq!(
        find(&r, "customapi-pass").ignored,
        Some(IgnoreReason::ProfileKey)
    );
    assert_eq!(p.ignored_keys(), ["DB_PASSWORD", "customapi-pass"]);
    assert_eq!(p.ignored().len(), 1);
    assert_no_secret(&std::fs::read(&path).expect("read profile"), &v);

    assert!(p.unignore_finding(&custom).expect("unignore custom"));
    assert!(!p.unignore_finding(&custom).expect("unignore custom again"));
    assert!(
        p.unignore_finding(find(&r, "API_KEY"))
            .expect("unignore api")
    );
    assert!(p.unignore_key("DB-PASSWORD").expect("unignore key"));
    assert!(!p.unignore_key("DB_PASSWORD").expect("unignore key again"));
    assert!(p.remove_extra_key("customapi_pass").expect("remove"));
    assert!(!p.remove_extra_key("customapi-pass").expect("remove again"));
    let (p, r) = roundtrip(&p, &path, &input);
    assert_eq!(p, Profile::default());
    assert_eq!(states(&r), states(&base));
    assert_no_secret(&std::fs::read(&path).expect("read profile"), &v);
}

fn load_err(dir: &Path, text: &[u8]) -> CoreError {
    let path = dir.join("bad.toml");
    std::fs::write(&path, text).expect("write");
    Profile::load(&path).expect_err("must be rejected")
}

#[test]
fn pf6_profile_safety() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = tmp.path();
    let mut big = b"version = 1\n".to_vec();
    big.resize(MAX_PROFILE as usize + 1, b'#');
    assert!(matches!(load_err(d, &big), CoreError::UnsafeProfile));
    let unknown = load_err(d, b"version = 1\nbogus = 1\n");
    assert!(
        matches!(unknown, CoreError::ProfileParse { line: 2 }),
        "{unknown}"
    );
    let v2 = load_err(d, b"version = 2\n");
    assert!(matches!(v2, CoreError::ProfileVersion { version: 2 }));
    let long = format!("version = 1\nextra_keys = [\"{}\"]\n", "K".repeat(65));
    assert!(matches!(
        load_err(d, long.as_bytes()),
        CoreError::BadKeyName
    ));
    let slash = b"version = 1\nignored_keys = [\"A/B\"]\n";
    assert!(matches!(load_err(d, slash), CoreError::BadKeyName));
    let both = b"version = 1\n[[ignored]]\nrel_path = \"a\"\nkey_name = \"K\"\nrule_id = \"r\"\n";
    assert!(matches!(load_err(d, both), CoreError::BadIgnoreEntry));
    let neither = b"version = 1\n[[ignored]]\nrel_path = \"a\"\n";
    assert!(matches!(load_err(d, neither), CoreError::BadIgnoreEntry));
    let dotdot = b"version = 1\n[[ignored]]\nrel_path = \"../x\"\nkey_name = \"K\"\n";
    assert!(matches!(load_err(d, dotdot), CoreError::BadRelPath { .. }));
    let mut p = Profile::default();
    assert!(matches!(
        p.add_extra_key(&"K".repeat(65)),
        Err(CoreError::BadKeyName)
    ));
    assert!(matches!(p.ignore_key("a/b"), Err(CoreError::BadKeyName)));
    assert!(matches!(p.add_extra_key(""), Err(CoreError::BadKeyName)));
    // D88: a key name needs an ASCII letter or digit; lists are capped.
    assert!(matches!(
        p.add_extra_key("-. _"),
        Err(CoreError::BadKeyName)
    ));
    assert!(matches!(p.ignore_key("---"), Err(CoreError::BadKeyName)));
    assert_eq!(p, Profile::default());
    pf6_caps(d);
    #[cfg(unix)]
    {
        let real = d.join("real.toml");
        std::fs::write(&real, "version = 1\n").expect("write");
        let link = d.join("link.toml");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(matches!(
            Profile::load(&link),
            Err(CoreError::UnsafeProfile)
        ));
    }
    let missing = Profile::load(&d.join("none").join("profile.toml")).expect("missing");
    assert_eq!(missing, Profile::default());
    pf6_input_profile_has_no_effect(d);
}

/// A profile file inside the input folder is never read (D75).
fn pf6_input_profile_has_no_effect(d: &Path) {
    let input = d.join("in");
    let (pw, w) = (fake_password(), fake_password());
    let planted = "version = 1\nextra_keys = [\"customapi-pass\"]\nignored_keys = [\"DB_PASSWORD\"]\n\
                   [[ignored]]\nrel_path = \".env\"\nkey_name = \"DB_PASSWORD\"\n";
    write_tree(
        &input,
        &[
            (".env", format!("DB_PASSWORD={pw}\n").as_bytes()),
            ("config.yml", format!("customapi-pass: {w}\n").as_bytes()),
            ("profile.toml", planted.as_bytes()),
            (".veilcode.toml", planted.as_bytes()),
        ],
    );
    let r = scan_with(&input, &Profile::default());
    let env = in_file(&r, ".env");
    assert_eq!(env.len(), 1);
    assert_eq!(env[0].ignored, None);
    assert_eq!(in_file(&r, "config.yml").len(), 0);
    assert_eq!(r.findings.len(), 1);
}

/// D88: at most 256 extra_keys, 256 ignored_keys and 4096 [[ignored]].
fn pf6_caps(d: &Path) {
    let keys = |n: usize| {
        (0..n)
            .map(|i| format!("\"K{i}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    for (field, max) in [("extra_keys", MAX_KEYS), ("ignored_keys", MAX_KEYS)] {
        let ok = format!("version = 1\n{field} = [{}]\n", keys(max));
        assert!(load_ok(d, &ok), "{field} at cap");
        let over = format!("version = 1\n{field} = [{}]\n", keys(max + 1));
        let err = load_err(d, over.as_bytes());
        assert!(matches!(err, CoreError::ProfileTooLarge { .. }), "{err}");
    }
    let entry = |i: usize| format!("[[ignored]]\nrel_path = \"f{i}\"\nkey_name = \"K\"\n");
    let entries = |n: usize| (0..n).map(entry).collect::<String>();
    let ok = format!("version = 1\n{}", entries(MAX_ENTRIES));
    assert!(load_ok(d, &ok), "entries at cap");
    let over = format!("version = 1\n{}", entries(MAX_ENTRIES + 1));
    let err = load_err(d, over.as_bytes());
    assert!(matches!(err, CoreError::ProfileTooLarge { .. }), "{err}");
    let mut p = Profile::default();
    for i in 0..MAX_KEYS {
        assert!(p.add_extra_key(&format!("K{i}")).expect("add"));
    }
    let err = p.add_extra_key("ONE_MORE").expect_err("over cap");
    assert!(matches!(err, CoreError::ProfileTooLarge { .. }), "{err}");
}

#[test]
fn pf3b_ignore_applies_when_gitleaks_also_matches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    // Not every random value passes generic-api-key's own checks, so pick one
    // that does: the precondition is "a gitleaks rule also matches".
    let mut v = String::new();
    let mut rules = None;
    for _ in 0..50 {
        v = random_alnum(28);
        write_tree(
            &input,
            &[("config.yml", format!("customapi-pass: {v}\n").as_bytes())],
        );
        let r = scan_with(&input, &Profile::default());
        if r.findings.len() == 1 {
            rules = Some(r);
            break;
        }
    }
    let rules = rules.expect("a value that generic-api-key also matches");
    assert_eq!(rules.findings[0].detector, Detector::D1);
    let both =
        "version = 1\nextra_keys = [\"customapi-pass\"]\nignored_keys = [\"customapi-pass\"]\n";
    let r = scan_with(&input, &profile_from(tmp.path(), both));
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.key_name.as_deref(), Some("customapi-pass"));
    assert_eq!(f.ignored, Some(IgnoreReason::ProfileKey));
    assert_span(&input, f, v.as_bytes());
    let mut vault = test_vault(tmp.path());
    let opts = MaskOptions::default();
    let out = tmp.path().join("m1");
    let m = mask(&r, &Selection::All, &input, &out, &mut vault, &opts).expect("mask");
    assert_eq!((m.secrets_masked, m.ignored_by_profile), (0, 1));
    assert!(contains(&all_bytes(&out), &v), "ignored value stays");

    let extra = "version = 1\nextra_keys = [\"customapi-pass\"]\n";
    let r = scan_with(&input, &profile_from(tmp.path(), extra));
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].key_name.as_deref(), Some("customapi-pass"));
    assert_eq!(r.findings[0].ignored, None);
    let out = tmp.path().join("m2");
    let m = mask(&r, &Selection::All, &input, &out, &mut vault, &opts).expect("mask");
    assert_eq!(m.secrets_masked, 1);
    assert_no_secret(&all_bytes(&out), &[&v]);
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn pf8_d5_linear_on_hostile_lines() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    let size = 5 * 1024 * 1024;
    let line = |unit: &str| unit.repeat(size / unit.len()).into_bytes();
    let (plain, quoted) = (line("dbname="), line("dbname=\"dbname="));
    write_tree(&input, &[("a.yml", &plain), ("b.yml", &quoted)]);
    let profile = profile_from(tmp.path(), "version = 1\nextra_keys = [\"dbname\"]\n");
    let start = std::time::Instant::now();
    let r = scan_with(&input, &profile);
    let secs = start.elapsed().as_secs();
    assert!(secs < 30, "D5 took {secs} s on 2 × 5 MiB hostile lines");
    // The plain line is one value (the whole rest of the line).
    assert_eq!(in_file(&r, "a.yml").len(), 1);
    // Each `"dbname=` value is closed by the next unit's quote, so values
    // never overlap: at most one per unit.
    let b = in_file(&r, "b.yml").len();
    assert!(
        b >= 1 && b <= quoted.len() / "dbname=\"dbname=".len(),
        "{b}"
    );
    for w in r.findings.windows(2) {
        assert!(w[0].rel_path != w[1].rel_path || w[0].end <= w[1].start);
    }
}

fn load_ok(dir: &Path, text: &str) -> bool {
    let path = dir.join("ok.toml");
    std::fs::write(&path, text).expect("write");
    Profile::load(&path).is_ok()
}
