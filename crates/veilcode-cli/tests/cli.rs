//! P4 CLI tests C1–C7, LF8, PF7 (TEST_CASES.md). They run the real binary
//! with `--passphrase-stdin`, a temp `--vault` and a temp `--profile`.

mod common;

use common::*;
use std::path::{Path, PathBuf};

/// `.env` (D2), `wp-config.php` (D3) and `src/app.js` (D1 PAT).
struct Sample {
    input: PathBuf,
    pw: String,
    key: String,
    pat: String,
}

fn sample(ctx: &mut Ctx) -> Sample {
    let input = ctx.path("project");
    let (pw, key, pat) = (fake_password(), fake_password(), fake_github_pat());
    let env = format!("APP=demo\nDB_PASSWORD={pw}\n");
    let php = format!("<?php\ndefine('AUTH_KEY', '{key}');\n");
    let js = format!("let a = 1;\nconst t = \"{pat}\";\n");
    write_tree(
        &input,
        &[
            (".env", env.as_bytes()),
            ("wp-config.php", php.as_bytes()),
            ("src/app.js", js.as_bytes()),
        ],
    );
    ctx.secrets.extend([pw.clone(), key.clone(), pat.clone()]);
    Sample {
        input,
        pw,
        key,
        pat,
    }
}

/// C1 flow: scan --json, mask, restore. Returns every output.
fn c1_flow(ctx: &mut Ctx) -> (Sample, Vec<Out>, Vec<PathBuf>) {
    let sm = sample(ctx);
    let (json, masked, restored) = (
        ctx.path("scan.json"),
        ctx.path("masked"),
        ctx.path("restored"),
    );
    let (mask_rep, restore_rep) = (ctx.path("mask.json"), ctx.path("restore.json"));
    let scan = ctx.run(&["scan", &s(&sm.input), "--json", &s(&json)], "");
    let mask = ctx.run_pass(&[
        "mask",
        &s(&sm.input),
        "--out",
        &s(&masked),
        "--report",
        &s(&mask_rep),
    ]);
    let restore = ctx.run_pass(&[
        "restore",
        &s(&masked),
        "--out",
        &s(&restored),
        "--report",
        &s(&restore_rep),
    ]);
    let files = vec![json, masked, restored, mask_rep, restore_rep];
    (sm, vec![scan, mask, restore], files)
}

#[test]
fn c1_end_to_end() {
    let mut ctx = Ctx::new();
    let (sm, outs, files) = c1_flow(&mut ctx);
    for o in &outs {
        assert_eq!(o.code, 0, "{}", o.err());
    }
    let json = std::fs::read(&files[0]).expect("scan json");
    assert!(contains(&json, "\"findings\""));
    assert_no_secret(&json, &ctx.secrets);
    assert!(outs[0].err().contains("3 findings"), "{}", outs[0].err());
    assert_no_secret(&all_bytes(&files[1]), &[&sm.pw, &sm.key, &sm.pat]);
    assert!(
        outs[1].err().contains("masked 3 secrets"),
        "{}",
        outs[1].err()
    );
    assert_eq!(tree(&files[2]), tree(&sm.input));
    assert!(
        outs[2].err().contains("session forgotten"),
        "{}",
        outs[2].err()
    );
    assert!(
        !ctx.vault.exists(),
        "last session forgotten removes the vault"
    );
}

/// C2 flow: mask of a missing folder.
fn c2_flow(ctx: &Ctx) -> Out {
    let out = ctx.path("c2-out");
    let o = ctx.run_pass(&["mask", "/no/such", "--out", &s(&out)]);
    assert!(!out.exists());
    o
}

#[test]
fn c2_bad_path() {
    let ctx = Ctx::new();
    let o = c2_flow(&ctx);
    assert_eq!(o.code, 2);
    assert!(o.err().starts_with("error: "), "{}", o.err());
    assert!(o.err().contains("/no/such"), "{}", o.err());
    assert!(!ctx.vault.exists());
    c2_bad_output_files();
}

/// D89: report files never land inside the input, and only a regular file
/// is ever replaced.
fn c2_bad_output_files() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let before = tree(&sm.input);
    for flag in ["--json", "--report"] {
        let inside = sm.input.join("src").join("x.json");
        let o = ctx.run(&["scan", &s(&sm.input), flag, &s(&inside)], "");
        assert_eq!(o.code, 2, "{flag}: {}", o.err());
        assert!(o.err().contains("inside the input folder"), "{}", o.err());
    }
    assert_eq!(tree(&sm.input), before, "input untouched");
    let existing = ctx.path("old.json");
    std::fs::write(&existing, b"old").expect("write");
    let o = ctx.run(&["scan", &s(&sm.input), "--json", &s(&existing)], "");
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(contains(
        &std::fs::read(&existing).expect("read"),
        "\"findings\""
    ));
    #[cfg(unix)]
    {
        let target = ctx.path("target.txt");
        std::fs::write(&target, b"keep").expect("write");
        let link = ctx.path("link.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let o = ctx.run(&["scan", &s(&sm.input), "--json", &s(&link)], "");
        assert_eq!(o.code, 2, "{}", o.err());
        assert_eq!(std::fs::read(&target).expect("read"), b"keep");
    }
}

#[test]
fn c3_help() {
    let ctx = Ctx::new();
    let o = run_binary(&["--help".to_string()], b"", ctx.tmp.path());
    assert_eq!(o.code, 0);
    let help = o.out();
    for cmd in ["scan", "mask", "restore", "session", "vault", "profile"] {
        assert!(help.contains(cmd), "help lacks {cmd}");
    }
    assert!(help.contains("--vault <project>.vc"), "{help}");
}

/// C4 flow: drop the DB_PASSWORD finding from the scan JSON, then mask.
fn c4_flow(ctx: &mut Ctx) -> (Sample, Vec<Out>, PathBuf) {
    let sm = sample(ctx);
    let json = ctx.path("scan.json");
    let scan = ctx.run(&["scan", &s(&sm.input), "--json", &s(&json)], "");
    let text = std::fs::read_to_string(&json).expect("json");
    let edited = ctx.path("findings.json");
    std::fs::write(&edited, drop_finding(&text, "\"DB_PASSWORD\"")).expect("write");
    let masked = ctx.path("masked");
    let mask = ctx.run_pass(&[
        "mask",
        &s(&sm.input),
        "--out",
        &s(&masked),
        "--findings",
        &s(&edited),
    ]);
    (sm, vec![scan, mask], masked)
}

#[test]
fn c4_findings_file_deselect() {
    let mut ctx = Ctx::new();
    let (sm, outs, masked) = c4_flow(&mut ctx);
    for o in &outs {
        assert_eq!(o.code, 0, "{}", o.err());
    }
    let bytes = all_bytes(&masked);
    assert!(contains(&bytes, &sm.pw), "deselected secret stays");
    assert_no_secret(&bytes, &[&sm.key, &sm.pat]);
    assert!(
        outs[1].err().contains("masked 2 secrets"),
        "{}",
        outs[1].err()
    );
}

#[test]
fn c5_no_secrets_on_any_stream() {
    // Ctx::run checks stdout and stderr of every invocation; the report
    // files and outputs are checked here too.
    let mut ctx = Ctx::new();
    let (_, outs, files) = c1_flow(&mut ctx);
    assert!(outs.iter().all(|o| o.code == 0));
    for report in [&files[0], &files[3], &files[4]] {
        assert_no_secret(&std::fs::read(report).expect("report"), &ctx.secrets);
    }
    let c2 = c2_flow(&ctx);
    assert_eq!(c2.code, 2);
    let mut ctx4 = Ctx::new();
    let (_, outs4, _) = c4_flow(&mut ctx4);
    assert!(outs4.iter().all(|o| o.code == 0));
    let mut streams: Vec<u8> = Vec::new();
    for o in outs.iter().chain(&outs4).chain([&c2]) {
        streams.extend(&o.stdout);
        streams.extend(&o.stderr);
    }
    assert!(!streams.is_empty());
    assert_no_secret(&streams, &[ctx.secrets.as_slice(), &ctx4.secrets].concat());
}

#[test]
fn c6_wrong_passphrase() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let wrong = format!("wrong {}", random_alnum(16));
    ctx.secrets.push(wrong.clone());
    let masked = ctx.path("masked");
    let mask = ctx.run_pass(&["mask", &s(&sm.input), "--out", &s(&masked)]);
    assert_eq!(mask.code, 0, "{}", mask.err());
    let before = std::fs::read(&ctx.vault).expect("vault");
    let restored = ctx.path("restored");
    let args = [
        "restore",
        &s(&masked),
        "--out",
        &s(&restored),
        "--passphrase-stdin",
    ];
    let o = ctx.run(&args, &format!("{wrong}\n"));
    assert_eq!(o.code, 2);
    assert_eq!(
        o.err().trim_end(),
        "error: wrong passphrase or corrupted vault"
    );
    assert!(!restored.exists());
    assert_eq!(std::fs::read(&ctx.vault).expect("vault"), before);
}

#[test]
fn c7_scan_exit_code() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let clean = ctx.path("clean");
    write_tree(&clean, &[("README.md", b"nothing here\n")]);
    let a = ctx.run(&["scan", &s(&sm.input)], "");
    let b = ctx.run(&["scan", &s(&clean)], "");
    assert_eq!((a.code, b.code), (0, 0), "{} {}", a.err(), b.err());
    assert!(a.err().contains("3 findings"), "{}", a.err());
    assert!(b.err().contains("0 findings"), "{}", b.err());
}

/// The number after `label` on its own line of `text`.
fn number_after(text: &str, label: &str) -> u64 {
    let line = text.lines().find(|l| l.starts_with(label)).expect("label");
    let rest = line[label.len()..].trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().expect("number")
}

fn now() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.expect("clock").as_secs()
}

#[test]
fn lf8_cli_lifecycle() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let m1 = ctx.path("m1");
    let o = ctx.run_pass(&["mask", &s(&sm.input), "--out", &s(&m1), "--ttl-days", "7"]);
    assert_eq!(o.code, 0, "{}", o.err());
    let st = ctx.run_pass(&["vault", "status"]);
    assert_eq!(st.code, 0, "{}", st.err());
    assert_eq!(number_after(&st.out(), "sessions:"), 1);
    let expiry = number_after(&st.out(), "next expiry:");
    let want = now() + 7 * 86_400;
    assert!(
        expiry <= want && expiry + 120 >= want,
        "expiry about 7 days ahead"
    );

    let r1 = ctx.run_pass(&["restore", &s(&m1), "--out", &s(&ctx.path("r1")), "--keep"]);
    assert_eq!(r1.code, 0, "{}", r1.err());
    assert!(
        r1.err().contains("session kept: keep requested"),
        "{}",
        r1.err()
    );
    let r2 = ctx.run_pass(&["restore", &s(&m1), "--out", &s(&ctx.path("r2"))]);
    assert_eq!(r2.code, 0, "{}", r2.err());
    assert!(r2.err().contains("session forgotten"), "{}", r2.err());
    assert!(!ctx.vault.exists(), "last session gone, so is vault file");

    let m2 = ctx.path("m2");
    assert_eq!(
        ctx.run_pass(&["mask", &s(&sm.input), "--out", &s(&m2)])
            .code,
        0
    );
    let before = std::fs::read(&ctx.vault).expect("vault");
    let no = ctx.run(
        &["vault", "purge", "--passphrase-stdin"],
        &format!("{PASS}\nn\n"),
    );
    assert_eq!(no.code, 2, "{}", no.err());
    assert_eq!(std::fs::read(&ctx.vault).expect("vault kept"), before);
    let yes = ctx.run_pass(&["vault", "purge", "--yes"]);
    assert_eq!(yes.code, 0, "{}", yes.err());
    assert!(!ctx.vault.exists());
}

fn profile_list(ctx: &Ctx) -> String {
    let o = ctx.run(&["profile", "list"], "");
    assert_eq!(o.code, 0, "{}", o.err());
    o.out()
}

#[test]
fn pf7_cli_profile_commands() {
    let mut ctx = Ctx::new();
    let input = ctx.path("project");
    let v: Vec<String> = (0..4).map(|_| fake_password()).collect();
    let env = format!("DB_NAME={}\nDB_PASSWORD={}\n", v[0], v[1]);
    let a_env = format!("API_KEY={}\n", v[2]);
    let yml = format!("customapi-pass: {}\n", v[3]);
    let files: [(&str, &[u8]); 3] = [
        (".env", env.as_bytes()),
        ("a/.env", a_env.as_bytes()),
        ("config.yml", yml.as_bytes()),
    ];
    write_tree(&input, &files);
    ctx.secrets.extend(v.iter().cloned());
    let (base_json, end_json) = (ctx.path("base.json"), ctx.path("end.json"));
    let ok = |o: Out| {
        assert_eq!(o.code, 0, "{}", o.err());
        o
    };
    let scan = |json: &PathBuf| ok(ctx.run(&["scan", &s(&input), "--json", &s(json)], ""));
    scan(&base_json);

    ok(ctx.run(&["profile", "add-key", "customapi-pass"], ""));
    let found = scan(&ctx.path("s1.json"));
    assert!(
        found
            .err()
            .contains("config.yml:1:17  custom-key  customapi-pass"),
        "{}",
        found.err()
    );

    // DB_NAME has none of the built-in key words: it is added, then ignored (D83).
    ok(ctx.run(&["profile", "add-key", "DB_NAME"], ""));
    ok(ctx.run(&["profile", "ignore-key", "DB_NAME"], ""));
    let ignored = scan(&ctx.path("s2.json"));
    assert!(
        ignored.err().contains("DB_NAME") && ignored.err().contains("[ignored: profile key]"),
        "{}",
        ignored.err()
    );
    let masked = ctx.path("masked");
    let m = ok(ctx.run_pass(&["mask", &s(&input), "--out", &s(&masked)]));
    assert!(
        m.err()
            .contains("1 findings ignored by profile (not masked)"),
        "{}",
        m.err()
    );

    ok(ctx.run(
        &["profile", "ignore", "--path", "a/.env", "--key", "API_KEY"],
        "",
    ));
    assert!(profile_list(&ctx).contains("a/.env key API_KEY"));
    let entry = scan(&ctx.path("s3.json"));
    assert!(
        entry.err().contains("[ignored: profile entry]"),
        "{}",
        entry.err()
    );
    ok(ctx.run(
        &[
            "profile", "unignore", "--path", "a/.env", "--key", "API_KEY",
        ],
        "",
    ));
    assert!(!profile_list(&ctx).contains("a/.env"));

    for (cmd, key) in [
        ("unignore-key", "DB_NAME"),
        ("remove-key", "DB_NAME"),
        ("remove-key", "customapi-pass"),
    ] {
        ok(ctx.run(&["profile", cmd, key], ""));
    }
    let list = profile_list(&ctx);
    assert!(
        list.contains("extra keys: (none)") && list.contains("ignored keys: (none)"),
        "{list}"
    );
    scan(&end_json);
    assert_eq!(
        std::fs::read(&end_json).expect("end"),
        std::fs::read(&base_json).expect("base")
    );

    let bad = ctx.run(&["profile", "add-key", "a/b"], "");
    assert_eq!(bad.code, 2);
    let both = ctx.run(
        &[
            "profile", "ignore", "--path", "x", "--key", "K", "--rule", "r",
        ],
        "",
    );
    assert_eq!(both.code, 2);
}

#[test]
fn c10_mask_token_prefix_round_trip() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let (masked, restored) = (ctx.path("masked"), ctx.path("restored"));
    let m = ctx.run_pass(&[
        "mask",
        &s(&sm.input),
        "--out",
        &s(&masked),
        "--token-prefix",
        "Infra_Mask_",
    ]);
    assert_eq!(m.code, 0, "{}", m.err());
    let out = all_bytes(&masked);
    assert!(
        contains(&out, "Infra_Mask_DB_PASSWORD_"),
        "custom token missing"
    );
    assert!(!contains(&out, "VEILCODE_"), "default token written");
    let r = ctx.run_pass(&["restore", &s(&masked), "--out", &s(&restored)]);
    assert_eq!(r.code, 0, "{}", r.err());
    assert!(r.err().contains("session forgotten"), "{}", r.err());
    assert_eq!(tree(&restored), tree(&sm.input));
    for o in [&m, &r] {
        assert_no_secret(&o.stdout, &ctx.secrets);
        assert_no_secret(&o.stderr, &ctx.secrets);
    }
}

#[test]
fn c10_invalid_token_prefix_is_refused_before_the_passphrase() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let masked = ctx.path("masked");
    let seventeen = format!("A{}_", "b".repeat(15));
    for bad in ["1bad_", "NoUnderscore", seventeen.as_str()] {
        let args = [
            "mask",
            &s(&sm.input),
            "--out",
            &s(&masked),
            "--token-prefix",
            bad,
        ];
        let o = ctx.run(&args, "");
        assert_eq!(o.code, 2, "{bad}: {}", o.err());
        assert!(o.err().contains("ending with _"), "{bad}: {}", o.err());
        assert!(!ctx.vault.exists() && !masked.exists(), "{bad}");
        assert_no_secret(&o.stderr, &ctx.secrets);
    }
    let help = ctx.run(&["mask", "--help"], "");
    assert_eq!(help.code, 0);
    assert!(help.out().contains("--token-prefix"), "{}", help.out());
}

#[test]
fn c10_mask_reports_findings_that_already_are_tokens() {
    let mut ctx = Ctx::new();
    let input = ctx.path("project");
    let pw = fake_password();
    let env = format!("API_KEY=Infra_Mask_API_KEY_abcdef01\nDB_PASSWORD={pw}\n");
    write_tree(&input, &[(".env", env.as_bytes())]);
    ctx.secrets.push(pw);
    let masked = ctx.path("masked");
    let m = ctx.run_pass(&[
        "mask",
        &s(&input),
        "--out",
        &s(&masked),
        "--token-prefix",
        "Infra_Mask_",
    ]);
    assert_eq!(m.code, 0, "{}", m.err());
    assert!(m.err().contains("masked 1 secrets"), "{}", m.err());
    let line = "1 findings already were placeholder tokens (not masked again)";
    assert!(m.err().contains(line), "{}", m.err());
    let out = all_bytes(&masked);
    assert!(contains(&out, "API_KEY=Infra_Mask_API_KEY_abcdef01\n"));
}

/// `mask <input> --out <out>` plus `extra`; expects exit 0 and the
/// "placeholder prefix: …" line `want` on stderr.
fn mask_expect_prefix(ctx: &Ctx, input: &Path, out: &str, extra: &[&str], want: &str) -> Vec<u8> {
    let (input, out) = (s(input), ctx.path(out));
    let mut args = vec!["mask", input.as_str(), "--out"];
    let out_s = s(&out);
    args.push(&out_s);
    args.extend_from_slice(extra);
    let m = ctx.run_pass(&args);
    assert_eq!(m.code, 0, "{}", m.err());
    let line = format!("placeholder prefix: {want}\n");
    assert!(m.err().contains(&line), "want {line:?} in {}", m.err());
    all_bytes(&out)
}

#[test]
fn c11_mask_uses_the_prefix_remembered_for_the_folder() {
    let mut ctx = Ctx::new();
    let sm = sample(&mut ctx);
    let other = ctx.path("other");
    write_tree(&other, &[("readme.txt", b"no secrets here\n")]);
    let flag = ["--token-prefix", "Infra_Mask_"];
    let out = mask_expect_prefix(
        &ctx,
        &sm.input,
        "m1",
        &flag,
        "Infra_Mask_ (from --token-prefix)",
    );
    assert!(contains(&out, "Infra_Mask_DB_PASSWORD_"));
    let want = "Infra_Mask_ (remembered for this folder)";
    let out = mask_expect_prefix(&ctx, &sm.input, "m2", &[], want);
    assert!(contains(&out, "Infra_Mask_DB_PASSWORD_") && !contains(&out, "VEILCODE_"));
    mask_expect_prefix(&ctx, &other, "m3", &[], "VEILCODE_ (default)");
    let reset = ["--token-prefix", "VEILCODE_"];
    let out = mask_expect_prefix(
        &ctx,
        &sm.input,
        "m4",
        &reset,
        "VEILCODE_ (from --token-prefix)",
    );
    assert!(contains(&out, "VEILCODE_DB_PASSWORD_") && !contains(&out, "Infra_Mask_"));
    let out = mask_expect_prefix(&ctx, &sm.input, "m5", &[], "VEILCODE_ (default)");
    assert!(contains(&out, "VEILCODE_DB_PASSWORD_"));
    let help = ctx.run(&["mask", "--help"], "");
    assert_eq!(help.code, 0);
    assert!(help.out().contains("remembered"), "{}", help.out());
}
