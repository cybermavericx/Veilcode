//! P8 finding-viewer tests (TEST_CASES VW1–VW3, D137).

use super::*;
use crate::scan::Detector;
use crate::test_support::*;
use sha2::{Digest, Sha256};
use std::path::Path;

/// A finding over `start..end` of `content` at `rel`.
fn finding(rel: &str, content: &[u8], start: usize, end: usize, id: &str) -> Finding {
    let line = content[..start].iter().filter(|&&b| b == b'\n').count() + 1;
    Finding {
        id: id.to_string(),
        rel_path: rel.to_string(),
        line,
        column: 1,
        start,
        end,
        rule_id: "r".to_string(),
        detector: Detector::D2,
        key_name: None,
        preview: String::new(),
        file_sha256: crate::hex::encode(&Sha256::digest(content)),
        ignored: None,
    }
}

fn report(findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        findings,
        ..ScanReport::default()
    }
}

fn lines(view: FindingView) -> Vec<ViewLine> {
    match view {
        FindingView::Lines(l) => l,
        other => panic!("expected lines, got {other:?}"),
    }
}

fn kinds(line: &ViewLine) -> Vec<PartKind> {
    line.parts.iter().map(|p| p.kind).collect()
}

fn joined(line: &ViewLine) -> String {
    line.parts.iter().map(ViewPart::text).collect()
}

fn span_of(content: &str, needle: &str) -> (usize, usize) {
    let start = content.find(needle).expect("needle");
    (start, start + needle.len())
}

#[test]
fn vw1_context_lines_with_values_masked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (pw, other) = (fake_password(), fake_password());
    let mut text = String::new();
    for i in 1..=40 {
        match i {
            20 => text.push_str(&format!("DB_PASSWORD={pw}\n")),
            22 => text.push_str(&format!("API_KEY={other}\n")),
            _ => text.push_str(&format!("# line {i}\n")),
        }
    }
    write_tree(dir.path(), &[("app/.env", text.as_bytes())]);
    let (s, e) = span_of(&text, &pw);
    let (os, oe) = span_of(&text, &other);
    let f = finding("app/.env", text.as_bytes(), s, e, "a");
    let g = finding("app/.env", text.as_bytes(), os, oe, "b");
    let rep = report(vec![f, g]);
    let view = view_finding(dir.path(), &rep, "a").expect("view");
    assert_no_secret(format!("{view:?}").as_bytes(), &[&pw, &other]);
    let ls = lines(view);
    let numbers: Vec<usize> = ls.iter().map(|l| l.number).collect();
    assert_eq!(numbers, (5..=35).collect::<Vec<_>>());
    let hits: Vec<usize> = ls.iter().filter(|l| l.hit).map(|l| l.number).collect();
    assert_eq!(hits, vec![20]);
    let l20 = &ls[15];
    assert_eq!(kinds(l20), vec![PartKind::Plain, PartKind::Selected]);
    assert_eq!(joined(l20), "DB_PASSWORD=", "value held before Reveal");
    assert_eq!((l20.parts[1].start, l20.parts[1].end), (s, e));
    let l22 = &ls[17];
    assert_eq!(kinds(l22), vec![PartKind::Plain, PartKind::Other]);
    assert_eq!(joined(l22), "API_KEY=", "other values are not held");
    assert_eq!((l22.parts[1].start, l22.parts[1].end), (os, oe));
    assert_eq!(joined(&ls[0]), "# line 5");
    assert_eq!(kinds(&ls[0]), vec![PartKind::Plain]);
    let all: String = ls.iter().map(joined).collect();
    assert_no_secret(all.as_bytes(), &[&pw, &other]);
    // Reveal reads the file again and fills only the viewed value.
    let mut shown = view_finding_revealed(dir.path(), &rep, "a");
    let ls = lines_mut(&mut shown);
    assert_eq!(joined(&ls[15]), format!("DB_PASSWORD={pw}"));
    assert_eq!(joined(&ls[17]), "API_KEY=");
    shown.hide_values();
    let all: String = lines(shown).iter().map(joined).collect();
    assert_no_secret(all.as_bytes(), &[&pw, &other]);
}

fn view_finding_revealed(root: &Path, rep: &ScanReport, id: &str) -> FindingView {
    reveal_finding(root, rep, id).expect("reveal")
}

fn lines_mut(view: &mut FindingView) -> &[ViewLine] {
    match view {
        FindingView::Lines(l) => l,
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn vw1_overlapping_spans_never_show_other_bytes_as_plain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b) = (random_alnum(20), random_alnum(20));
    let text = format!(
        "k={a}{b} tail
"
    );
    write_tree(dir.path(), &[("o.txt", text.as_bytes())]);
    let (s, e) = span_of(&text, &a);
    let bs = text.find(&b).expect("b");
    let rep = report(vec![
        finding("o.txt", text.as_bytes(), s, e, "sel"),
        // Overlaps the end of the viewed value and covers all of `b`.
        finding("o.txt", text.as_bytes(), e - 5, bs + b.len(), "o1"),
        // Starts inside the first other span.
        finding("o.txt", text.as_bytes(), bs + 3, bs + 8, "o2"),
    ]);
    let others = [(e - 5, bs + b.len()), (bs + 3, bs + 8)];
    for revealed in [false, true] {
        let view = if revealed {
            reveal_finding(dir.path(), &rep, "sel")
        } else {
            view_finding(dir.path(), &rep, "sel")
        };
        let ls = lines(view.expect("view"));
        let parts = &ls[0].parts;
        let mut at = 0;
        for p in parts.iter().filter(|p| p.kind != PartKind::Cut) {
            assert!(p.start >= at, "parts overlap");
            at = p.end;
            if p.kind == PartKind::Plain {
                let hit = others.iter().any(|&(x, y)| p.start < y && x < p.end);
                assert!(!hit, "other finding bytes shown as plain");
            }
        }
        let all = joined(&ls[0]);
        assert_no_secret(all.as_bytes(), &[&b]);
        assert!(all.ends_with(" tail"), "plain text after the spans");
    }
}

#[test]
fn vw1_value_spanning_lines_is_split_per_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b, c) = (random_alnum(30), random_alnum(30), random_alnum(30));
    let text = format!("one\nkey: {a}\r\n{b}\n{c} end\nlast\n");
    write_tree(dir.path(), &[("k.yml", text.as_bytes())]);
    let start = text.find(&a).expect("a");
    let end = text.find(&c).expect("c") + c.len();
    let rep = report(vec![finding("k.yml", text.as_bytes(), start, end, "m")]);
    let ls = lines(reveal_finding(dir.path(), &rep, "m").expect("view"));
    assert_eq!(ls.len(), 5);
    let hits: Vec<usize> = ls.iter().filter(|l| l.hit).map(|l| l.number).collect();
    assert_eq!(hits, vec![2, 3, 4]);
    assert_eq!(kinds(&ls[1]), vec![PartKind::Plain, PartKind::Selected]);
    assert_eq!(ls[1].parts[1].text(), a, "CR is not part of the line");
    assert_eq!(kinds(&ls[2]), vec![PartKind::Selected]);
    assert_eq!(kinds(&ls[3]), vec![PartKind::Selected, PartKind::Plain]);
    assert_eq!(joined(&ls[3]), format!("{c} end"));
}

#[test]
fn vw2_too_large_and_changed_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let mut big = format!("K={pw}\n").into_bytes();
    big.resize(VIEW_MAX_BYTES + 1, b'x');
    let small = format!("K={pw}\n");
    write_tree(
        dir.path(),
        &[("big.txt", &big), ("small.env", small.as_bytes())],
    );
    let f = finding("big.txt", &big, 2, 2 + pw.len(), "big");
    let g = finding("small.env", small.as_bytes(), 2, 2 + pw.len(), "small");
    let rep = report(vec![f, g]);
    let v = view_finding(dir.path(), &rep, "big").expect("view");
    assert!(matches!(v, FindingView::TooLarge), "{v:?}");
    write_tree(
        dir.path(),
        &[("small.env", format!("K={pw}x\n").as_bytes())],
    );
    let v = view_finding(dir.path(), &rep, "small").expect("view");
    assert!(matches!(v, FindingView::Changed), "{v:?}");
    let err = view_finding(dir.path(), &rep, "nope").expect_err("unknown");
    assert!(matches!(err, CoreError::UnknownFinding { .. }));
}

#[test]
fn vw2_long_line_is_cut_on_char_boundaries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    // Both 120-byte cuts land inside a 2-byte character (U+00E9).
    let before = format!("{}\u{e9}", "x\u{e9}".repeat(8_334));
    let after = format!("x{}", "\u{e9}".repeat(12_500));
    let text = format!("{before}{pw}{after}\n");
    let cut_at = |i: usize| !text.is_char_boundary(i);
    let (s, e) = span_of(&text, &pw);
    assert!(cut_at(s - AROUND) && cut_at(e + AROUND));
    assert!(text.len() > 50_000);
    write_tree(dir.path(), &[("min.js", text.as_bytes())]);
    let rep = report(vec![finding("min.js", text.as_bytes(), s, e, "m")]);
    let ls = lines(reveal_finding(dir.path(), &rep, "m").expect("view"));
    let parts = &ls[0].parts;
    let k: Vec<PartKind> = parts.iter().map(|p| p.kind).collect();
    use PartKind::{Cut, Plain, Selected};
    assert_eq!(k, vec![Cut, Plain, Selected, Plain, Cut]);
    assert_eq!(parts[0].text(), ELLIPSIS);
    assert_eq!(parts[2].text(), pw);
    for p in [&parts[1], &parts[3]] {
        assert!(p.text().len() <= AROUND && p.text().len() >= AROUND - 3);
        assert!(!p.text().contains('\u{fffd}'), "cut inside a character");
    }
}

#[test]
fn vw2_long_lines_and_values_are_cut() {
    let dir = tempfile::tempdir().expect("tempdir");
    let value = random_alnum(VALUE_MAX + 50);
    let text = format!("{}\nV={value}\n", "z".repeat(LINE_MAX + 10));
    write_tree(dir.path(), &[("a.txt", text.as_bytes())]);
    let (s, e) = span_of(&text, &value);
    let rep = report(vec![finding("a.txt", text.as_bytes(), s, e, "v")]);
    let ls = lines(reveal_finding(dir.path(), &rep, "v").expect("view"));
    assert_eq!(kinds(&ls[0]), vec![PartKind::Plain, PartKind::Cut]);
    assert_eq!(ls[0].parts[0].text().len(), LINE_MAX);
    use PartKind::{Cut, Plain, Selected};
    assert_eq!(kinds(&ls[1]), vec![Plain, Selected, Cut]);
    assert_eq!(ls[1].parts[1].text(), &value[..VALUE_MAX]);
}

#[test]
fn vw2_invalid_utf8_is_shown_lossily() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    let content = [b"\xff\xfeK=".as_slice(), pw.as_bytes(), b" \xc3\n"].concat();
    write_tree(dir.path(), &[("bin.env", &content)]);
    let rep = report(vec![finding("bin.env", &content, 4, 4 + pw.len(), "u")]);
    let ls = lines(reveal_finding(dir.path(), &rep, "u").expect("view"));
    assert_eq!(ls[0].parts[0].text(), "\u{fffd}\u{fffd}K=");
    assert_eq!(ls[0].parts[1].text(), pw);
    assert_eq!(ls[0].parts[2].text(), " \u{fffd}");
}

fn refused(root: &Path, rel: &str, content: &[u8], secret: &str) -> CoreError {
    let rep = report(vec![finding(rel, content, 0, 1, "x")]);
    let err = view_finding(root, &rep, "x").expect_err(rel);
    assert_no_secret(err.to_string().as_bytes(), &[secret]);
    err
}

#[test]
fn vw3_bad_relative_paths_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    for rel in ["../x", "/etc/passwd", "C:/x", "a\\b", "a/../b", ""] {
        let err = refused(dir.path(), rel, pw.as_bytes(), &pw);
        assert!(matches!(err, CoreError::BadRelPath { .. }), "{rel}: {err}");
    }
}

#[test]
fn vw3_directory_where_a_file_was_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pw = fake_password();
    write_tree(dir.path(), &[("sub/f.txt", pw.as_bytes())]);
    let err = refused(dir.path(), "sub", pw.as_bytes(), &pw);
    assert!(matches!(err, CoreError::NotViewable { .. }), "{err}");
}

#[cfg(unix)]
#[test]
fn vw3_symlinks_below_the_root_are_refused() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (root, outside) = (tmp.path().join("root"), tmp.path().join("outside"));
    let pw = fake_password();
    write_tree(&outside, &[("f.txt", pw.as_bytes())]);
    write_tree(&root, &[("real/ok.txt", b"x")]);
    symlink(&outside, root.join("link")).expect("dir link");
    symlink(outside.join("f.txt"), root.join("l.txt")).expect("file link");
    symlink(outside.join("f.txt"), root.join("real/l.txt")).expect("nested link");
    for rel in ["link/f.txt", "l.txt", "real/l.txt"] {
        let err = refused(&root, rel, pw.as_bytes(), &pw);
        assert!(matches!(err, CoreError::NotViewable { .. }), "{rel}: {err}");
    }
}

#[cfg(unix)]
#[test]
fn vw3b_symlinks_inside_the_root_are_refused() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    let pw = fake_password();
    write_tree(
        &root,
        &[
            ("real.txt", pw.as_bytes()),
            ("realdir/f.txt", pw.as_bytes()),
        ],
    );
    symlink(root.join("real.txt"), root.join("link.txt")).expect("file link");
    symlink(root.join("realdir"), root.join("linkdir")).expect("dir link");
    for rel in ["link.txt", "linkdir/f.txt"] {
        let err = refused(&root, rel, pw.as_bytes(), &pw);
        assert!(matches!(err, CoreError::NotViewable { .. }), "{rel}: {err}");
    }
    let rep = report(vec![finding("real.txt", pw.as_bytes(), 0, 1, "ok")]);
    assert!(matches!(
        view_finding(&root, &rep, "ok"),
        Ok(FindingView::Lines(_))
    ));
}

#[test]
fn vw2_lossy_text_is_built_without_reallocating() {
    let worst = [0xffu8; 100];
    let text = lossy(&worst);
    assert_eq!(text.as_str(), String::from_utf8_lossy(&worst));
    assert_eq!(text.len(), 300);
    let sized = String::with_capacity(300).capacity();
    assert_eq!(text.capacity(), sized, "the buffer grew");
    let mixed = b"ok \xc3( caf\xc3\xa9 \xff\xfe end";
    assert_eq!(lossy(mixed).as_str(), String::from_utf8_lossy(mixed));
}

#[cfg(unix)]
#[test]
fn vw3_open_does_not_follow_a_link() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_tree(tmp.path(), &[("real.txt", b"x")]);
    symlink(tmp.path().join("real.txt"), tmp.path().join("l.txt")).expect("link");
    assert!(open_no_follow(&tmp.path().join("real.txt")).is_ok());
    assert!(
        open_no_follow(&tmp.path().join("l.txt")).is_err(),
        "link followed"
    );
}
