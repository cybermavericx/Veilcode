//! Path safety tests (TEST_CASES.md R6, R11; D14, D52, D54).

use super::*;
use crate::error::CoreError;

fn prepared() -> (tempfile::TempDir, OutputDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(tmp.path().join("in")).expect("mkdir");
    let out = OutputDir::prepare(&tmp.path().join("out"), &tmp.path().join("in")).expect("prepare");
    (tmp, out)
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).expect("valid rel path")
}

#[test]
fn rel_path_rules() {
    for ok in ["a", "a/b.txt", ".env", "a/.git-x/b", "..a", "a..", "a b/c"] {
        assert_eq!(rel(ok).as_str(), ok);
    }
    let bad = [
        "", "/", "a/", "/a", "./a", "a/./b", "..", "a/..", "a//b", "a\\b", "C:", "c:x", "\\\\s\\x",
        "a\0b",
    ];
    for b in bad {
        let err = RelPath::parse(b).err();
        assert!(
            matches!(err, Some(CoreError::BadRelPath { ref rel_path }) if rel_path == b),
            "{b:?}"
        );
    }
}

#[test]
fn r6_safe_join_stays_under_root() {
    let (_tmp, out) = prepared();
    let p = safe_join(&out, &rel("a/b/c.txt"));
    assert_eq!(p, out.root().join("a").join("b").join("c.txt"));
    assert!(out.root().is_absolute());
    create_dir(&out, &rel("a")).expect("mkdir");
    write_new(&out, &rel("a/x"), b"x", 0o644).expect("write");
    let log = take_write_log();
    assert_eq!(
        log,
        vec![out.root().join("a"), out.root().join("a").join("x")]
    );
}

#[test]
fn r11_output_never_overwrites() {
    let (tmp, out) = prepared();
    write_new(&out, &rel("a.txt"), b"first", 0o644).expect("write");
    let err = write_new(&out, &rel("a.txt"), b"second", 0o644).expect_err("exists");
    assert!(
        matches!(
            err,
            CoreError::Io {
                kind: std::io::ErrorKind::AlreadyExists,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(
        std::fs::read(out.root().join("a.txt")).expect("read"),
        b"first"
    );
    assert!(create_dir(&out, &rel("a.txt")).is_err());
    #[cfg(unix)]
    {
        let target = tmp.path().join("target.txt");
        std::fs::write(&target, b"target").expect("write");
        std::os::unix::fs::symlink(&target, out.root().join("link")).expect("ln");
        let err = write_new(&out, &rel("link"), b"evil", 0o644).expect_err("symlink");
        assert!(matches!(
            err,
            CoreError::Io {
                kind: std::io::ErrorKind::AlreadyExists,
                ..
            }
        ));
        assert_eq!(std::fs::read(&target).expect("read"), b"target");
        std::os::unix::fs::symlink(tmp.path(), out.root().join("dirlink")).expect("ln");
        assert!(write_new(&out, &rel("dirlink/evil.txt"), b"evil", 0o644).is_err());
        assert!(!tmp.path().join("evil.txt").exists());
        let dangling = out.root().join("dangling");
        std::os::unix::fs::symlink(tmp.path().join("nowhere"), &dangling).expect("ln");
        assert!(write_new(&out, &rel("dangling"), b"evil", 0o644).is_err());
        assert!(!tmp.path().join("nowhere").exists());
    }
    let _ = tmp;
}

#[test]
fn prepare_rules() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = tmp.path().join("in");
    std::fs::create_dir_all(input.join("sub")).expect("mkdir");
    let new = tmp.path().join("x").join("y");
    let out = OutputDir::prepare(&new, &input).expect("creates missing parents");
    assert!(new.is_dir());
    assert_eq!(out.root(), std::fs::canonicalize(&new).expect("canon"));
    // Unix resolves `nope/..` only if `nope` exists; Windows resolves it lexically.
    #[cfg(unix)]
    {
        let up = input.join("nope").join("..").join("..").join("z");
        assert!(OutputDir::prepare(&up, &input).is_err());
        assert!(!tmp.path().join("z").exists());
    }
    let inside = input.join("sub").join("..").join("sub2");
    assert!(OutputDir::prepare(&inside, &input).is_err());
    assert!(!input.join("sub2").exists());
}
