//! S22 (D44): an unsafe `.veilcodeignore` fails the scan without being read.
//! An integration test, so the FIFO case may run `mkfifo` (no libc, SPEC §9).

use std::path::Path;
use veilcode_core::{CoreError, ScanOptions, scan};

const D44: &str = "unsafe .veilcodeignore (must be a regular file ≤ 1 MiB)";

fn assert_d44(dir: &Path) {
    match scan(dir, &ScanOptions::default()) {
        Err(e @ CoreError::UnsafeIgnoreFile) => assert_eq!(e.to_string(), D44),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("scan succeeded"),
    }
}

#[test]
fn s22_unsafe_veilcodeignore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ignore = dir.path().join(".veilcodeignore");
    std::fs::write(&ignore, vec![b'#'; 1024 * 1024 + 1]).expect("write");
    assert_d44(dir.path());
    // Exactly 1 MiB is allowed.
    std::fs::write(&ignore, vec![b'#'; 1024 * 1024]).expect("write");
    let r = scan(dir.path(), &ScanOptions::default()).expect("scan");
    assert_eq!(r.scanned_files.len(), 1);
    #[cfg(unix)]
    unix_cases(dir.path(), &ignore);
}

/// Runs `mkfifo` (test-only process launch, allowed in crates/*/tests per clippy.toml).
#[cfg(unix)]
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn unix_cases(dir: &Path, ignore: &Path) {
    let real = dir.join("real-ignore");
    std::fs::write(&real, b"secrets/**\n").expect("write");
    std::fs::remove_file(ignore).expect("rm");
    std::os::unix::fs::symlink(&real, ignore).expect("symlink");
    assert_d44(dir);
    std::fs::remove_file(ignore).expect("rm");
    match std::process::Command::new("mkfifo").arg(ignore).status() {
        Ok(s) if s.success() => assert_d44(dir),
        _ => eprintln!("s22: mkfifo unavailable, FIFO case skipped"),
    }
}
