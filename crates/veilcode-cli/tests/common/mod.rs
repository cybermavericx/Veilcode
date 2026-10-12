//! Small copies of the core test helpers (core's are `#[cfg(test)]`), plus a
//! runner for the real `veilcode` binary. Secrets are generated at runtime.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::path::{Path, PathBuf};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// One random u64 from std's randomly seeded SipHash keys (no extra crate).
fn random_u64(i: usize) -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_usize(i);
    h.finish()
}

/// `n` random `[A-Za-z0-9]` characters.
pub fn random_alnum(n: usize) -> String {
    let pick = |i| char::from(ALNUM[(random_u64(i) % ALNUM.len() as u64) as usize]);
    (0..n).map(pick).collect()
}

/// A random GitHub-PAT-shaped string; the prefix is built at runtime.
pub fn fake_github_pat() -> String {
    [["gh", "p_"].concat(), random_alnum(36)].concat()
}

/// 20 random alnum characters plus one symbol from `!%^*`.
pub fn fake_password() -> String {
    let sym = char::from(b"!%^*"[(random_u64(99) % 4) as usize]);
    format!("{}{sym}", random_alnum(20))
}

/// Writes each `(rel, bytes)` under `dir`, creating parent directories.
pub fn write_tree(dir: &Path, files: &[(&str, &[u8])]) {
    for (rel, bytes) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create dirs");
        }
        std::fs::write(&path, bytes).expect("write file");
    }
}

/// Every file's bytes under `dir`, keyed by `/`-separated relative path.
pub fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    tree_into(dir, "", &mut out);
    out
}

fn tree_into(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type().expect("file type").is_dir() {
            tree_into(&entry.path(), &rel, out);
        } else {
            out.insert(rel, std::fs::read(entry.path()).expect("read file"));
        }
    }
}

/// All file bytes under `dir`, NUL-separated.
pub fn all_bytes(dir: &Path) -> Vec<u8> {
    tree(dir)
        .into_values()
        .flat_map(|mut v| {
            v.push(0);
            v
        })
        .collect()
}

pub fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Fails if any secret occurs in `haystack`; the message shows only a length.
pub fn assert_no_secret(haystack: &[u8], secrets: &[impl AsRef<[u8]>]) {
    for s in secrets {
        let s = s.as_ref();
        assert!(!s.is_empty(), "assert_no_secret: empty secret");
        if haystack.windows(s.len()).any(|w| w == s) {
            panic!("secret …({}) found in output", s.len());
        }
    }
}

/// One finished run of the binary.
pub struct Out {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Out {
    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// A temp dir with a per-test vault and profile path, and the secrets that
/// must never appear on any stream.
pub struct Ctx {
    pub tmp: tempfile::TempDir,
    pub vault: PathBuf,
    pub profile: PathBuf,
    pub secrets: Vec<String>,
}

pub const PASS: &str = "cli test passphrase";

impl Ctx {
    pub fn new() -> Ctx {
        let tmp = tempfile::tempdir().expect("tempdir");
        Ctx {
            vault: tmp.path().join("project.vc"),
            profile: tmp.path().join("profile.toml"),
            secrets: vec![PASS.to_string()],
            tmp,
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    /// Runs `veilcode <args> --vault V --profile P` with `stdin`; every
    /// stdout and stderr is checked against all known secrets.
    pub fn run(&self, args: &[&str], stdin: &str) -> Out {
        let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        all.extend([
            "--vault".into(),
            s(&self.vault),
            "--profile".into(),
            s(&self.profile),
        ]);
        let out = run_binary(&all, stdin.as_bytes(), self.tmp.path());
        assert_no_secret(&out.stdout, &self.secrets);
        assert_no_secret(&out.stderr, &self.secrets);
        out
    }

    /// `run` with `--passphrase-stdin` and the test passphrase.
    pub fn run_pass(&self, args: &[&str]) -> Out {
        let mut all = args.to_vec();
        all.push("--passphrase-stdin");
        self.run(&all, &format!("{PASS}\n"))
    }
}

/// A path as a `&str` argument (temp dirs are UTF-8 here).
pub fn s(p: &Path) -> String {
    p.to_str().expect("utf-8 temp path").to_string()
}

/// Runs the real binary. HOME and the XDG dirs point into the temp dir so a
/// bug can never touch the user's real vault or profile.
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
pub fn run_binary(args: &[String], stdin: &[u8], home: &Path) -> Out {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_veilcode"))
        .args(args)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn veilcode");
    if let Some(mut pipe) = child.stdin.take() {
        // The binary may exit without reading stdin; a broken pipe is fine.
        let _ = pipe.write_all(stdin);
    }
    let out = child.wait_with_output().expect("wait veilcode");
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// Removes the finding object whose JSON text contains `needle` from the
/// `findings` array of a pretty-printed scan report (string-aware brace scan).
pub fn drop_finding(json: &str, needle: &str) -> String {
    let start = json.find("\"findings\": [").expect("findings array") + 13;
    let mut objects: Vec<(usize, usize)> = Vec::new();
    let (mut depth, mut in_str, mut esc, mut open) = (0, false, false, 0);
    for (i, c) in json[start..].char_indices() {
        let i = start + i;
        match (in_str, esc, c) {
            (true, true, _) => esc = false,
            (true, false, '\\') => esc = true,
            (true, false, '"') => in_str = false,
            (true, ..) => {}
            (false, _, '"') => in_str = true,
            (false, _, '{') => {
                if depth == 0 {
                    open = i;
                }
                depth += 1;
            }
            (false, _, '}') => {
                depth -= 1;
                if depth == 0 {
                    objects.push((open, i + 1));
                }
            }
            (false, _, ']') if depth == 0 => break,
            _ => {}
        }
    }
    let (a, b) = *objects
        .iter()
        .find(|(a, b)| json[*a..*b].contains(needle))
        .expect("finding to drop");
    let kept: Vec<&str> = objects
        .iter()
        .filter(|o| **o != (a, b))
        .map(|(x, y)| &json[*x..*y])
        .collect();
    let end = objects.last().expect("objects").1;
    format!("{}{}{}", &json[..start], kept.join(","), &json[end..])
}
