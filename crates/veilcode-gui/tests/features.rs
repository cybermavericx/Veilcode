//! G4: the resolved dependency graph of our release targets has no
//! forbidden eframe/egui features and no browser-launching or HTTP/TLS
//! crate (SPEC §9, §10.1, D99), and no D-Bus stack on Linux (D104). Parses `cargo metadata` with a tiny JSON
//! reader, so the GUI crate needs no extra dependency.

use std::collections::BTreeMap;

const TARGETS: &[&str] = &["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"];
const FORBIDDEN_FEATURES: &[&str] = &["links", "persistence"];
const CHECKED_CRATES: &[&str] = &["eframe", "egui-winit", "egui"];
const BANNED: &[&str] = &[
    "webbrowser",
    "open",
    "opener",
    "reqwest",
    "ureq",
    "hyper",
    "rustls",
    "native-tls",
    "openssl",
];
/// D104: the D-Bus stack that accesskit pulls in on Linux (zbus can dial
/// `tcp:` bus addresses and spawn `unixexec:` programs).
const LINUX_BANNED: &[&str] = &[
    "zbus",
    "atspi",
    "accesskit_unix",
    "async-io",
    "async-process",
];
const LINUX: &str = "x86_64-unknown-linux-gnu";

#[derive(Debug)]
enum Json {
    Null,
    Bool,
    Num,
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(fields) => fields
                .iter()
                .find(|(k, _)| k == key)
                .map_or(&Json::Null, |(_, v)| v),
            _ => &Json::Null,
        }
    }

    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            _ => &[],
        }
    }

    fn str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            _ => "",
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.b.get(self.i).is_some_and(u8::is_ascii_whitespace) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        self.ws();
        assert_eq!(
            self.b.get(self.i),
            Some(&c),
            "JSON: expected {} at {}",
            c as char,
            self.i
        );
        self.i += 1;
    }

    fn peek(&mut self) -> u8 {
        self.ws();
        *self.b.get(self.i).expect("JSON: unexpected end")
    }

    fn value(&mut self) -> Json {
        match self.peek() {
            b'{' => self
                .list(b'{', b'}', |r| {
                    let k = r.string();
                    r.eat(b':');
                    Some((k, r.value()))
                })
                .map_or(Json::Null, Json::Obj),
            b'[' => self
                .list(b'[', b']', |r| Some(r.value()))
                .map_or(Json::Null, Json::Arr),
            b'"' => Json::Str(self.string()),
            b't' => self.word("true", Json::Bool),
            b'f' => self.word("false", Json::Bool),
            b'n' => self.word("null", Json::Null),
            _ => {
                let num = |c: &u8| c.is_ascii_digit() || b"+-.eE".contains(c);
                while self.b.get(self.i).is_some_and(num) {
                    self.i += 1;
                }
                Json::Num
            }
        }
    }

    fn list<T>(
        &mut self,
        open: u8,
        close: u8,
        mut item: impl FnMut(&mut Self) -> Option<T>,
    ) -> Option<Vec<T>> {
        self.eat(open);
        let mut out = Vec::new();
        if self.peek() == close {
            self.i += 1;
            return Some(out);
        }
        loop {
            out.extend(item(self));
            match self.peek() {
                b',' => self.i += 1,
                c if c == close => {
                    self.i += 1;
                    return Some(out);
                }
                c => panic!("JSON: unexpected {} at {}", c as char, self.i),
            }
        }
    }

    fn word(&mut self, w: &str, v: Json) -> Json {
        assert!(
            self.b[self.i..].starts_with(w.as_bytes()),
            "JSON: bad literal at {}",
            self.i
        );
        self.i += w.len();
        v
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = Vec::new();
        loop {
            let c = *self.b.get(self.i).expect("JSON: unterminated string");
            self.i += 1;
            match c {
                b'"' => return String::from_utf8_lossy(&out).into_owned(),
                b'\\' => self.escape(&mut out),
                _ => out.push(c),
            }
        }
    }

    fn escape(&mut self, out: &mut Vec<u8>) {
        let c = self.b[self.i];
        self.i += 1;
        let ch = match c {
            b'n' => '\n',
            b't' => '\t',
            b'r' => '\r',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'u' => {
                let hex = std::str::from_utf8(&self.b[self.i..self.i + 4]).expect("hex");
                self.i += 4;
                char::from_u32(u32::from_str_radix(hex, 16).expect("hex")).unwrap_or('\u{fffd}')
            }
            other => char::from(other),
        };
        out.extend(ch.to_string().as_bytes());
    }
}

#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn metadata(target: &str) -> Json {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            target,
        ])
        .args(["--manifest-path", manifest])
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Reader {
        b: &out.stdout,
        i: 0,
    }
    .value()
}

/// Package name and enabled features of every node in the resolved graph.
fn resolved(meta: &Json) -> Vec<(String, Vec<String>)> {
    let names: BTreeMap<&str, &str> = meta
        .get("packages")
        .arr()
        .iter()
        .map(|p| (p.get("id").str(), p.get("name").str()))
        .collect();
    let nodes = meta.get("resolve").get("nodes").arr();
    nodes
        .iter()
        .map(|n| {
            let name = names
                .get(n.get("id").str())
                .copied()
                .unwrap_or("")
                .to_string();
            let features = n
                .get("features")
                .arr()
                .iter()
                .map(|f| f.str().to_string())
                .collect();
            (name, features)
        })
        .collect()
}

#[test]
fn g4_forbidden_features_and_crates_absent() {
    for target in TARGETS {
        let graph = resolved(&metadata(target));
        assert!(
            graph.len() > 100,
            "{target}: implausibly small graph ({})",
            graph.len()
        );
        for krate in CHECKED_CRATES {
            let features = graph
                .iter()
                .find(|(n, _)| n == krate)
                .map(|(_, f)| f)
                .unwrap_or_else(|| panic!("{target}: {krate} not in the graph"));
            for bad in FORBIDDEN_FEATURES {
                assert!(
                    !features.iter().any(|f| f == bad),
                    "{target}: {krate} has feature {bad}"
                );
            }
        }
        let banned: Vec<_> = graph
            .iter()
            .filter(|(n, _)| BANNED.contains(&n.as_str()))
            .collect();
        assert!(banned.is_empty(), "{target}: banned crates {banned:?}");
    }
    assert_no_dbus_on_linux();
}

/// Package names in the `cargo tree` of the GUI for `target`. Unlike
/// `cargo metadata`, which unifies features across all targets (cargo
/// issue 7754), `cargo tree` applies the v2 feature resolver per target, so
/// it is the one that shows a target-specific feature (D104) is not enabled.
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn tree(target: &str) -> Vec<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = std::process::Command::new(cargo)
        .args(["tree", "--locked", "-e", "normal", "-p", "veilcode-gui"])
        .args(["--target", target, "--prefix", "none", "-f", "{p}"])
        .args(["--manifest-path", manifest])
        .output()
        .expect("run cargo tree");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let name = |l: &str| l.split_whitespace().next().unwrap_or("").to_string();
    text.lines().map(name).collect()
}

/// D104: no zbus/atspi family crate on Linux (also `zbus_names`,
/// `atspi-common`, …); Windows keeps its accesskit adapter.
fn assert_no_dbus_on_linux() {
    let linux = tree(LINUX);
    assert!(linux.len() > 100, "{LINUX}: implausibly small tree");
    let dbus: Vec<_> = linux
        .iter()
        .filter(|n| {
            LINUX_BANNED.contains(&n.as_str()) || n.starts_with("zbus") || n.starts_with("atspi")
        })
        .collect();
    assert!(dbus.is_empty(), "{LINUX}: D-Bus crates {dbus:?}");
    let windows = tree("x86_64-pc-windows-msvc");
    assert!(windows.iter().any(|n| n == "accesskit_windows"));
}
