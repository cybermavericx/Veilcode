//! Veilcode desktop app: a thin eframe/egui wrapper over `veilcode-core`.
//! Native only: no webview, no links, no persistence (SPEC §10.4).
#![forbid(unsafe_code)]
// D125: a GUI-subsystem binary on Windows, so no console window opens
// (Rust reference, "The windows_subsystem attribute"; ignored elsewhere).
// Startup errors are therefore shown in the window (`app::StartupError`).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod idle;
mod state;
#[cfg(test)]
mod test_support;
mod theme;
mod viewmodel;
mod views;
mod worker;

use eframe::egui;
use state::GuiError;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn main() -> eframe::Result {
    // windows_subsystem is ignored off Windows, so this refusal (D105,
    // D109) still goes to stderr, before any window exists.
    #[cfg(target_os = "linux")]
    if let Err(e) = check_display(
        std::env::var_os("DISPLAY").as_deref(),
        Path::new(X11_SOCKET_DIR),
    ) {
        eprintln!("veilcode-gui: {e}");
        std::process::exit(2);
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Veilcode")
            .with_inner_size([980.0, 720.0]),
        // Inert without the `persistence` feature; set off for clarity.
        persist_window: false,
        persistence_path: None,
        ..eframe::NativeOptions::default()
    };
    let result = eframe::run_native(
        "Veilcode",
        options,
        Box::new(|cc| {
            // A window exists: an error file from an earlier failed start is stale.
            #[cfg(windows)]
            if let Some(dir) = data_dir() {
                clear_startup_error(&dir);
            }
            Ok(app::start(&cc.egui_ctx))
        }),
    );
    #[cfg(windows)]
    if let Err(e) = &result {
        report_startup_failure(e);
    }
    // An error makes `main` exit non-zero (and print it where stderr exists).
    result
}

/// D129(a): on Windows a `windows`-subsystem process has no stderr, so a
/// `run_native` failure (no window was possible) is written to
/// `startup-error.txt` in the local data dir (D81) instead.
#[cfg(windows)]
fn report_startup_failure(e: &eframe::Error) {
    if let Some(dir) = data_dir() {
        // Nothing else can show the error; a failed write is not reportable.
        let _ = write_startup_error(&dir, &e.to_string());
    }
}

/// Writes `msg` to `<dir>/startup-error.txt`, creating `dir` and replacing
/// an older file: a fresh `create_new` temp file (D54 style, never opens an
/// existing path) renamed over it.
#[cfg_attr(not(windows), allow(dead_code))]
fn write_startup_error(dir: &Path, msg: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let (path, tmp) = (
        dir.join(STARTUP_ERROR_FILE),
        dir.join("startup-error.txt.tmp"),
    );
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    f.write_all(capped(msg, MAX_STARTUP_ERROR).as_bytes())?;
    f.write_all(b"\n")?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// The name of the startup error file (README "Troubleshooting").
#[cfg_attr(not(windows), allow(dead_code))]
const STARTUP_ERROR_FILE: &str = "startup-error.txt";

/// The largest startup error text written, in bytes (D130).
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_STARTUP_ERROR: usize = 4096;

/// The local data dir (D81): the folder of the default vault file.
#[cfg(windows)]
fn data_dir() -> Option<PathBuf> {
    veilcode_core::default_vault_path().and_then(|p| p.parent().map(Path::to_path_buf))
}

/// `s` cut to at most `max` bytes, on a character boundary.
#[cfg_attr(not(windows), allow(dead_code))]
fn capped(s: &str, max: usize) -> &str {
    let end = (0..=max.min(s.len()))
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0);
    &s[..end]
}

/// Removes a stale `startup-error.txt` (best effort; errors are ignored).
#[cfg_attr(not(windows), allow(dead_code))]
fn clear_startup_error(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(STARTUP_ERROR_FILE));
}

/// Where local X servers listen (x11rb-protocol `connect_addresses`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const X11_SOCKET_DIR: &str = "/tmp/.X11-unix";

/// D105/D109: X11 libraries dial TCP when `DISPLAY` names a host, and fall
/// back to TCP `localhost:6000+N` when `:N` has no live local socket. So the
/// app starts only if `DISPLAY` is unset, or is `:N[.S]` / `unix:N[.S]` and
/// `<socket_dir>/X<N>` accepts a connection. Called on Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_display(display: Option<&OsStr>, socket_dir: &Path) -> Result<(), GuiError> {
    let Some(d) = display else {
        return Ok(());
    };
    let n = d.to_str().and_then(display_number);
    match n {
        Some(n) if socket_live(&socket_dir.join(format!("X{n}"))) => Ok(()),
        _ => Err(GuiError::RemoteDisplay),
    }
}

/// The display number of `:N`, `:N.S`, `unix:N` or `unix:N.S`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn display_number(d: &str) -> Option<&str> {
    let rest = d.strip_prefix("unix").unwrap_or(d).strip_prefix(':')?;
    let (n, screen) = rest.split_once('.').unwrap_or((rest, "0"));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    (digits(n) && digits(screen)).then_some(n)
}

/// D109/D110 preflight: a local X server accepts on `path`, or (Linux) on the
/// abstract socket of the same name, which x11rb and libxcb try first. Both
/// are local-only. The stream is closed at once (dropped).
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn socket_live(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok() || abstract_live(path)
}

#[cfg(target_os = "linux")]
fn abstract_live(path: &Path) -> bool {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    let name = path.as_os_str().as_encoded_bytes();
    SocketAddr::from_abstract_name(name)
        .and_then(|addr| UnixStream::connect_addr(&addr))
        .is_ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
#[allow(dead_code)]
fn abstract_live(_path: &Path) -> bool {
    false
}

/// No X11 on this target: never live.
#[cfg(not(unix))]
#[allow(dead_code)]
fn socket_live(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that holds no socket at all.
    fn empty_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tempdir")
    }

    /// Fails unless `value` is refused with a message that names DISPLAY,
    /// does not echo the value and suggests no value (no digits).
    fn assert_refused(value: &str, dir: &Path) {
        let e = check_display(Some(OsStr::new(value)), dir).expect_err(value);
        let msg = e.to_string();
        assert!(msg.contains("DISPLAY"), "{value}: {msg}");
        if !value.is_empty() {
            assert!(!msg.contains(value), "message echoes {value}");
        }
        assert!(!msg.chars().any(|c| c.is_ascii_digit()), "suggests a value");
    }

    #[test]
    fn g9_display_guard_accepts_local_rejects_remote() {
        let dir = empty_dir();
        assert!(check_display(None, dir.path()).is_ok(), "unset");
        for (ok, n) in [
            (":0", "0"),
            (":1.0", "1"),
            ("unix:0", "0"),
            ("unix:12.3", "12"),
        ] {
            assert_eq!(display_number(ok), Some(n), "{ok}");
        }
        let bad = [
            "/tmp/.X11-unix/X0",
            "localhost:10",
            "host:0",
            "10.0.0.1:0",
            "tcp/host:0",
            "[::1]:0",
            "",
            ":",
            ":0.",
            ":x",
            "unix:",
        ];
        for value in bad {
            assert_eq!(display_number(value), None, "{value}");
            assert_refused(value, dir.path());
        }
    }

    #[cfg(unix)]
    #[test]
    fn g9b_x11_preflight_needs_a_live_local_socket() {
        use std::os::unix::net::UnixListener;
        let dir = empty_dir();
        for value in [":7", "unix:7", ":7.0"] {
            assert_refused(value, dir.path()); // no socket
        }
        drop(UnixListener::bind(dir.path().join("X7")).expect("bind"));
        assert!(dir.path().join("X7").exists(), "socket file stays");
        for value in [":7", "unix:7.0"] {
            assert_refused(value, dir.path()); // refuses connections
        }
        std::fs::remove_file(dir.path().join("X7")).expect("remove");
        let _live = UnixListener::bind(dir.path().join("X7")).expect("bind");
        for value in [":7", ":7.0", "unix:7", "unix:7.0"] {
            assert!(
                check_display(Some(OsStr::new(value)), dir.path()).is_ok(),
                "{value}"
            );
        }
        for value in ["/tmp/.X11-unix/X7", "localhost:7", "host:7"] {
            assert_refused(value, dir.path()); // still refused with a live socket
        }
        assert_refused(":8", dir.path()); // other display, no socket
    }

    /// D110: an X server that listens only on the abstract socket (e.g.
    /// Xvfb under WSLg, where `/tmp/.X11-unix` is read-only) is accepted.
    #[cfg(target_os = "linux")]
    #[test]
    fn g9b_x11_preflight_accepts_a_live_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener};
        let dir = empty_dir();
        let name = dir.path().join("X9");
        assert_refused(":9", dir.path()); // nothing listening anywhere
        let addr = SocketAddr::from_abstract_name(name.as_os_str().as_encoded_bytes())
            .expect("abstract addr");
        let _live = UnixListener::bind_addr(&addr).expect("bind abstract");
        assert!(!name.exists(), "abstract socket has no file");
        assert!(check_display(Some(OsStr::new(":9")), dir.path()).is_ok());
        assert!(check_display(Some(OsStr::new("unix:9")), dir.path()).is_ok());
        assert_refused("localhost:9", dir.path());
    }

    /// D129(a): the file is created with its folder and replaced on reuse.
    #[test]
    fn startup_error_file_is_written_and_replaced() {
        let tmp = empty_dir();
        let dir = tmp.path().join("Veilcode").join("data");
        let path = write_startup_error(&dir, "first error").expect("write");
        assert_eq!(path, dir.join("startup-error.txt"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "first error\n"
        );
        write_startup_error(&dir, "second").expect("rewrite");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "second\n");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .expect("ls")
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("startup-error.txt")]);
    }

    /// D130(e): the text is capped at 4 KiB (on a char boundary), and a
    /// stale file is removed after a successful start.
    #[test]
    fn startup_error_text_is_capped_and_stale_file_removed() {
        let tmp = empty_dir();
        let long = "é".repeat(3000); // 6000 bytes
        let path = write_startup_error(tmp.path(), &long).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text, format!("{}\n", "é".repeat(2048)));
        clear_startup_error(tmp.path());
        assert!(!path.exists());
        clear_startup_error(tmp.path()); // already gone: no panic
        assert_eq!(std::fs::read_dir(tmp.path()).expect("ls").count(), 0);
    }
}
