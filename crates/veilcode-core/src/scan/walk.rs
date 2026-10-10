//! Input walk and file classification (SPEC §5, D35, D40, D43–D46).

use crate::error::{CoreError, Result};
use crate::scan::ScanOptions;
use crate::scan::finding::ScanReport;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};
use zeroize::Zeroizing;

/// Larger than this is oversized; exactly this is scanned.
pub(crate) const MAX_TEXT: usize = 5 * 1024 * 1024;
/// A NUL in this many leading bytes makes a file binary.
const BINARY_PROBE: usize = 8 * 1024;
/// Directory names excluded unless `no_default_excludes`.
const DEFAULT_EXCLUDES: [&str; 6] = [
    "node_modules",
    "vendor",
    "target",
    ".venv",
    "venv",
    "__pycache__",
];
const IGNORE_FILE: &str = ".veilcodeignore";
/// D44: the largest `.veilcodeignore` that is read.
const MAX_IGNORE: u64 = 1024 * 1024;

/// A regular file to classify.
pub(crate) struct FileEntry {
    pub(crate) rel_path: String,
    pub(crate) file_name: String,
    pub(crate) path: PathBuf,
    /// (dev, ino) seen by the walk (D45).
    pub(crate) ident: Option<(u64, u64)>,
}

/// A file's class; only text is scanned.
pub(crate) enum Class {
    Text(Zeroizing<Vec<u8>>),
    Binary,
    Oversized,
    /// Not the file the walk saw, or no longer a regular file (D45).
    Changed,
}

/// (dev, ino) on Unix; `None` elsewhere (D45).
#[cfg(unix)]
pub(crate) fn identity(meta: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

/// (dev, ino) on Unix; `None` elsewhere (D45).
#[cfg(not(unix))]
pub(crate) fn identity(_meta: &Metadata) -> Option<(u64, u64)> {
    None
}

/// A name for listing: the name itself, or (D46) an escaped form if it is not UTF-8.
fn display_name(name: &OsStr) -> String {
    if let Some(s) = name.to_str() {
        return s.to_string();
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().escape_ascii().to_string()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().into_owned()
    }
}

/// `/`-joined components of `path` below `root` (D12).
fn rel_path(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let parts: Vec<_> = rel
        .components()
        .map(|c| display_name(c.as_os_str()))
        .collect();
    parts.join("/")
}

/// D43: `.git` ignoring ASCII case and trailing dots and spaces.
fn is_git_name(name: &str) -> bool {
    name.trim_end_matches(['.', ' '])
        .eq_ignore_ascii_case(".git")
}

/// Walks `input` without following links. Symlinks and excluded entries go
/// into `report.skipped`; regular files are returned sorted by path.
pub(crate) fn walk(
    input: &Path,
    opts: &ScanOptions,
    report: &mut ScanReport,
) -> Result<Vec<FileEntry>> {
    if !input.is_dir() {
        return Err(CoreError::Io {
            path: input.to_path_buf(),
            kind: io::ErrorKind::NotADirectory,
        });
    }
    let ignore = load_ignore(input, &mut report.warnings)?;
    let mut files = Vec::new();
    let mut it = WalkDir::new(input)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();
    while let Some(entry) = it.next() {
        let entry = entry.map_err(|e| walk_error(input, &e))?;
        if entry.depth() == 0 {
            continue;
        }
        let rel = rel_path(input, entry.path());
        match visit(input, entry, rel, opts, &ignore, report)? {
            Visit::File(file) => files.push(file),
            Visit::Prune => it.skip_current_dir(),
            Visit::Next => {}
        }
    }
    Ok(files)
}

/// What the walk does with one entry.
enum Visit {
    File(FileEntry),
    /// A skipped directory: do not descend.
    Prune,
    Next,
}

/// Sorts one entry into a skip list, or returns it as a file to classify.
fn visit(
    input: &Path,
    entry: DirEntry,
    rel: String,
    opts: &ScanOptions,
    ignore: &GlobSet,
    report: &mut ScanReport,
) -> Result<Visit> {
    let kind = entry.file_type();
    let Some(name) = entry.file_name().to_str().map(str::to_string) else {
        report.skipped.non_utf8_name.push(rel); // D46
        return Ok(prune(kind.is_dir()));
    };
    if is_excluded(&entry, &name, &rel, opts, ignore) {
        report.skipped.excluded.push(rel);
        return Ok(prune(kind.is_dir()));
    } else if kind.is_symlink() {
        report.skipped.symlink.push(rel);
    } else if kind.is_file() {
        let meta = entry.metadata().map_err(|e| walk_error(input, &e))?;
        return Ok(Visit::File(FileEntry {
            rel_path: rel,
            file_name: name,
            ident: identity(&meta),
            path: entry.into_path(),
        }));
    } else if !kind.is_dir() {
        report.skipped.excluded.push(rel); // D40: FIFOs, sockets, devices
    }
    Ok(Visit::Next)
}

fn prune(is_dir: bool) -> Visit {
    if is_dir { Visit::Prune } else { Visit::Next }
}

fn walk_error(input: &Path, e: &walkdir::Error) -> CoreError {
    let path = e.path().unwrap_or(input);
    let kind = e.io_error().map_or(io::ErrorKind::Other, io::Error::kind);
    CoreError::Io {
        path: path.to_path_buf(),
        kind,
    }
}

/// `.git` dirs (D43, not overridable), default excludes, ignore globs.
fn is_excluded(
    entry: &DirEntry,
    name: &str,
    rel: &str,
    opts: &ScanOptions,
    ignore: &GlobSet,
) -> bool {
    let is_dir = entry.file_type().is_dir();
    if is_dir && is_git_name(name) {
        return true;
    }
    let default = is_dir && DEFAULT_EXCLUDES.contains(&name);
    (default && !opts.no_default_excludes) || ignore.is_match(rel)
}

/// D44: reads `.veilcodeignore` only if it is a regular file of at most 1 MiB.
/// A missing file means no globs.
fn read_ignore(path: &Path) -> Result<String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(CoreError::io(path, &e)),
    };
    if !meta.is_file() || meta.len() > MAX_IGNORE {
        return Err(CoreError::UnsafeIgnoreFile);
    }
    let file = File::open(path).map_err(|e| CoreError::io(path, &e))?;
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Err(CoreError::UnsafeIgnoreFile);
    }
    let mut bytes = Vec::new();
    file.take(MAX_IGNORE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CoreError::io(path, &e))?;
    if bytes.len() as u64 > MAX_IGNORE {
        return Err(CoreError::UnsafeIgnoreFile);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Parses `.veilcodeignore` at the root (D35, D40, D44).
fn load_ignore(input: &Path, warnings: &mut Vec<String>) -> Result<GlobSet> {
    let path = input.join(IGNORE_FILE);
    let text = read_ignore(&path)?;
    let mut builder = GlobSetBuilder::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !add_pattern(&mut builder, line) {
            warnings.push(format!(
                "{IGNORE_FILE} line {}: invalid pattern ignored",
                n + 1
            ));
        }
    }
    builder.build().map_err(|_| CoreError::Io {
        path,
        kind: io::ErrorKind::InvalidData,
    })
}

/// D35 pattern rules; D40: a leading `/` anchors to the root. False if invalid.
fn add_pattern(builder: &mut GlobSetBuilder, line: &str) -> bool {
    let rooted = line.strip_prefix('/').unwrap_or(line);
    let dir_only = rooted.strip_suffix('/');
    let base = dir_only.unwrap_or(rooted);
    let base = if base.contains('/') || line.starts_with('/') {
        base.to_string()
    } else {
        format!("**/{base}")
    };
    let mut globs = vec![base.clone()];
    if dir_only.is_some() {
        globs.push(format!("{base}/**"));
    }
    let built: Option<Vec<_>> = globs
        .iter()
        .map(|g| GlobBuilder::new(g).literal_separator(true).build().ok())
        .collect();
    let Some(built) = built else { return false };
    for g in built {
        builder.add(g);
    }
    true
}

/// Opens (read-only) and classifies a regular file. D45: the opened file
/// must still be a regular file with the identity the walk saw. Residual
/// risk (accepted in D45): a FIFO swapped in before `open` can block.
pub(crate) fn classify(path: &Path, expected: Option<(u64, u64)>) -> Result<Class> {
    let file = File::open(path).map_err(|e| CoreError::io(path, &e))?;
    let meta = file.metadata().map_err(|e| CoreError::io(path, &e))?;
    if !meta.is_file() || identity(&meta) != expected {
        return Ok(Class::Changed);
    }
    // Pre-sized so growth rarely reallocates (old buffers are not wiped).
    let cap = usize::try_from(meta.len())
        .unwrap_or(MAX_TEXT)
        .min(MAX_TEXT)
        + 1;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    file.take(MAX_TEXT as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| CoreError::io(path, &e))?;
    if buf.len() > MAX_TEXT {
        return Ok(Class::Oversized);
    }
    if buf.iter().take(BINARY_PROBE).any(|&b| b == 0) {
        return Ok(Class::Binary);
    }
    Ok(Class::Text(buf))
}
