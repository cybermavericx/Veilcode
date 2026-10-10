//! Write safety (SPEC §6.1 steps 1–2, §6.2; D14, D52, D54, D55).
//!
//! `RelPath` can only be built through validation, `OutputDir` only through
//! `prepare`, and every output path is built by `safe_join`. All output
//! files and directories are created here, never over an existing path.

use crate::error::{CoreError, Result};
use crate::scan::walk::{FileEntry, identity};
use std::ffi::OsStr;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};

/// A validated relative path: `/`-separated, no `.`/`..`/empty components,
/// no root, drive or UNC prefix, no `\` or NUL (D14).
pub(crate) struct RelPath(String);

impl RelPath {
    /// Validates `s` without touching the file system.
    pub(crate) fn parse(s: &str) -> Result<RelPath> {
        if is_valid(s) {
            Ok(RelPath(s.to_string()))
        } else {
            Err(CoreError::BadRelPath {
                rel_path: s.to_string(),
            })
        }
    }

    /// The path text.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid(s: &str) -> bool {
    let b = s.as_bytes();
    let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
    !s.is_empty() && !drive && !s.contains(['\\', '\0']) && s.split('/').all(valid_component)
}

/// One component; it must also be a single normal component to this
/// platform's `Path` (catches e.g. `a:b` drive forms on Windows).
fn valid_component(c: &str) -> bool {
    if c.is_empty() || c == "." || c == ".." {
        return false;
    }
    let mut parts = Path::new(c).components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(n)), None) if n == OsStr::new(c)
    )
}

/// A canonical, empty output directory outside the input.
pub(crate) struct OutputDir {
    root: PathBuf,
}

impl OutputDir {
    /// SPEC §6.1 step 1, D68: refuse an existing output or one inside the
    /// input; on Unix refuse a group/other-writable non-sticky parent. Then
    /// create it (and missing parents) owner-only.
    pub(crate) fn prepare(out: &Path, input: &Path) -> Result<OutputDir> {
        let input = canonical(input)?;
        match std::fs::symlink_metadata(out) {
            Ok(_) => {
                if let Ok(existing) = std::fs::canonicalize(out) {
                    refuse_inside(&existing, &input)?;
                }
                return Err(CoreError::OutputExists {
                    path: out.to_path_buf(),
                });
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::io(out, &e)),
        }
        let (base, planned) = planned_path(out)?;
        refuse_inside(&planned, &input)?;
        check_parent(&base)?;
        create_private(out)?;
        let root = canonical(out)?;
        if root.starts_with(&input) {
            let _ = std::fs::remove_dir(&root);
            return Err(CoreError::OutputInsideInput);
        }
        Ok(OutputDir { root })
    }

    /// D69: removes the tree this run created and wraps `cause`.
    pub(crate) fn discard(&self, cause: CoreError) -> CoreError {
        let cleaned = std::fs::remove_dir_all(&self.root).is_ok();
        CoreError::PartialOutput {
            cleaned,
            dir: self.root.clone(),
            cause: Box::new(cause),
        }
    }

    /// The canonical output directory.
    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

fn canonical(p: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(p).map_err(|e| CoreError::io(p, &e))
}

fn refuse_inside(candidate: &Path, input: &Path) -> Result<()> {
    if candidate.starts_with(input) {
        Err(CoreError::OutputInsideInput)
    } else {
        Ok(())
    }
}

/// Where a not-yet-existing `out` will be: (its nearest existing ancestor,
/// canonicalised; that plus the missing components, which must be normal).
fn planned_path(out: &Path) -> Result<(PathBuf, PathBuf)> {
    let mut base = out.to_path_buf();
    let mut missing = Vec::new();
    while !(base.as_os_str().is_empty() || base.exists()) {
        match base.components().next_back() {
            Some(Component::Normal(name)) => missing.push(name.to_os_string()),
            _ => {
                return Err(CoreError::Io {
                    path: out.to_path_buf(),
                    kind: ErrorKind::InvalidInput,
                });
            }
        }
        base.pop();
    }
    let base = if base.as_os_str().is_empty() {
        Path::new(".")
    } else {
        base.as_path()
    };
    let base = canonical(base)?;
    let mut planned = base.clone();
    planned.extend(missing.iter().rev());
    Ok((base, planned))
}

/// D68 (Unix): the nearest existing parent must not be writable by group
/// or others unless it has the sticky bit (like `/tmp`).
#[cfg(unix)]
fn check_parent(base: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(base).map_err(|e| CoreError::io(base, &e))?;
    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(CoreError::UnsafeOutputParent {
            path: base.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_parent(_base: &Path) -> Result<()> {
    Ok(())
}

/// Creates missing parents, then `out` itself exclusively, `0700` on Unix.
fn create_private(out: &Path) -> Result<()> {
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        dir_builder(true)
            .create(parent)
            .map_err(|e| CoreError::io(parent, &e))?;
    }
    dir_builder(false).create(out).map_err(|e| match e.kind() {
        ErrorKind::AlreadyExists => CoreError::OutputExists {
            path: out.to_path_buf(),
        },
        _ => CoreError::io(out, &e),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let private = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(out, private).map_err(|e| CoreError::io(out, &e))?;
    }
    Ok(())
}

fn dir_builder(recursive: bool) -> DirBuilder {
    let mut builder = DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

/// The only way to build an output path: `rel`'s components under the root.
pub(crate) fn safe_join(out: &OutputDir, rel: &RelPath) -> PathBuf {
    let mut path = out.root.clone();
    path.extend(rel.0.split('/'));
    path
}

/// Every parent of `rel` under the root must be a real directory, not a
/// symlink (D54: never write through a pre-planted link).
fn check_parents(out: &OutputDir, rel: &RelPath) -> Result<()> {
    let parts: Vec<&str> = rel.0.split('/').collect();
    let mut path = out.root.clone();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| CoreError::io(&path, &e))?;
        if !meta.file_type().is_dir() {
            return Err(CoreError::Io {
                path,
                kind: ErrorKind::NotADirectory,
            });
        }
    }
    Ok(())
}

/// Creates directory `rel` (never an existing path).
pub(crate) fn create_dir(out: &OutputDir, rel: &RelPath) -> Result<()> {
    check_parents(out, rel)?;
    let path = safe_join(out, rel);
    log_write(&path);
    std::fs::create_dir(&path).map_err(|e| CoreError::io(&path, &e))
}

/// Creates file `rel` with `create_new` (D54), owner-only until `finish`.
fn create_file(out: &OutputDir, rel: &RelPath) -> Result<(File, PathBuf)> {
    check_parents(out, rel)?;
    let path = safe_join(out, rel);
    log_write(&path);
    #[cfg(test)]
    injected_failure(&path)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&path).map_err(|e| CoreError::io(&path, &e))?;
    Ok((file, path))
}

/// Writes a new file `rel` holding `bytes`, with permission bits `mode` (D55).
pub(crate) fn write_new(out: &OutputDir, rel: &RelPath, bytes: &[u8], mode: u32) -> Result<()> {
    let (mut file, path) = create_file(out, rel)?;
    file.write_all(bytes)
        .map_err(|e| CoreError::io(&path, &e))?;
    set_mode(&file, &path, mode)?;
    file.sync_all().map_err(|e| CoreError::io(&path, &e))
}

/// Copies input file `src` as-is to a new file `rel`, keeping its mode;
/// `inspect` sees every chunk in order. The opened source must still be
/// the regular file the walk saw (D45).
pub(crate) fn copy_new(
    out: &OutputDir,
    rel: &RelPath,
    src: &FileEntry,
    inspect: &mut dyn FnMut(&[u8]),
) -> Result<()> {
    let mut input = File::open(&src.path).map_err(|e| CoreError::io(&src.path, &e))?;
    let meta = input.metadata().map_err(|e| CoreError::io(&src.path, &e))?;
    if !meta.is_file() || identity(&meta) != src.ident {
        return Err(CoreError::Rescan);
    }
    let (mut file, path) = create_file(out, rel)?;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(CoreError::io(&src.path, &e)),
        };
        inspect(&chunk[..n]);
        file.write_all(&chunk[..n])
            .map_err(|e| CoreError::io(&path, &e))?;
    }
    set_mode(&file, &path, src.mode)?;
    file.sync_all().map_err(|e| CoreError::io(&path, &e))
}

/// Fsyncs each created directory and the output root (Unix; SPEC §6.2 step 5).
#[cfg(unix)]
pub(crate) fn sync_dirs(out: &OutputDir, dirs: &[RelPath]) -> Result<()> {
    let paths = dirs.iter().map(|d| safe_join(out, d));
    for path in paths.chain(std::iter::once(out.root.clone())) {
        File::open(&path)
            .and_then(|d| d.sync_all())
            .map_err(|e| CoreError::io(&path, &e))?;
    }
    Ok(())
}

/// No directory fsync off Unix (VERIFY_LOG: no std API for it on Windows).
#[cfg(not(unix))]
pub(crate) fn sync_dirs(_out: &OutputDir, _dirs: &[RelPath]) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(file: &File, path: &Path, mode: u32) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(Permissions::from_mode(mode & 0o777))
        .map_err(|e| CoreError::io(path, &e))
}

/// D55: no permission handling off Unix.
#[cfg(not(unix))]
fn set_mode(_file: &File, _path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static WRITE_LOG: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Test hook (R6): records every path this module creates.
fn log_write(_path: &Path) {
    #[cfg(test)]
    WRITE_LOG.with(|log| log.borrow_mut().push(_path.to_path_buf()));
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Test hook (LF7): after `n` more files are created, file creation fails.
#[cfg(test)]
pub(crate) fn fail_file_writes_after(n: Option<usize>) {
    FAIL_AFTER.with(|f| f.set(n));
}

#[cfg(test)]
fn injected_failure(path: &Path) -> Result<()> {
    match FAIL_AFTER.with(std::cell::Cell::get) {
        Some(0) => Err(CoreError::Io {
            path: path.to_path_buf(),
            kind: ErrorKind::PermissionDenied,
        }),
        Some(n) => {
            FAIL_AFTER.with(|f| f.set(Some(n - 1)));
            Ok(())
        }
        None => Ok(()),
    }
}

/// Returns and clears this thread's write log.
#[cfg(test)]
pub(crate) fn take_write_log() -> Vec<PathBuf> {
    WRITE_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

#[cfg(test)]
mod tests;
