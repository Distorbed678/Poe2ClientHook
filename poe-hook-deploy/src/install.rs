use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// `path` with `.orig` appended to the file name.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".orig");
    path.with_file_name(name)
}

/// Copies `path` to `path.orig` unless a backup exists already (so the pristine file is never
/// overwritten by repeated deploys). Returns whether a backup was made.
pub fn backup_once(path: &Path) -> Result<bool> {
    let orig = backup_path(path);
    if path.exists() && !orig.exists() {
        std::fs::copy(path, &orig).with_context(|| format!("backing up {}", path.display()))?;
        return Ok(true);
    }
    Ok(false)
}

/// Copies a DLL through a temporary file and a rename: a running client keeps its mapping of
/// the old file intact (overwriting a mapped file in place can corrupt it), and the core
/// loader only ever sees a complete file.
pub fn install_file(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_extension("dll.tmp");
    copy(from, &tmp)?;
    std::fs::rename(&tmp, to).with_context(|| format!("renaming to {}", to.display()))?;
    Ok(())
}

pub(crate) fn copy(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to)
        .with_context(|| format!("copying {} -> {}", from.display(), to.display()))?;
    Ok(())
}
