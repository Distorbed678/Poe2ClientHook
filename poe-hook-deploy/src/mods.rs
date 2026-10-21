//! Installing a mod into a game directory, the way the launcher lays it out
//! (`<game dir>/poe-hook-mods/<id>/` plus the enabled list in `state.toml`, see
//! `docs/mod-manifest.md`). Used by `cargo xtask deploy-mod` and `deploy-client --sample-mod`;
//! nothing here ever writes mod files by hand into a game folder.
//!
//! A folder installed here carries a marker file, so [`install_mod`] replaces only its own
//! installs (never a mod the launcher put there) and [`remove_installed_mods`] (part of
//! [`crate::revert`]) removes exactly those.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use poe_hook_mods::{
    MANIFEST_FILE, MODS_DIR, STATE_FILE, check_abi, parse_manifest, parse_state, state_text,
};

use crate::install::install_file;

/// Present in the folders [`install_mod`] created.
pub const DEPLOY_MARKER: &str = ".installed-by-poe-hook-deploy";

#[derive(Debug)]
pub struct InstalledMod {
    pub id: String,
    pub dir: PathBuf,
    /// Listed in `state.toml` (loads at the next client start).
    pub enabled: bool,
}

fn read_enabled(mods_dir: &Path) -> Result<Vec<String>> {
    match std::fs::read_to_string(mods_dir.join(STATE_FILE)) {
        Ok(t) => parse_state(&t)
            .map(|s| s.enabled)
            .map_err(anyhow::Error::msg),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).context("reading state.toml"),
    }
}

fn write_enabled(mods_dir: &Path, enabled: &[String]) -> Result<()> {
    std::fs::create_dir_all(mods_dir)?;
    let path = mods_dir.join(STATE_FILE);
    let tmp = mods_dir.join("state.toml.tmp");
    std::fs::write(&tmp, state_text(enabled))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))
}

/// Installs the mod in `source_dir` (a folder with a `mod.toml`) into
/// `<game_dir>/poe-hook-mods/<id>/` and, with `enable`, appends it to the load order in
/// `state.toml` (without `enable` it is installed and taken out of the list).
///
/// Only `mod.toml`, the `[data]` paths and the entry DLL are copied. The entry DLL comes from
/// `built_dll` (a build output elsewhere) or, when that is `None`, from the source folder.
/// Refuses a manifest the loader would not accept (invalid, or another mod ABI) and a folder
/// that exists but was not installed by this function.
pub fn install_mod(
    game_dir: &Path,
    source_dir: &Path,
    built_dll: Option<&Path>,
    enable: bool,
) -> Result<InstalledMod> {
    let text = std::fs::read_to_string(source_dir.join(MANIFEST_FILE))
        .with_context(|| format!("reading {}/{MANIFEST_FILE}", source_dir.display()))?;
    let parsed = parse_manifest(&text)
        .map_err(|e| anyhow::anyhow!("invalid {MANIFEST_FILE}: {}", e.join("; ")))?;
    let m = parsed.manifest;
    check_abi(&m).map_err(|e| anyhow::anyhow!("{}: {e}", m.id))?;

    // Everything that can fail before anything is touched.
    let dll_from = m
        .entry_dll
        .as_ref()
        .map(|rel| built_dll.map_or_else(|| source_dir.join(rel), Path::to_path_buf));
    if let Some(from) = dll_from.as_ref().filter(|f| !f.is_file()) {
        bail!("entry DLL {} not found (build it first)", from.display());
    }
    let mods_dir = game_dir.join(MODS_DIR);
    let dst = mods_dir.join(&m.id);
    if dst.exists() {
        if !dst.join(DEPLOY_MARKER).exists() {
            bail!(
                "{} exists but was not installed by deploy (launcher?); not overwriting it",
                dst.display()
            );
        }
        std::fs::remove_dir_all(&dst).with_context(|| format!("replacing {}", dst.display()))?;
    }
    std::fs::create_dir_all(&dst)?;
    std::fs::write(dst.join(DEPLOY_MARKER), format!("{}\n", m.id))?;
    std::fs::write(dst.join(MANIFEST_FILE), &text)?;
    for rel in m
        .data_tables
        .iter()
        .chain(&m.data_opcodes)
        .chain(m.config_defaults.as_ref())
    {
        copy_tree(&source_dir.join(rel), &dst.join(rel))?;
    }
    if let (Some(rel), Some(from)) = (&m.entry_dll, &dll_from) {
        install_file(from, &dst.join(rel))?;
    }

    let mut enabled = read_enabled(&mods_dir)?;
    enabled.retain(|e| *e != m.id);
    if enable {
        enabled.push(m.id.clone());
    }
    write_enabled(&mods_dir, &enabled)?;
    Ok(InstalledMod {
        id: m.id,
        dir: dst,
        enabled: enable,
    })
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for e in std::fs::read_dir(from)? {
            let e = e?;
            copy_tree(&e.path(), &to.join(e.file_name()))?;
        }
    } else {
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::copy(from, to)
            .with_context(|| format!("copying {} -> {}", from.display(), to.display()))?;
    }
    Ok(())
}

/// Removes every mod folder [`install_mod`] created, takes them out of `state.toml`, and
/// removes `state.toml` and `poe-hook-mods/` when nothing else is left in them. Mods the
/// launcher installed are left alone. Returns what was removed.
pub fn remove_installed_mods(game_dir: &Path) -> Result<Vec<PathBuf>> {
    let mods_dir = game_dir.join(MODS_DIR);
    let mut touched = Vec::new();
    let Ok(rd) = std::fs::read_dir(&mods_dir) else {
        return Ok(touched);
    };
    let mut ids = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.join(DEPLOY_MARKER).exists() {
            ids.push(e.file_name().to_string_lossy().into_owned());
            std::fs::remove_dir_all(&p)?;
            touched.push(p);
        }
    }
    let mut enabled = read_enabled(&mods_dir).unwrap_or_default();
    let before = enabled.len();
    enabled.retain(|e| !ids.contains(e));
    if enabled.is_empty() {
        let state = mods_dir.join(STATE_FILE);
        if state.exists() {
            std::fs::remove_file(&state)?;
            touched.push(state);
        }
    } else if enabled.len() != before {
        write_enabled(&mods_dir, &enabled)?;
    }
    // Only succeeds when empty.
    if std::fs::remove_dir(&mods_dir).is_ok() {
        touched.push(mods_dir);
    }
    Ok(touched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn source(dir: &Path, id: &str, hook_api: u32) -> PathBuf {
        let s = dir.join(format!("src-{id}"));
        fs::create_dir_all(s.join("data/tables")).unwrap();
        fs::write(s.join("data/tables/t.txt"), "x").unwrap();
        fs::write(s.join("junk.rs"), "not copied").unwrap();
        fs::write(
            s.join("mod.toml"),
            format!(
                "manifest_version = 1\nid = \"{id}\"\nname = \"{id}\"\nversion = \"1.0.0\"\n[game]\nhook_api = {hook_api}\n[entry]\ndll = \"m.dll\"\n[data]\ntables = [\"data/tables\"]\n"
            ),
        )
        .unwrap();
        s
    }

    fn enabled(game: &Path) -> Vec<String> {
        read_enabled(&game.join(MODS_DIR)).unwrap()
    }

    #[test]
    fn install_copies_only_the_mod_files_and_enables_in_order() {
        let t = tempfile::tempdir().unwrap();
        let game = t.path().join("game");
        fs::create_dir_all(&game).unwrap();
        let built = t.path().join("built.dll");
        fs::write(&built, b"MZ").unwrap();
        let a = source(t.path(), "alpha", 1);
        let b = source(t.path(), "beta", 1);
        let r = install_mod(&game, &a, Some(&built), true).unwrap();
        assert_eq!(r.id, "alpha");
        install_mod(&game, &b, Some(&built), true).unwrap();
        let d = game.join("poe-hook-mods/alpha");
        assert!(d.join("mod.toml").is_file() && d.join("m.dll").is_file());
        assert!(d.join("data/tables/t.txt").is_file());
        assert!(!d.join("junk.rs").exists());
        assert_eq!(enabled(&game), ["alpha", "beta"]);
        // Reinstalling keeps the position in the list only by moving to the end: no duplicates.
        install_mod(&game, &a, Some(&built), true).unwrap();
        assert_eq!(enabled(&game), ["beta", "alpha"]);
        // Installed but not enabled.
        install_mod(&game, &a, Some(&built), false).unwrap();
        assert_eq!(enabled(&game), ["beta"]);
    }

    #[test]
    fn install_refuses_a_wrong_abi_a_missing_dll_and_a_foreign_folder() {
        let t = tempfile::tempdir().unwrap();
        let game = t.path().join("game");
        fs::create_dir_all(&game).unwrap();
        let built = t.path().join("built.dll");
        fs::write(&built, b"MZ").unwrap();
        let wrong = source(t.path(), "wrong", 99);
        let e = install_mod(&game, &wrong, Some(&built), true).unwrap_err();
        assert!(e.to_string().contains("mod ABI 99"), "{e}");
        let ok = source(t.path(), "right", 1);
        let e = install_mod(&game, &ok, Some(&t.path().join("nope.dll")), true).unwrap_err();
        assert!(e.to_string().contains("not found"), "{e}");
        // A failed install leaves nothing behind.
        assert!(!game.join("poe-hook-mods").exists());
        // A folder the launcher made is not ours to replace.
        fs::create_dir_all(game.join("poe-hook-mods/right")).unwrap();
        let e = install_mod(&game, &ok, Some(&built), true).unwrap_err();
        assert!(e.to_string().contains("not overwriting"), "{e}");
    }

    #[test]
    fn revert_removes_only_what_deploy_installed() {
        let t = tempfile::tempdir().unwrap();
        let game = t.path().join("game");
        fs::create_dir_all(&game).unwrap();
        let built = t.path().join("built.dll");
        fs::write(&built, b"MZ").unwrap();
        let a = source(t.path(), "alpha", 1);
        install_mod(&game, &a, Some(&built), true).unwrap();
        // A launcher-installed mod, enabled too.
        let theirs = game.join("poe-hook-mods/theirs");
        fs::create_dir_all(&theirs).unwrap();
        fs::write(theirs.join("mod.toml"), "x").unwrap();
        write_enabled(&game.join(MODS_DIR), &["theirs".into(), "alpha".into()]).unwrap();

        let touched = remove_installed_mods(&game).unwrap();
        assert!(touched.contains(&game.join("poe-hook-mods/alpha")));
        assert!(!game.join("poe-hook-mods/alpha").exists());
        assert!(theirs.join("mod.toml").is_file());
        assert_eq!(enabled(&game), ["theirs"]);

        // With nothing of the launcher's left, the directory goes away entirely.
        fs::remove_dir_all(&theirs).unwrap();
        write_enabled(&game.join(MODS_DIR), &[]).unwrap();
        let b = source(t.path(), "beta", 1);
        install_mod(&game, &b, Some(&built), true).unwrap();
        remove_installed_mods(&game).unwrap();
        assert!(!game.join(MODS_DIR).exists());
    }
}
