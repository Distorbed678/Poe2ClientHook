//! Starting the client through Proton (Linux) with a prefix owned by the caller, and moving the
//! crash dumps the client would upload.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

use crate::{CLIENT_EXE, HOOK_CONFIG, STEAM_APPID, hook_config::top_level_string};

/// Arguments that make a standalone-login client skip its built-in patcher.
///
/// Without Steam the client believes it was started by the standalone patcher launcher: it
/// first opens the patcher window and connects to GGG's patch servers
/// (`us.patch.pathofexile2.com`, ...). The patcher normally starts the real client with
/// `--success-event <inherited event handle>`; a client started with that option (and without
/// `--disable-client-switching`) skips the patcher (`FUN_1401162d0` in docs/re/standalone-login.md).
/// The event is only signalled and closed at the end of start-up (`SetEvent`/`CloseHandle` on
/// handle `0`, which just fail), so `0` is a safe dummy.
pub const STANDALONE_CLIENT_ARGS: [&str; 2] = ["--success-event", "0"];

/// Extra client arguments for the installation in `game_dir`, from its `poe-hook.toml`:
/// [`STANDALONE_CLIENT_ARGS`] when `login_mode = "standalone"` and the mode is not official.
pub fn client_args(game_dir: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(game_dir.join(HOOK_CONFIG)) else {
        return Vec::new();
    };
    client_args_for(&text)
}

fn client_args_for(config_text: &str) -> Vec<String> {
    let official = top_level_string(config_text, "mode").as_deref() == Some("official");
    let standalone = top_level_string(config_text, "login_mode").as_deref() == Some("standalone");
    if standalone && !official {
        STANDALONE_CLIENT_ARGS.map(str::to_owned).to_vec()
    } else {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct ProtonLaunch {
    /// The Steam root (`~/.local/share/Steam`); see [`default_steam_root`].
    pub steam_root: PathBuf,
    /// Proton installation, a folder name under `steamapps/common` (e.g. `Proton - Experimental`).
    pub proton: String,
    /// A dedicated prefix; never the Steam install's `compatdata/<appid>`.
    pub prefix_dir: PathBuf,
    /// The client directory with `PathOfExileSteam.exe`.
    pub game_dir: PathBuf,
    /// Pending crash dumps are moved here before launch (so nothing is uploaded and the dumps
    /// stay available for debugging). `None` leaves them.
    pub crash_dump_dir: Option<PathBuf>,
}

pub fn default_steam_root() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var("HOME").context("HOME not set")?).join(".local/share/Steam"))
}

impl ProtonLaunch {
    /// The command that starts the client; does not run it.
    pub fn command(&self) -> Result<Command> {
        let proton_bin = self
            .steam_root
            .join("steamapps/common")
            .join(&self.proton)
            .join("proton");
        if !proton_bin.exists() {
            bail!("{} not found", proton_bin.display());
        }
        let game = std::fs::canonicalize(&self.game_dir)?;
        let mut cmd = Command::new(proton_bin);
        cmd.arg("run")
            .arg(game.join(CLIENT_EXE))
            .args(client_args(&game))
            .current_dir(&game)
            .env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &self.steam_root)
            .env("STEAM_COMPAT_DATA_PATH", &self.prefix_dir)
            .env("SteamAppId", STEAM_APPID)
            .env("SteamGameId", STEAM_APPID)
            .env("WINEDLLOVERRIDES", "version=n,b");
        Ok(cmd)
    }

    /// Moves crash dumps, then runs the client and waits for it to exit. Steam must be running.
    pub fn launch(&self) -> Result<()> {
        std::fs::create_dir_all(&self.prefix_dir)?;
        if let Some(target) = &self.crash_dump_dir {
            for moved in quarantine_crash_dumps(&self.prefix_dir, target)? {
                println!("moved crash dump {}", moved.display());
            }
        }
        let mut cmd = self.command()?;
        let status = cmd.status().with_context(|| format!("running {cmd:?}"))?;
        if !status.success() {
            bail!("{cmd:?} failed with {status}");
        }
        Ok(())
    }
}

/// The client uploads pending crash dumps (`PoE-*.dmp` plus `.poecap`/`.txt` side files) from
/// a helper process at startup. Moves them from the prefix into `target`; returns the new paths.
pub fn quarantine_crash_dumps(prefix_dir: &Path, target: &Path) -> Result<Vec<PathBuf>> {
    let users = prefix_dir.join("pfx/drive_c/users");
    let mut moved = Vec::new();
    let Ok(entries) = std::fs::read_dir(&users) else {
        return Ok(moved);
    };
    for user in entries.flatten() {
        let dir = user
            .path()
            .join("Documents/My Games/Path of Exile 2/poe2_production");
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        for file in files.flatten() {
            let name = file.file_name();
            if !name.to_string_lossy().starts_with("PoE-") {
                continue;
            }
            std::fs::create_dir_all(target)?;
            let to = target.join(&name);
            std::fs::rename(file.path(), &to)
                .with_context(|| format!("moving {}", file.path().display()))?;
            moved.push(to);
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_dumps_are_moved() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path().join("prefix");
        let dir = prefix
            .join("pfx/drive_c/users/steamuser/Documents/My Games/Path of Exile 2/poe2_production");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("PoE-1.dmp"), b"x").unwrap();
        std::fs::write(dir.join("keep.txt"), b"y").unwrap();
        let target = tmp.path().join("dumps");
        let moved = quarantine_crash_dumps(&prefix, &target).unwrap();
        assert_eq!(moved, vec![target.join("PoE-1.dmp")]);
        assert!(dir.join("keep.txt").exists());
    }

    #[test]
    fn standalone_adds_the_patcher_skip_option() {
        let args = |t: &str| client_args_for(t);
        let skip = vec!["--success-event".to_owned(), "0".to_owned()];
        assert_eq!(
            args("mode = \"private\"\nlogin_mode = \"standalone\"\n"),
            skip
        );
        assert_eq!(args("login_mode = \"standalone\"\n"), skip);
        assert!(args("mode = \"private\"\nlogin_mode = \"steam\"\n").is_empty());
        assert!(args("mode = \"private\"\n").is_empty());
        // Official mode never gets standalone behaviour.
        assert!(args("mode = \"official\"\nlogin_mode = \"standalone\"\n").is_empty());
    }

    #[test]
    fn missing_config_adds_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(client_args(tmp.path()).is_empty());
        std::fs::write(
            tmp.path().join(HOOK_CONFIG),
            "login_mode = \"standalone\"\n",
        )
        .unwrap();
        assert_eq!(client_args(tmp.path()), ["--success-event", "0"]);
    }

    #[test]
    fn missing_proton_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let l = ProtonLaunch {
            steam_root: tmp.path().into(),
            proton: "nope".into(),
            prefix_dir: tmp.path().join("p"),
            game_dir: tmp.path().into(),
            crash_dump_dir: None,
        };
        assert!(l.command().is_err());
    }
}
