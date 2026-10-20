//! Host-side deployment of the client hook into a game directory. Used by `cargo xtask` in
//! Poe2ModdingProject and meant for the launcher as well.
//!
//! Nothing here knows the layout of a particular repository: every directory comes in as a
//! parameter ([`DeployOptions::game_dir`], [`DeployOptions::dll_dir`], ...).
//!
//! What a deploy does ([`deploy`]):
//! 1. backs up `gateway_list.txt` once (`.orig`), then writes a single local entry, or puts the
//!    original back for official servers ([`Mode::Official`], read-only);
//! 2. installs `version.dll` (the loader) and `poe_hook_core.dll` (the hot-reloadable core);
//! 3. creates `poe-hook.toml` from the built-in template if it does not exist yet (edits survive
//!    redeploys) and sets `mode`, `login_mode`, `trusted_servers`, `position_sync_port`,
//!    `dump_dir`, `auto_keys` in it (official mode: `login_mode = "steam"` and no trusted
//!    servers, whatever the options say);
//! 4. writes `steam_appid.txt`.
//!
//! [`deploy_core`] installs only the core, [`revert`] undoes everything,
//! [`launch::ProtonLaunch`] starts the client through Proton, and
//! [`login_token::write_login_token`] signs a launcher account in without typing a password.

pub mod gateway;
pub mod hook_config;
mod install;
pub mod launch;
pub mod login_token;
mod trusted;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub use gateway::GatewayEntry;
pub use hook_config::{hook_path, set_hook_key};
pub use install::{backup_once, backup_path, install_file};
pub use login_token::{LoginTokenFiles, write_login_token};
pub use trusted::resolve_trusted_servers;

/// The loader, installed as the client's `version.dll`.
pub const LOADER_DLL: &str = "version.dll";
/// The file `cargo build` produces for the loader (`poe-hook`), looked up in [`DeployOptions::dll_dir`].
pub const LOADER_BUILD_NAME: &str = "poe_hook.dll";
/// The hot-reloadable debug core loaded by `version.dll`.
pub const CORE_DLL: &str = "poe_hook_core.dll";
/// The hook's configuration next to the client executable.
pub const HOOK_CONFIG: &str = "poe-hook.toml";
/// Starting point for [`HOOK_CONFIG`]; copied once into the game directory.
pub const DEFAULT_HOOK_CONFIG: &str = include_str!("../../poe-hook/poe-hook.toml");
pub const STEAM_APPID_FILE: &str = "steam_appid.txt";
pub const STEAM_APPID: &str = "2694490";
pub const GATEWAY_FILE: &str = "gateway_list.txt";
pub const CLIENT_EXE: &str = "PathOfExileSteam.exe";

/// How the hook behaves (`mode` in `poe-hook.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Our server: crypto bypass, external connections refused.
    Private,
    /// Official servers, read-only: the hook only observes and logs. The original gateway
    /// list stays in place.
    Official,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Private => "private",
            Mode::Official => "official",
        }
    }
}

/// Which login the client shows (`login_mode` in `poe-hook.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMode {
    /// Account name and password (or remembered token): the loader patches the client's
    /// platform detection. Only effective in [`Mode::Private`].
    Standalone,
    /// The client as shipped (Steam login). Always used in [`Mode::Official`].
    Steam,
}

impl LoginMode {
    pub fn as_str(self) -> &'static str {
        match self {
            LoginMode::Standalone => "standalone",
            LoginMode::Steam => "steam",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeployOptions {
    /// The client directory (next to `PathOfExileSteam.exe`).
    pub game_dir: PathBuf,
    /// Build output directory holding [`LOADER_BUILD_NAME`] and [`CORE_DLL`].
    pub dll_dir: PathBuf,
    pub mode: Mode,
    /// The only gateway entry to write in [`Mode::Private`]. `None` leaves the list alone.
    pub gateway: Option<GatewayEntry>,
    /// UDP port of the instance server for position reports (`[features] position_sync_port`).
    pub position_sync_port: Option<u16>,
    /// Where the hook writes generated outputs (`dump_dir`); created if missing and written
    /// to the config as a path the client can read (see [`hook_path`]).
    pub dump_dir: Option<PathBuf>,
    /// `login_mode` for [`Mode::Private`]; ignored (forced to `steam`) in [`Mode::Official`].
    pub login_mode: LoginMode,
    /// `trusted_servers` for [`Mode::Private`]: `host:port` entries the client treats like
    /// loopback (not blocked, no read-only latch, crypto bypass). Host names are resolved to
    /// IPv4 here ([`resolve_trusted_servers`]). Ignored (written empty) in [`Mode::Official`].
    pub trusted_servers: Vec<String>,
}

/// What [`deploy`] did, for the caller's log.
#[derive(Debug, Default)]
pub struct DeployReport {
    pub gateway: Option<String>,
    pub dump_dir: Option<String>,
    /// The `login_mode` that was written.
    pub login_mode: Option<LoginMode>,
    /// The `trusted_servers` that were written (resolved).
    pub trusted_servers: Vec<String>,
    /// Entries that could not be used.
    pub warnings: Vec<String>,
}

pub fn deploy(opts: &DeployOptions) -> Result<DeployReport> {
    let game = &opts.game_dir;
    let mut report = DeployReport::default();

    // Gateway list: keep the original once, then write a single local entry (or put the
    // original back for official servers).
    let gateway = game.join(GATEWAY_FILE);
    backup_once(&gateway)?;
    match (opts.mode, &opts.gateway) {
        (Mode::Official, _) => {
            let orig = backup_path(&gateway);
            if orig.exists() {
                install::copy(&orig, &gateway)?;
            }
        }
        (Mode::Private, Some(entry)) => {
            let line = entry.line();
            std::fs::write(&gateway, gateway::utf16le_with_bom(&line))?;
            report.gateway = Some(line);
        }
        (Mode::Private, None) => {}
    }

    install_file(
        &opts.dll_dir.join(LOADER_BUILD_NAME),
        &game.join(LOADER_DLL),
    )?;
    install_file(&opts.dll_dir.join(CORE_DLL), &game.join(CORE_DLL))?;

    let cfg = game.join(HOOK_CONFIG);
    if !cfg.exists() {
        std::fs::write(&cfg, DEFAULT_HOOK_CONFIG)
            .with_context(|| format!("writing {}", cfg.display()))?;
    }
    set_hook_key(&cfg, None, "mode", &format!("\"{}\"", opts.mode.as_str()))?;
    // Official mode: no patch, nothing trusted beyond loopback (the DLL enforces this too).
    let (login_mode, trusted) = match opts.mode {
        Mode::Official => (LoginMode::Steam, Vec::new()),
        Mode::Private => {
            let (list, warnings) = resolve_trusted_servers(&opts.trusted_servers);
            report.warnings = warnings;
            (opts.login_mode, list)
        }
    };
    set_hook_key(
        &cfg,
        None,
        "login_mode",
        &format!("\"{}\"", login_mode.as_str()),
    )?;
    set_hook_key(
        &cfg,
        None,
        "trusted_servers",
        &trusted::toml_array(&trusted),
    )?;
    report.login_mode = Some(login_mode);
    report.trusted_servers = trusted;
    if let Some(port) = opts.position_sync_port {
        set_hook_key(
            &cfg,
            Some("features"),
            "position_sync_port",
            &port.to_string(),
        )?;
    }
    if let Some(dir) = &opts.dump_dir {
        std::fs::create_dir_all(dir)?;
        let path = hook_path(dir)?;
        set_hook_key(&cfg, None, "dump_dir", &format!("'{path}'"))?;
        report.dump_dir = Some(path);
    }
    // Test input comes from POE_HOOK_AUTO_KEYS, never from the user's config (an Enter at 20 s
    // opened the chat box in normal play).
    set_hook_key(&cfg, Some("features"), "auto_keys", "[]")?;
    std::fs::write(game.join(STEAM_APPID_FILE), STEAM_APPID)?;
    Ok(report)
}

/// Installs only the debug core; a running client reloads it by itself. Returns the target.
pub fn deploy_core(game_dir: &Path, dll_dir: &Path) -> Result<PathBuf> {
    let target = game_dir.join(CORE_DLL);
    install_file(&dll_dir.join(CORE_DLL), &target)?;
    Ok(target)
}

/// Undoes [`deploy`]: restores the original gateway list and removes the installed files.
/// Returns what was restored or removed.
pub fn revert(game_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let gateway = game_dir.join(GATEWAY_FILE);
    let orig = backup_path(&gateway);
    if orig.exists() {
        std::fs::rename(&orig, &gateway)?;
        touched.push(gateway);
    }
    for name in [LOADER_DLL, CORE_DLL, HOOK_CONFIG, STEAM_APPID_FILE] {
        let p = game_dir.join(name);
        if p.exists() {
            std::fs::remove_file(&p)?;
            touched.push(p);
        }
    }
    Ok(touched)
}
