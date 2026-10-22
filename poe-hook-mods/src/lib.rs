//! The logic of the mod loader that does not need Windows: parsing `mod.toml`, reading
//! `state.toml`, deciding which enabled mods may load and in what order, and the ABI and
//! official-mode checks. The `poe-hook` loader (`version.dll`) feeds the result to
//! `LoadLibrary`; `poe-hook-deploy` uses the same parser to install a mod. Spec:
//! `docs/mod-manifest.md`.
//!
//! The manifest is shared by every program that handles mods: the client loader, the launcher,
//! the server and the SDK's packer. A mod has a [`Side`] (client, server or both); the client
//! loader ignores the server half and refuses a server-only mod. With the `package` feature
//! (on by default, off for the loader DLL) [`verify_package`] checks a distributable
//! `<id>-<version>.zip` and its `.sha256`.
//!
//! Layout next to `PathOfExileSteam.exe` (written by the launcher and `cargo xtask deploy-mod`,
//! read here):
//!
//! ```text
//! poe-hook-mods/
//!   state.toml        enabled = ["core-lib", "my-mod"]    # enabled mods, in load order
//!   my-mod/mod.toml   (+ the entry DLL and data files)
//! ```

mod manifest;
#[cfg(feature = "package")]
mod package;
mod plan;
mod state;

pub use manifest::{
    CommandRole, CommandSpec, Manifest, Parsed, Platform, Side, parse_manifest, parse_manifest_max,
    valid_command_name, valid_id,
};
#[cfg(feature = "package")]
pub use package::{
    Limits, PACKAGE_EXTENSION, PackageFile, PackageReport, package_file_name, parse_sha256_file,
    sha256_file_text, sha256_hex, verify_package, verify_package_bytes,
};
pub use plan::{LoadSet, Plan, PlannedMod, Skipped, check_abi, check_server_api, plan, refusal};
pub use state::{State, parse_state, state_text};

/// Directory (next to the client executable) that holds the mods.
pub const MODS_DIR: &str = "poe-hook-mods";
/// The enabled mods in load order, inside [`MODS_DIR`].
pub const STATE_FILE: &str = "state.toml";
/// A mod's manifest, at the root of its folder.
pub const MANIFEST_FILE: &str = "mod.toml";
/// The highest `manifest_version` this crate reads. 1 is the client-only format; 2 adds `side`,
/// `[client]`, `[server]` and `[[commands]]` (see `docs/mod-manifest.md`).
pub const MANIFEST_VERSION: u32 = 2;
/// The mod ABI version this loader offers (see `poe-hook-mod-api`).
pub const HOOK_API: u32 = poe_hook_mod_api::HOOK_API_VERSION;
