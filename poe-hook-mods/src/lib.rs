//! The logic of the mod loader that does not need Windows: parsing `mod.toml`, reading
//! `state.toml`, deciding which enabled mods may load and in what order, and the ABI and
//! official-mode checks. The `poe-hook` loader (`version.dll`) feeds the result to
//! `LoadLibrary`; `poe-hook-deploy` uses the same parser to install a mod. Spec:
//! `docs/mod-manifest.md`.
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
mod plan;
mod state;

pub use manifest::{Manifest, Parsed, parse_manifest, valid_id};
pub use plan::{LoadSet, Plan, PlannedMod, Skipped, check_abi, plan, refusal};
pub use state::{State, parse_state, state_text};

/// Directory (next to the client executable) that holds the mods.
pub const MODS_DIR: &str = "poe-hook-mods";
/// The enabled mods in load order, inside [`MODS_DIR`].
pub const STATE_FILE: &str = "state.toml";
/// A mod's manifest, at the root of its folder.
pub const MANIFEST_FILE: &str = "mod.toml";
/// The `manifest_version` this loader reads.
pub const MANIFEST_VERSION: u32 = 1;
/// The mod ABI version this loader offers (see `poe-hook-mod-api`).
pub const HOOK_API: u32 = poe_hook_mod_api::HOOK_API_VERSION;
