//! The **mod ABI**: what a mod DLL (`[entry] dll` of a `mod.toml`) exports and what the
//! `poe-hook` loader hands it. Spec: `docs/mod-manifest.md`.
//!
//! A mod exports
//!
//! ```text
//! extern "C" fn poe_mod_init(api: *const HookApi) -> i32      // required; 0 = ok
//! extern "C" fn poe_mod_abi_version() -> u32                   // optional; HOOK_API_VERSION
//! ```
//!
//! and declares the same number as `game.hook_api` in its manifest. The loader refuses a mod
//! whose manifest or export names another version, before it runs any of the mod's code (the
//! manifest) or right after mapping it (the export).
//!
//! Only `#[repr(C)]` data and `extern "C"` functions cross the boundary: the loader and every
//! mod have their own Rust runtime and allocator. Strings are borrowed UTF-8 ([`Str`]) and
//! valid for the call only, except the ones inside [`HookApi`] itself, which live for the
//! process.
//!
//! **Versioning.** [`HOOK_API_VERSION`] is bumped whenever a field or function below changes
//! meaning, moves or is removed. Appending fields at the end does not need a bump: a mod reads
//! `HookApi::size` before it touches a field that was added later. The layout test in this file
//! fails when the struct changes, so the bump is not forgotten.

use std::ffi::c_void;

/// The mod ABI version (the "hook API major" of `game.hook_api` in `mod.toml`).
pub const HOOK_API_VERSION: u32 = 1;
/// Name of the required entry point ([`ModInit`]).
pub const MOD_INIT: &[u8] = b"poe_mod_init\0";
/// Name of the optional export that repeats the ABI version ([`ModAbiVersion`]).
pub const MOD_ABI_VERSION: &[u8] = b"poe_mod_abi_version\0";

pub type ModInit = unsafe extern "C" fn(api: *const HookApi) -> i32;
pub type ModAbiVersion = unsafe extern "C" fn() -> u32;

/// `log::Level as u32`.
pub const LOG_ERROR: u32 = 1;
pub const LOG_WARN: u32 = 2;
pub const LOG_INFO: u32 = 3;
pub const LOG_DEBUG: u32 = 4;
pub const LOG_TRACE: u32 = 5;

/// Borrowed UTF-8 string.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Str {
    pub ptr: *const u8,
    pub len: usize,
}

// Only ever points at data that outlives its use (leaked strings, or a callback's arguments).
unsafe impl Send for Str {}
unsafe impl Sync for Str {}

impl Str {
    pub fn new(s: &str) -> Self {
        Self {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }

    /// # Safety
    /// The pointer must be valid for `len` bytes of UTF-8 for `'a`.
    pub unsafe fn as_str<'a>(&self) -> &'a str {
        if self.len == 0 {
            return "";
        }
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(self.ptr, self.len)) }
    }
}

/// What the loader hands `poe_mod_init`: one instance per mod, valid for the whole process.
#[repr(C)]
pub struct HookApi {
    /// [`HOOK_API_VERSION`] of the loader.
    pub abi_version: u32,
    /// `size_of::<HookApi>()` of the loader: fields past this size do not exist.
    pub size: u32,
    /// Pass as the first argument of [`HookApi::log`].
    pub ctx: *const c_void,
    /// The mod's id (its folder name under `poe-hook-mods/`).
    pub mod_id: Str,
    /// The mod's folder (`<game dir>/poe-hook-mods/<id>`), for its data files.
    pub mod_dir: Str,
    /// The game directory (next to `PathOfExileSteam.exe`).
    pub exe_dir: Str,
    /// Client version of the signature table that matched, e.g. `0.5.5e` (empty: the table
    /// could not be used).
    pub game_version: Str,
    /// `Build Revision:` of that client, e.g. `323943`.
    pub build_revision: Str,
    /// 1 when the executable is exactly the build the table was made for (timestamp, size and
    /// revision agree); 0 on an unknown build, where `sig_addr` results are candidates only.
    pub build_verified: u32,
    pub reserved: u32,
    /// Writes a record to `poe-hook.log` (and the overlay's Log tab) tagged `mod:<id>`.
    pub log: extern "C" fn(ctx: *const c_void, level: u32, message: Str),
    /// The loader's read-only latch: true in official mode (no mod loads then) or once the
    /// client connected to an untrusted server. A mod that sends, alters or injects anything
    /// must stop doing so while this is true.
    pub read_only: extern "C" fn() -> bool,
    /// Runtime address of a signature of the table (`signatures/<version>.toml`), or 0 when it
    /// did not resolve (zero or several matches, wrong bytes) or the name is unknown.
    pub sig_addr: extern "C" fn(name: Str) -> usize,
    /// Whether every signature and field the table's feature needs resolved.
    pub feature_ok: extern "C" fn(feature: Str) -> bool,
    /// A resolved struct offset of the table; false when unknown or unresolved.
    pub field: extern "C" fn(name: Str, out: *mut usize) -> bool,
}

unsafe impl Send for HookApi {}
unsafe impl Sync for HookApi {}

impl HookApi {
    pub fn log(&self, level: u32, message: &str) {
        (self.log)(self.ctx, level, Str::new(message));
    }

    pub fn info(&self, message: &str) {
        self.log(LOG_INFO, message);
    }

    pub fn id(&self) -> &str {
        unsafe { self.mod_id.as_str() }
    }

    pub fn mod_dir(&self) -> &str {
        unsafe { self.mod_dir.as_str() }
    }

    pub fn exe_dir(&self) -> &str {
        unsafe { self.exe_dir.as_str() }
    }

    pub fn game_version(&self) -> &str {
        unsafe { self.game_version.as_str() }
    }

    pub fn build_revision(&self) -> &str {
        unsafe { self.build_revision.as_str() }
    }

    pub fn build_verified(&self) -> bool {
        self.build_verified != 0
    }

    pub fn read_only(&self) -> bool {
        (self.read_only)()
    }

    /// Runtime address of a resolved signature.
    pub fn sig_addr(&self, name: &str) -> Option<usize> {
        match (self.sig_addr)(Str::new(name)) {
            0 => None,
            a => Some(a),
        }
    }

    pub fn feature_ok(&self, feature: &str) -> bool {
        (self.feature_ok)(Str::new(feature))
    }

    pub fn field(&self, name: &str) -> Option<usize> {
        let mut out = 0usize;
        (self.field)(Str::new(name), &mut out).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout is the ABI: when this fails, bump [`HOOK_API_VERSION`] (and the manifest spec,
    /// the sample mod and the launcher's `HOOK_API`) unless the change only appends fields.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn hook_api_layout_is_pinned() {
        assert_eq!(HOOK_API_VERSION, 1);
        assert_eq!(std::mem::size_of::<Str>(), 16);
        assert_eq!(std::mem::size_of::<HookApi>(), 144);
        assert_eq!(std::mem::offset_of!(HookApi, ctx), 8);
        assert_eq!(std::mem::offset_of!(HookApi, mod_id), 16);
        assert_eq!(std::mem::offset_of!(HookApi, build_verified), 96);
        assert_eq!(std::mem::offset_of!(HookApi, log), 104);
        assert_eq!(std::mem::offset_of!(HookApi, field), 136);
    }

    #[test]
    fn export_names_are_nul_terminated() {
        assert_eq!(MOD_INIT, b"poe_mod_init\0");
        assert!(MOD_ABI_VERSION.ends_with(&[0]));
    }

    #[test]
    fn str_round_trips_and_empty_is_safe() {
        let s = Str::new("0.5.5e");
        assert_eq!(unsafe { s.as_str() }, "0.5.5e");
        let e = Str {
            ptr: std::ptr::null(),
            len: 0,
        };
        assert_eq!(unsafe { e.as_str() }, "");
    }
}
