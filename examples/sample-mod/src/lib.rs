//! The smallest useful mod: on load it logs a hello line with the game build, whether the
//! build is the one the signature table was made for, and the address of one signature.
//! Everything goes through the mod ABI (`poe-hook-mod-api`); the loader tags the lines
//! `mod:sample-mod` in `poe-hook.log`.

use poe_hook_mod_api::{HOOK_API_VERSION, HookApi};

/// Optional export: the loader refuses the DLL if this disagrees with its own ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn poe_mod_abi_version() -> u32 {
    HOOK_API_VERSION
}

/// Required entry point. Returns 0 when the mod started; anything else makes the loader log
/// the failure, unload the DLL and go on with the next mod.
///
/// # Safety
/// `api` is the loader's `HookApi` (valid for the whole process) or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poe_mod_init(api: *const HookApi) -> i32 {
    let Some(api) = (unsafe { api.as_ref() }) else {
        return 1;
    };
    if api.abi_version != HOOK_API_VERSION {
        return 2;
    }
    api.info(&format!(
        "hello from {} {}: game build {} (revision {}, table {}), read_only={}",
        api.id(),
        env!("CARGO_PKG_VERSION"),
        api.game_version(),
        api.build_revision(),
        if api.build_verified() {
            "verified"
        } else {
            "NOT verified"
        },
        api.read_only()
    ));
    // The resolved signature table is available to every mod.
    match api.sig_addr("read_message") {
        Some(a) => api.info(&format!("signature read_message resolved at {a:#x}")),
        None => api.info("signature read_message is not resolved"),
    }
    api.info(&format!(
        "feature packets ok: {}, mod folder {}",
        api.feature_ok("packets"),
        api.mod_dir()
    ));
    0
}
