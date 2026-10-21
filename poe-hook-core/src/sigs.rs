//! The signature table as the core uses it: every hook address, patch site and game struct
//! offset comes from here (`signatures/<version>.toml`, resolved once at load by
//! `poe_hook_shared::sigs`), none is written into the features.
//!
//! A feature calls [`gate`] before it installs anything: it is off when one of its signatures
//! or fields did not resolve (zero or several matches, wrong bytes), and, on an official
//! server with an executable the table was not made for, when it is not a pure observer.

use std::{ops::Range, sync::OnceLock};

use poe_hook_shared::{
    module::Module,
    offsets::Offsets,
    sigs::{Loaded, OBSERVE_ONLY},
};

static LOADED: OnceLock<Loaded> = OnceLock::new();
static OFFSETS: OnceLock<Offsets> = OnceLock::new();

/// Resolves the table (the core's features: everything the loader does not apply itself) and
/// logs the result. On failure every feature that needs a signature stays off.
pub fn init(main: &Module) {
    let started = std::time::Instant::now();
    let features = match Loaded::core_features() {
        Ok(f) => f,
        Err(e) => {
            log::error!("signature table unusable, features that need it are off: {e}");
            return;
        }
    };
    let list: Vec<&str> = features.iter().map(String::as_str).collect();
    match Loaded::resolve(main, Some(&list)) {
        Ok(loaded) => {
            log::info!(
                "signatures resolved in {} ms",
                started.elapsed().as_millis()
            );
            loaded.log_summary();
            OFFSETS
                .set(Offsets::from_resolution(loaded.resolution()))
                .ok();
            LOADED.set(loaded).ok();
        }
        Err(e) => log::error!("signature table unusable, features that need it are off: {e}"),
    }
}

/// Whether the loaded build is the one the table was made for.
pub fn verified() -> bool {
    LOADED.get().is_some_and(Loaded::verified)
}

/// Whether every signature and field `feature` needs resolved.
pub fn feature_ok(feature: &str) -> bool {
    LOADED.get().is_some_and(|l| l.feature_ok(feature))
}

/// `Ok` when `feature` may start: its entries resolved, and, with `read_only` (official
/// servers) on a build the table does not know, only pure observers. The error says why not.
pub fn gate(feature: &str, read_only: bool) -> Result<(), String> {
    let Some(l) = LOADED.get() else {
        return Err("signature table not loaded".into());
    };
    if !l.feature_ok(feature) {
        return Err(format!("signatures: {}", l.feature_problem(feature)));
    }
    if read_only && !l.verified() && !OBSERVE_ONLY.contains(&feature) {
        return Err(
            "unverified build on an official server: only observers start (see signatures log)"
                .into(),
        );
    }
    Ok(())
}

/// Runtime address of a signature.
pub fn addr(name: &str) -> Result<usize, String> {
    LOADED
        .get()
        .ok_or_else(|| "signature table not loaded".to_string())?
        .addr(name)
}

/// The `.pdata` range of the function a signature points at.
pub fn function_range(name: &str) -> Option<Range<usize>> {
    LOADED.get()?.function_range(name)
}

/// Ghidra address of a runtime address (logs).
pub fn ghidra(addr: usize) -> usize {
    LOADED.get().map_or(addr, |l| l.ghidra(addr))
}

/// The resolved struct offsets (all 0 when the table is not loaded: every feature that reads
/// them is off then).
pub fn off() -> &'static Offsets {
    static ZERO: OnceLock<Offsets> = OnceLock::new();
    OFFSETS
        .get()
        .unwrap_or_else(|| ZERO.get_or_init(Offsets::default))
}
