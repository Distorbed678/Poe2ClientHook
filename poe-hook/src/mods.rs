//! The mod loader: maps the enabled mods' entry DLLs (`poe-hook-mods/<id>/<entry.dll>`, listed
//! in `poe-hook-mods/state.toml`) and calls their `poe_mod_init(&HookApi)`. The decisions (which
//! mods, what order, ABI check, official-mode refusal) are in the host-testable `poe-hook-mods`
//! crate; this file only does the Windows part. Spec: `docs/mod-manifest.md`.
//!
//! Guarantees:
//! - **Official mode (or an already-set read-only latch): nothing is loaded, nothing is read** from the mod
//!   directory. Mods are code running inside the client; the official client only gets the
//!   observing DLL.
//! - A mod that is invalid, has the wrong ABI, misses a dependency or its DLL, fails to map,
//!   lacks `poe_mod_init` or returns non-zero is logged and skipped; the next mod loads. The ABI
//!   version in the manifest is checked before the DLL is mapped, the optional
//!   `poe_mod_abi_version` export right after.
//! - Loaded mods stay loaded for the process (the loader is never unloaded); `poe_mod_shutdown`
//!   is not called in ABI 1.

use std::{ffi::c_void, path::Path, sync::OnceLock, time::Instant};

use poe_hook_mod_api::{
    HOOK_API_VERSION, HookApi, MOD_ABI_VERSION, MOD_INIT, ModAbiVersion, ModInit, Str,
};
use poe_hook_mods::{LoadSet, MODS_DIR, PlannedMod, STATE_FILE, plan, refusal};
use poe_hook_shared::{config::Config, module::Module, sigs::Loaded};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, GetLastError},
    System::LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
};

/// The signature table resolved for the mods (everything the loader does not patch itself).
/// `None` until [`prepare`] resolved it, or when the table is unusable.
static SIGS: OnceLock<Option<Loaded>> = OnceLock::new();
/// `(game version, build revision, verified)` of the table, as `'static` strings for the API.
static BUILD: OnceLock<(&'static str, &'static str, bool)> = OnceLock::new();

/// Per-mod context behind `HookApi::ctx`.
struct ModCtx {
    target: String,
}

/// Whether mods may load at all, and whether any are set up (`state.toml` exists). Official
/// mode or a set latch: no, without a look at the mod directory.
fn enabled(exe_dir: &Path, config: &Config, say: bool) -> Option<std::path::PathBuf> {
    let latch = crate::guard::read_only();
    if let Some(why) = refusal(config.official(), latch) {
        if say {
            log::info!("mods: {why}");
        }
        return None;
    }
    let dir = exe_dir.join(MODS_DIR);
    if !dir.join(STATE_FILE).is_file() {
        log::debug!("mods: no {MODS_DIR}/{STATE_FILE}, no mod is enabled");
        return None;
    }
    Some(dir)
}

/// Resolves the signature table for the mods, **before the debug core starts**: the core
/// hooks function starts, and a table resolved afterwards would no longer find them. Only when
/// mods are set up (resolving scans the 78 MB image, ~0.3 s). Runs on the loader's thread.
pub fn prepare(exe_dir: &Path, config: &Config) {
    if enabled(exe_dir, config, false).is_some() {
        resolve_sigs(&Module::main());
    }
}

/// Loads the enabled mods. Runs once, on the loader's thread, after the core started.
pub fn start(exe_dir: &Path, config: &Config) {
    let Some(dir) = enabled(exe_dir, config, true) else {
        return;
    };
    let latch = crate::guard::read_only();
    let build = BUILD.get().copied();
    let plan = plan(
        &dir,
        config.official(),
        latch,
        build.filter(|b| b.2).map(|b| b.0),
    );
    if let Some(why) = &plan.refused {
        log::info!("mods: {why}");
        return;
    }
    for n in &plan.notes {
        log::error!("mods: {n}");
    }
    for s in &plan.skipped {
        log::error!("mods: skipped {}: {}", s.id, s.reason);
    }
    let mut set = LoadSet::default();
    let mut loaded = 0;
    for m in &plan.mods {
        for w in &m.warnings {
            log::warn!("mods: {}: {w}", m.id);
        }
        if let Err(why) = set.check(&m.manifest) {
            log::error!("mods: skipped {}: {why}", m.id);
            continue;
        }
        let started = Instant::now();
        let result = match &m.dll {
            Some(dll) => load_dll(m, dll, exe_dir),
            None => {
                log::warn!(
                    "mods: {} has no entry DLL; its [data] files are not applied by this loader yet",
                    m.id
                );
                Ok(())
            }
        };
        match result {
            Ok(()) => {
                set.add(&m.manifest);
                loaded += 1;
                log::info!(
                    "mods: loaded {} {} ({} ms)",
                    m.id,
                    m.manifest.version,
                    started.elapsed().as_millis()
                );
            }
            Err(why) => log::error!("mods: skipped {}: {why}", m.id),
        }
    }
    log::info!(
        "mods: {loaded} of {} enabled loaded, {} skipped",
        plan.mods.len() + plan.skipped.len(),
        plan.mods.len() - loaded + plan.skipped.len()
    );
}

/// Resolves the table for the mods and logs how long it took.
fn resolve_sigs(main: &Module) {
    let started = Instant::now();
    let loaded = Loaded::core_features().ok().and_then(|features| {
        let list: Vec<&str> = features.iter().map(String::as_str).collect();
        match Loaded::resolve(main, Some(&list)) {
            Ok(l) => Some(l),
            Err(e) => {
                log::warn!("mods: signature table unusable, sig_addr answers 0: {e}");
                None
            }
        }
    });
    if let Some(l) = &loaded {
        let leak = |s: &str| -> &'static str { Box::leak(s.to_owned().into_boxed_str()) };
        let b = &l.table().build;
        BUILD
            .set((leak(&b.version), leak(&b.build_revision), l.verified()))
            .ok();
        log::info!(
            "mods: signature table {} resolved in {} ms ({})",
            b.version,
            started.elapsed().as_millis(),
            if l.verified() {
                "verified build"
            } else {
                "build NOT verified"
            }
        );
    }
    SIGS.set(loaded).ok();
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain([0])
        .collect()
}

/// Maps one mod DLL and runs its `poe_mod_init`. On any error the DLL is unmapped again.
fn load_dll(m: &PlannedMod, dll: &Path, exe_dir: &Path) -> Result<(), String> {
    // The altered search path lets the mod find its own DLLs next to it.
    let module = unsafe {
        LoadLibraryExW(
            wide(dll).as_ptr(),
            std::ptr::null_mut(),
            LOAD_WITH_ALTERED_SEARCH_PATH,
        )
    };
    if module.is_null() {
        return Err(format!(
            "LoadLibrary {} failed (error {})",
            dll.display(),
            unsafe { GetLastError() }
        ));
    }
    let fail = |why: String| {
        unsafe { FreeLibrary(module) };
        Err(why)
    };
    if let Some(f) = unsafe { GetProcAddress(module, MOD_ABI_VERSION.as_ptr()) } {
        let f: ModAbiVersion = unsafe { std::mem::transmute(f) };
        let v = unsafe { f() };
        if v != HOOK_API_VERSION {
            return fail(format!(
                "the DLL reports mod ABI {v}, this loader offers {HOOK_API_VERSION}"
            ));
        }
    }
    let Some(init) = (unsafe { GetProcAddress(module, MOD_INIT.as_ptr()) }) else {
        return fail("the DLL exports no poe_mod_init".into());
    };
    let init: ModInit = unsafe { std::mem::transmute(init) };
    let api = make_api(m, exe_dir);
    let rc = unsafe { init(api) };
    if rc != 0 {
        return fail(format!("poe_mod_init returned {rc}"));
    }
    Ok(())
}

/// The `HookApi` for one mod; leaked, the mod may keep the pointer for the process's life.
fn make_api(m: &PlannedMod, exe_dir: &Path) -> &'static HookApi {
    let leak = |s: String| -> Str { Str::new(Box::leak(s.into_boxed_str())) };
    let ctx: &'static ModCtx = Box::leak(Box::new(ModCtx {
        target: format!("mod:{}", m.id),
    }));
    let (version, revision, verified) = BUILD.get().copied().unwrap_or(("", "", false));
    Box::leak(Box::new(HookApi {
        abi_version: HOOK_API_VERSION,
        size: size_of::<HookApi>() as u32,
        ctx: (ctx as *const ModCtx).cast::<c_void>(),
        mod_id: leak(m.id.clone()),
        mod_dir: leak(m.dir.display().to_string()),
        exe_dir: leak(exe_dir.display().to_string()),
        game_version: Str::new(version),
        build_revision: Str::new(revision),
        build_verified: u32::from(verified),
        reserved: 0,
        log: api_log,
        read_only: api_read_only,
        sig_addr: api_sig_addr,
        feature_ok: api_feature_ok,
        field: api_field,
    }))
}

/// A mod's string, copied (a mod may pass anything): invalid UTF-8 is replaced, null is empty.
fn text(s: Str) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

extern "C" fn api_log(ctx: *const c_void, level: u32, message: Str) {
    let ctx = unsafe { (ctx as *const ModCtx).as_ref() };
    let target = ctx.map_or("mod", |c| c.target.as_str());
    crate::logsink::write(level.clamp(1, 5), target, &text(message));
}

extern "C" fn api_read_only() -> bool {
    crate::guard::read_only()
}

fn sigs() -> Option<&'static Loaded> {
    SIGS.get().and_then(Option::as_ref)
}

extern "C" fn api_sig_addr(name: Str) -> usize {
    sigs().and_then(|l| l.addr(&text(name)).ok()).unwrap_or(0)
}

extern "C" fn api_feature_ok(feature: Str) -> bool {
    sigs().is_some_and(|l| l.feature_ok(&text(feature)))
}

extern "C" fn api_field(name: Str, out: *mut usize) -> bool {
    match sigs().and_then(|l| l.field(&text(name))) {
        Some(v) if !out.is_null() => {
            unsafe { *out = v };
            true
        }
        _ => false,
    }
}
