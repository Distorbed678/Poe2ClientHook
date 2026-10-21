//! poe-hook-core: the debug core, loaded (and hot-reloaded) by the `version.dll` loader.
//!
//! It holds every client feature (crypto bypass, packet capture, research hooks, position
//! sync, test input) and the in-game debug overlay. Features that change the game or talk to
//! our server are not started while the loader's read-only latch is on (official servers),
//! and check it again where they act, since the latch can switch on later.
//!
//! Everything installed here is undone in `stop` ([`hooks::remove_all`]).

mod actions;
mod areas;
mod auto_keys;
mod crash;
mod crypto_bypass;
mod devlink;
mod dump_types;
mod entities;
mod exit_trace;
mod gamedata;
mod gamelog;
mod hidden;
mod hooks;
mod host;
mod inspect;
mod minimap;
mod net_trace;
mod notes;
mod overlay;
mod packets;
mod path_log;
mod position_sync;
mod protocol;
mod scanner;
mod side;
mod sigs;
mod snapshot;
mod symbols;
mod terrain_tools;
mod timing;
mod trace_calls;
mod ui;
mod util;
mod watches;

use std::sync::{OnceLock, atomic::Ordering};

use poe_hook_shared::{
    abi::{ABI_VERSION, CoreApi, HostApi},
    config::Config,
    module::Module,
};

static CONFIG: OnceLock<Config> = OnceLock::new();

pub fn config() -> &'static Config {
    CONFIG.get().expect("config loaded in poe_core_start")
}

/// Path of a generated output file: `<dump_dir>/<sub>/<name>` (the folder is created), or
/// `<exe dir>/<name>` when `dump_dir` is not configured (the old behaviour).
pub fn dump_path(sub: &str, name: &str) -> std::path::PathBuf {
    match &config().dump_dir {
        Some(root) => {
            let dir = root.join(sub);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                log::error!("dump dir {}: {e}", dir.display());
            }
            dir.join(name)
        }
        None => poe_hook_shared::exe_dir().join(name),
    }
}

/// Entry point called by the loader after loading this DLL.
///
/// # Safety
/// `host` must point to a valid [`HostApi`] that outlives the core.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poe_core_start(host: *const HostApi) -> *const CoreApi {
    let host = unsafe { *host };
    if host.abi_version != ABI_VERSION {
        return std::ptr::null();
    }
    host::set(host);
    // Release builds abort on panic: log it first (otherwise the game just vanishes).
    std::panic::set_hook(Box::new(|info| {
        let bt = std::backtrace::Backtrace::force_capture();
        log::error!("PANIC: {info}\n{bt}");
    }));
    let loaded = Config::load(&poe_hook_shared::exe_dir().join("poe-hook.toml"));
    log::set_max_level(loaded.log.level);
    // The core has its own copy of the trust list (the loader's statics are not shared).
    for e in poe_hook_shared::trust::set_trusted_servers(&loaded.trusted_servers) {
        log::error!("trusted_servers: ignored entry {e}");
    }
    CONFIG.set(loaded).ok();
    log::info!(
        "debug core {} started (load #{}, read-only {})",
        env!("CARGO_PKG_VERSION"),
        host::reload_count(),
        host::read_only()
    );
    match &config().dump_dir {
        Some(dir) => log::info!("dump_dir {}", dir.display()),
        None => log::info!("dump_dir not set: outputs go next to the exe / in the session folder"),
    }
    // Build the symbol table off the game's threads (the first stack print would otherwise).
    hooks::spawn(|| {
        symbols::fmt(0);
    });
    start_features(config(), &Module::main());
    overlay::init();
    static API: CoreApi = CoreApi {
        abi_version: ABI_VERSION,
        on_present,
        on_swapchain_destroy,
        on_window_message,
        stop,
    };
    &API
}

fn report(name: &str, enabled: bool, init: impl FnOnce() -> Result<(), String>) {
    if !enabled {
        log::info!("feature {name}: off");
        return;
    }
    match init() {
        Ok(()) => log::info!("feature {name}: on"),
        Err(e) => log::error!("feature {name}: failed: {e}"),
    }
}

/// Like [`report`], for a feature whose hooks come from the signature table: it does not start
/// (and says why) when one of its signatures or fields did not resolve.
fn report_sig(
    name: &str,
    enabled: bool,
    sig_feature: &str,
    read_only: bool,
    init: impl FnOnce() -> Result<(), String>,
) {
    if enabled && let Err(e) = sigs::gate(sig_feature, read_only) {
        log::error!("feature {name}: OFF: {e}");
        return;
    }
    report(name, enabled, init);
}

/// `wanted` and the feature's signatures resolved (logged when wanted but not possible).
fn sig_enabled(name: &str, wanted: bool, read_only: bool) -> bool {
    if !wanted {
        return false;
    }
    match sigs::gate(name, read_only) {
        Ok(()) => true,
        Err(e) => {
            log::error!("feature {name}: OFF: {e}");
            false
        }
    }
}

fn start_features(config: &Config, main: &Module) {
    let f = &config.features;
    let read_only = host::read_only();
    // Every hook address, patch site and struct offset comes from the signature table.
    sigs::init(main);
    let first_load = host::reload_count() == 0;
    // POE_HOOK_TRACE (comma-separated Ghidra addresses) adds to `trace_addresses` (RE tests).
    let mut addresses = f.trace_addresses.clone();
    if let Ok(extra) = std::env::var("POE_HOOK_TRACE") {
        addresses.extend(
            extra
                .split(',')
                .map(|a| a.trim().to_owned())
                .filter(|a| !a.is_empty()),
        );
    }
    // Position sync reads the player's components from the entity tick hook of
    // `dump_object_types`, so it needs both.
    let ps_wanted = f.position_sync && !read_only;
    let ps_ok = sig_enabled("position_sync", ps_wanted, read_only)
        && sig_enabled("dump_object_types", f.dump_object_types, read_only);
    position_sync::ENABLED.store(ps_ok, Ordering::Relaxed);
    position_sync::PORT.store(f.position_sync_port, Ordering::Relaxed);
    dump_types::ENTITY_TRACE.store(
        sig_enabled("entity_trace", f.entity_trace, read_only),
        Ordering::Relaxed,
    );
    dump_types::MOVEMENT_LOG.store(
        f.movement_log || std::env::var_os("POE_HOOK_MOVEMENT_LOG").is_some(),
        Ordering::Relaxed,
    );
    report_sig(
        "path_log",
        f.path_log || std::env::var_os("POE_HOOK_PATH_LOG").is_some(),
        "path_log",
        read_only,
        || path_log::init(main),
    );
    report("crash_log", f.crash_log, || crash::init(main));
    report("exit_trace", f.crash_log, || exit_trace::init(main));
    // Official servers need the real handshake; the hook also passes through once the latch is
    // on.
    report_sig(
        "crypto_bypass",
        f.crypto_bypass && !read_only,
        "crypto_bypass",
        read_only,
        || crypto_bypass::init(main),
    );
    // The authenticated side channel (position reports, debug link, terrain upload) needs the
    // instance session keys; never captured on official servers.
    report_sig(
        "side_channel",
        !read_only,
        "side_channel",
        read_only,
        || side::init(main),
    );
    report("net_trace", f.net_trace, || {
        net_trace::init(
            main,
            net_trace::Options {
                trace: true,
                dump_bytes: f.net_trace_dump_bytes,
            },
        )
    });
    report_sig(
        "packets",
        config.packets.capture,
        "packets",
        read_only,
        || {
            packets::init(main)?;
            // The field tracer hooks the stream primitives: not on an official server with an
            // executable the table was not made for (only the observers there).
            if read_only && !sigs::verified() {
                log::warn!("packets: field tracer off (unverified build on an official server)");
                return Ok(());
            }
            protocol::init(main)
        },
    );
    let object_types = dump_path("client-tables", "object_types.txt");
    report_sig(
        "dump_object_types",
        f.dump_object_types,
        "dump_object_types",
        read_only,
        || dump_types::init(main, object_types),
    );
    let generator_trace = f.generator_trace || std::env::var_os("POE_HOOK_GEN_TRACE").is_some();
    let export = sig_enabled("area_export", f.area_export, read_only);
    let trace = sig_enabled("generator_trace", generator_trace, read_only);
    report("area_export", export || trace, || {
        terrain_tools::init(main, export, trace)
    });
    report("trace_calls", !addresses.is_empty(), || {
        trace_calls::init(main, &addresses, f.trace_limit.max(200))
    });
    // Test input is injection: never while read-only. The key timeline only runs once per
    // process (a reload must not press Enter again).
    report(
        "window_title",
        !read_only && std::env::var_os("POE_HOOK_WINDOW_TITLE").is_some(),
        auto_keys::init_window_title,
    );
    let keys = if first_load {
        f.auto_keys.clone()
    } else {
        Vec::new()
    };
    report("auto_keys", !read_only, || auto_keys::init(keys));
    // The server debug link (our server only).
    if !read_only {
        devlink::start();
    }
}

extern "C" fn on_present(queue: u64, info: *const std::ffi::c_void) -> u64 {
    timing::present();
    if !config().overlay.enabled {
        return 0;
    }
    overlay::present(queue, info)
}

extern "C" fn on_swapchain_destroy(swapchain: u64) {
    overlay::swapchain_destroy(swapchain);
}

extern "C" fn on_window_message(
    hwnd: isize,
    msg: u32,
    wparam: usize,
    lparam: isize,
    result: *mut isize,
) -> bool {
    match overlay::window_message(hwnd, msg, wparam, lparam) {
        Some(r) => {
            unsafe { result.write(r) };
            true
        }
        None => false,
    }
}

extern "C" fn stop() {
    log::info!("debug core stopping");
    overlay::stop();
    packets::stop();
    crash::stop();
    hooks::remove_all();
    position_sync::stop();
    log::info!("debug core stopped");
}
