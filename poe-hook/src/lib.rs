//! poe-hook: the PoE2 client's companion DLL, loaded as `version.dll` (see [`proxy`]).
//!
//! This loader stays small and is never unloaded. In `DllMain` it reads `poe-hook.toml`, opens
//! the logs (next to the exe and in this process's session folder `logs/poe-hook/<time>_<pid>/`),
//! installs the network guard (the client's crash-report helper connects out within
//! milliseconds of starting) and applies the standalone-login patch ([`login_patch`]). A thread then hooks Vulkan for the overlay and loads the debug
//! core (`poe_hook_core.dll`), which holds the features and the overlay and can be hot-reloaded
//! ([`core`]). Once the core runs, the enabled mods are loaded ([`mods`]); never in official mode.

mod core;
mod guard;
mod login_patch;
mod logsink;
mod mods;
mod proxy;
mod vulkan;
mod window;

use std::ffi::c_void;

use poe_hook_shared::{config::Config, module::Module};
use windows_sys::Win32::{Foundation::HINSTANCE, System::SystemServices::DLL_PROCESS_ATTACH};

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_module: HINSTANCE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // Under the loader lock: only file I/O and code patching of already-mapped modules
        // (ws2_32 is a static import of the game). Everything else runs on a thread.
        let dir = poe_hook_shared::exe_dir();
        let config = Config::load(&dir.join("poe-hook.toml"));
        let session = dir.join("logs").join("poe-hook").join(format!(
            "{}_{}",
            poe_hook_shared::local_timestamp(),
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&session);
        logsink::init(
            &[&dir.join("poe-hook.log"), &session.join("poe-hook.log")],
            config.log.level,
        );
        log::info!(
            "poe-hook {} loaded, mode {:?}, login_mode {:?}, session {}",
            env!("CARGO_PKG_VERSION"),
            config.mode,
            config.login_mode,
            session.display()
        );
        let main = Module::main();
        log::info!("main module: base={:#x} size={:#x}", main.base, main.size);
        // Config::load already emptied the list in official mode.
        for e in poe_hook_shared::trust::set_trusted_servers(&config.trusted_servers) {
            log::error!("trusted_servers: ignored entry {e}");
        }
        log::info!(
            "trusted servers: loopback{}",
            poe_hook_shared::trust::trusted_servers()
                .iter()
                .map(|t| match t.port {
                    Some(p) => format!(", {}:{p}", t.ip),
                    None => format!(", {}:*", t.ip),
                })
                .collect::<String>()
        );
        match guard::init(&main, config.official(), config.features.block_external) {
            Ok(()) => log::info!("network guard: enabled"),
            Err(e) => log::error!("network guard: failed: {e}"),
        }
        // Before the client's first platform query (its entry point runs after every static
        // import, this DLL included, has been initialised).
        login_patch::apply(&main, config.login_mode);
        let exe_dir = dir.clone();
        std::thread::spawn(move || {
            logsink::flusher();
            if config.overlay.enabled {
                match vulkan::init() {
                    Ok(()) => log::info!("vulkan hooks: enabled"),
                    Err(e) => log::warn!("vulkan hooks: {e}"),
                }
            }
            // The mods' signature table must be resolved before the core hooks anything.
            mods::prepare(&exe_dir, &config);
            core::start(dir, session, config.reload.auto);
            // Mods last: they get a running loader, core and log. None in official mode.
            mods::start(&exe_dir, &config);
        });
    }
    1
}
