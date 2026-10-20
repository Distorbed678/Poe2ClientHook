//! Standalone login: patches the client's `ClientPlatform_Detect` to return platform 0, so it
//! shows `LoginScreen.ui` (account name + password) and sends the `0x0003` credentials
//! instead of the Steam login. Background, addresses and evidence:
//! docs/re/standalone-login.md; the addresses and the byte logic live in
//! `poe_hook_shared::login`.
//!
//! Safety:
//! - only with `login_mode = "standalone"`, which `Config` forces to `steam` in official mode,
//!   so official sessions get no patch at all (and `apply` refuses again if the read-only
//!   latch is already on);
//! - the three original bytes are verified first; any other content (another client build)
//!   skips the patch with an error;
//! - the page is made writable only for the 3-byte write and restored, and the instruction
//!   cache is flushed;
//! - the standalone patcher (see below) is skipped by the launcher's `--success-event`
//!   option (`poe_hook_deploy::launch`); only when the client's own check would still run it
//!   (option missing, or `--disable-client-switching`) the entry of the patcher function is
//!   replaced by `mov al,1; ret`, so GGG's patch servers are never contacted;
//! - the platform is cached lazily (thread-safe static). If something already cached the
//!   Steam value (guard set), the cached value is overwritten with 0 as well.

use poe_hook_shared::{
    config::LoginMode,
    login::{self, PatchOutcome},
    mem,
    module::Module,
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    Environment::GetCommandLineW,
    Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
    Threading::GetCurrentProcess,
};

/// Applies the patch for `mode`; logs the result. Never panics, never aborts the load.
pub fn apply(main: &Module, mode: LoginMode) {
    match mode {
        LoginMode::Steam => {
            log::info!("login_mode steam: client left unpatched (Steam login screen)");
            return;
        }
        LoginMode::Standalone if crate::guard::read_only() => {
            // Official mode forces `steam` already; this guards the invariant.
            log::warn!("login_mode standalone ignored: read-only latch is on, no patch");
            return;
        }
        LoginMode::Standalone => {}
    }
    match patch(main) {
        Ok(msg) => log::info!("login_mode standalone: {msg}"),
        Err(e) => {
            // Without the platform patch the client is not standalone: no patcher either.
            log::error!("login_mode standalone: NOT applied, Steam login stays: {e}");
            return;
        }
    }
    skip_patcher(main);
}

/// With platform 0 the client first runs the standalone patcher (window, GGG patch servers).
/// The launcher passes `--success-event 0`, which the client treats as "the patcher already
/// ran". If the command line does not (or `--disable-client-switching` undoes it), patch the
/// patcher's entry so it returns "go on" at once.
fn skip_patcher(main: &Module) {
    let cmdline = command_line();
    if !login::patcher_would_run(&cmdline) {
        log::info!(
            "standalone patcher skipped by the client itself ({} on the command line)",
            login::SUCCESS_EVENT_OPTION
        );
        return;
    }
    match patch_patcher(main) {
        Ok(msg) => log::warn!(
            "standalone patcher skip: {msg} (command line has no {})",
            login::SUCCESS_EVENT_OPTION
        ),
        Err(e) => {
            log::error!("standalone patcher NOT skipped, it would contact GGG patch servers: {e}")
        }
    }
}

fn patch_patcher(main: &Module) -> Result<String, String> {
    let func = main.from_ghidra(login::STANDALONE_PATCHER_RUN);
    let mut code: [u8; 3] = mem::read(func).ok_or_else(|| format!("{func:#x} is not readable"))?;
    let before = code;
    match login::patch_patcher_run(&mut code) {
        PatchOutcome::Mismatch(found) => Err(format!(
            "StandalonePatcher_Run (ghidra {:#x}) starts with {found:02x?}, expected {:02x?}",
            login::STANDALONE_PATCHER_RUN,
            login::PATCHER_RUN_ORIGINAL
        )),
        PatchOutcome::AlreadyPatched => Ok("already patched".into()),
        PatchOutcome::Patched => {
            unsafe { write_code(func, &code)? };
            Ok(format!(
                "StandalonePatcher_Run (ghidra {:#x}) {before:02x?} -> {code:02x?}",
                login::STANDALONE_PATCHER_RUN
            ))
        }
    }
}

/// The process command line (UTF-16 lossy to UTF-8).
fn command_line() -> String {
    unsafe {
        let p = GetCommandLineW();
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn patch(main: &Module) -> Result<String, String> {
    let func = main.from_ghidra(login::CLIENT_PLATFORM_DETECT);
    let mut code: [u8; 3] = mem::read(func).ok_or_else(|| format!("{func:#x} is not readable"))?;
    let before = code;
    match login::patch_prologue(&mut code) {
        PatchOutcome::Mismatch(found) => {
            return Err(format!(
                "ClientPlatform_Detect (ghidra {:#x}) starts with {found:02x?}, expected {:02x?}: \
                 wrong client build, patch skipped",
                login::CLIENT_PLATFORM_DETECT,
                login::PLATFORM_DETECT_ORIGINAL
            ));
        }
        PatchOutcome::AlreadyPatched => {}
        PatchOutcome::Patched => unsafe { write_code(func, &code)? },
    }
    let mut msg = format!(
        "ClientPlatform_Detect (ghidra {:#x}) {before:02x?} -> {code:02x?}",
        login::CLIENT_PLATFORM_DETECT
    );
    // Something may have cached the Steam value already.
    let guard = main.from_ghidra(login::CLIENT_PLATFORM_CACHE_GUARD);
    let value = main.from_ghidra(login::CLIENT_PLATFORM_CACHE_VALUE);
    if let Some(g) = mem::read::<i32>(guard) {
        if g != 0 {
            let old = mem::read::<i32>(value);
            if mem::readable(value, 4) {
                unsafe { (value as *mut i32).write_volatile(0) };
                msg += &format!("; cache was already set (guard {g}, value {old:?}), reset to 0");
            }
        }
    } else {
        log::warn!("platform cache guard at {guard:#x} not readable");
    }
    Ok(msg)
}

/// Writes `bytes` over code at `addr`: protection RWX, write, restore, flush.
unsafe fn write_code(addr: usize, bytes: &[u8]) -> Result<(), String> {
    unsafe {
        let mut old = 0;
        if VirtualProtect(
            addr as *const _,
            bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        ) == 0
        {
            return Err(format!("VirtualProtect({addr:#x}) failed"));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
        let mut ignored = 0;
        VirtualProtect(addr as *const _, bytes.len(), old, &mut ignored);
        FlushInstructionCache(GetCurrentProcess(), addr as *const _, bytes.len());
    }
    Ok(())
}
