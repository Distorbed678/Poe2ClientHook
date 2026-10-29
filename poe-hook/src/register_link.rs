//! The login screen's "Create account" button opens the private server's register page
//! instead of the official site: `ShellExecuteW` (shell32) is hooked and an account-page URL
//! is swapped for `register_url` (decision: `poe_hook_shared::register_link`). Nothing changes
//! while the read-only latch is on, and without a `register_url` the hook is not installed.

use std::{ffi::c_void, sync::OnceLock};

use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};

static REGISTER_URL: OnceLock<String> = OnceLock::new();

/// `ShellExecuteW(hwnd, operation, file, parameters, directory, show) -> HINSTANCE`.
type ShellExecuteWFn = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    i32,
) -> *mut c_void;

pub fn init(register_url: Option<String>) {
    let Some(url) = register_url.filter(|u| !u.trim().is_empty()) else {
        return;
    };
    REGISTER_URL.set(url.trim().to_owned()).ok();
    let shell32 = unsafe {
        let name: Vec<u16> = "shell32.dll\0".encode_utf16().collect();
        let mut h = GetModuleHandleW(name.as_ptr());
        if h.is_null() {
            h = LoadLibraryW(name.as_ptr());
        }
        h
    };
    if shell32.is_null() {
        log::warn!("create-account link: shell32.dll not loaded, not hooked");
        return;
    }
    let Some(addr) = (unsafe { GetProcAddress(shell32, c"ShellExecuteW".as_ptr().cast()) }) else {
        log::warn!("create-account link: ShellExecuteW not exported, not hooked");
        return;
    };
    let hooker = Hooker::new(
        addr as usize,
        HookType::Retn(on_shell_execute),
        CallbackOption::None,
        0,
        HookFlags::empty(),
    );
    match unsafe { hooker.hook() } {
        Ok(point) => {
            Box::leak(Box::new(point));
            log::info!("create-account link: opens {}", REGISTER_URL.get().map_or("", String::as_str));
        }
        Err(e) => log::warn!("create-account link: hook failed: {e:?}"),
    }
}

/// A NUL-terminated wide string, read up to 4096 units.
unsafe fn wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut n = 0;
    while n < 4096 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) }))
}

unsafe extern "win64" fn on_shell_execute(regs: *mut Registers, original: usize, _: usize) -> usize {
    let r = unsafe { &*regs };
    let (hwnd, op, file, params) = (r.rcx as *mut c_void, r.rdx as *const u16, r.r8 as *const u16, r.r9 as *const u16);
    let (dir, show) = unsafe { (r.get_stack(5) as *const u16, r.get_stack(6) as i32) };
    let f: ShellExecuteWFn = unsafe { std::mem::transmute(original) };
    let target = unsafe { wide(file) }.unwrap_or_default();
    if let Some(url) = poe_hook_shared::register_link::redirect(
        &target,
        REGISTER_URL.get().map(String::as_str),
        crate::guard::read_only(),
    ) {
        log::info!("create-account link: {target} -> {url}");
        let w: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        return unsafe { f(hwnd, op, w.as_ptr(), params, dir, show) } as usize;
    }
    unsafe { f(hwnd, op, file, params, dir, show) as usize }
}
