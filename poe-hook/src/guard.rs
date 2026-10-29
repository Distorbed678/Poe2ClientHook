//! Network guard (installed in `DllMain`, before the game runs: its crash-report helper
//! connects out within milliseconds): hooks every Winsock way to open a connection to
//!
//! - refuse *untrusted* connections in private mode with `block_external`, which keeps a
//!   client pointed at our server away from official services (shop, telemetry, crash upload).
//!   Trusted means loopback or an entry of `trusted_servers` (`poe_hook_shared::trust`);
//! - set the **read-only latch** the first time an untrusted ("external") connection goes
//!   through (official play), or from the start in official mode. Read-only means the core
//!   sends, alters and injects nothing; it only observes. Trusted connections never latch;
//! - record every connection (the core's packet capture and position sync use the table).
//!
//! Hooked: `connect`, `WSAConnect` (what the client uses: `connect`, docs/re/network-apis.md),
//! `WSAConnectByNameW/A`, `WSAConnectByList`, and `WSAIoctl`, whose
//! `SIO_GET_EXTENSION_FUNCTION_POINTER` answer for `ConnectEx` is wrapped by hooking the
//! returned function (if that hook cannot be installed the ioctl is failed instead, unless
//! the latch is already on). The decisions are in `poe_hook_shared::netguard` (unit-tested).

use std::{
    ffi::c_void,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers, RetnRoutine};
use poe_hook_shared::{
    abi::Connection,
    module::Module,
    netguard::{self, Verdict},
};
use windows_sys::Win32::{
    Networking::WinSock::{
        SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ADDRESS_LIST, SOCKET_ERROR, WSAECONNREFUSED,
        WSAEOPNOTSUPP, WSAGetLastError, WSASetLastError,
    },
    System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW},
};

static READ_ONLY: AtomicBool = AtomicBool::new(false);
static BLOCK_EXTERNAL: AtomicBool = AtomicBool::new(true);
static SEQ: AtomicU32 = AtomicU32::new(0);
static CONNECTIONS: Mutex<Vec<Connection>> = Mutex::new(Vec::new());
static MAIN: std::sync::OnceLock<Module> = std::sync::OnceLock::new();
/// Addresses of `ConnectEx` implementations already hooked (the pointer is per provider).
static CONNECT_EX_HOOKED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Hooks that must exist (their absence is an error), then the optional ones.
const REQUIRED: [(&[u8], RetnRoutine); 3] = [
    (b"connect\0", on_connect),
    (b"WSAConnect\0", on_connect),
    (b"WSAIoctl\0", on_wsa_ioctl),
];
const OPTIONAL: [(&[u8], RetnRoutine); 3] = [
    (b"WSAConnectByNameW\0", on_connect_by_name_w),
    (b"WSAConnectByNameA\0", on_connect_by_name_a),
    (b"WSAConnectByList\0", on_connect_by_list),
];

fn hook_at(addr: usize, routine: RetnRoutine, display: &str) -> Result<(), String> {
    let hooker = Hooker::new(
        addr,
        HookType::Retn(routine),
        CallbackOption::None,
        0,
        HookFlags::empty(),
    );
    let point = unsafe { hooker.hook() }.map_err(|e| format!("hook {display}: {e:?}"))?;
    // The loader is never unloaded: hooks live for the whole process.
    Box::leak(Box::new(point));
    Ok(())
}

pub fn init(main: &Module, official: bool, block_external: bool) -> Result<(), String> {
    MAIN.set(*main).ok();
    if official {
        READ_ONLY.store(true, Ordering::SeqCst);
        log::warn!(
            "official mode: read-only latch on (nothing is sent or changed, but the DLL still \
             patches game code in memory to observe, which can be detected)"
        );
    }
    BLOCK_EXTERNAL.store(block_external && !official, Ordering::SeqCst);
    log::info!(
        "network guard: official={official} block_external={} latch_at_start={} \
         hooks=connect,WSAConnect,WSAConnectByNameW/A,WSAConnectByList,WSAIoctl(ConnectEx) \
         (a socket opened by raw system calls is neither blocked nor latched)",
        BLOCK_EXTERNAL.load(Ordering::SeqCst),
        READ_ONLY.load(Ordering::SeqCst)
    );
    let ws2 = unsafe {
        let name: Vec<u16> = "ws2_32.dll\0".encode_utf16().collect();
        let mut h = GetModuleHandleW(name.as_ptr());
        if h.is_null() {
            h = LoadLibraryW(name.as_ptr());
        }
        h
    };
    if ws2.is_null() {
        return Err("ws2_32.dll not loaded".into());
    }
    for (required, list) in [(true, &REQUIRED[..]), (false, &OPTIONAL[..])] {
        for (name, routine) in list {
            let display = String::from_utf8_lossy(&name[..name.len() - 1]).into_owned();
            let Some(addr) = (unsafe { GetProcAddress(ws2, name.as_ptr()) }) else {
                if required {
                    return Err(format!("{display} not exported"));
                }
                log::warn!("network guard: {display} not exported by ws2_32, not hooked");
                continue;
            };
            match hook_at(addr as usize, *routine, &display) {
                Ok(()) => {}
                Err(e) if required => return Err(e),
                Err(e) => log::warn!("network guard: {e}"),
            }
        }
    }
    Ok(())
}

pub fn read_only() -> bool {
    READ_ONLY.load(Ordering::SeqCst)
}

pub extern "C" fn host_read_only() -> bool {
    read_only()
}

pub extern "C" fn host_connections(out: *mut Connection, max: usize) -> usize {
    let list = CONNECTIONS.lock().unwrap();
    let start = list.len().saturating_sub(max);
    for (i, c) in list[start..].iter().enumerate() {
        unsafe { out.add(i).write(*c) };
    }
    list.len() - start
}

fn backtrace(rsp: u64) -> String {
    let Some(main) = MAIN.get() else {
        return String::new();
    };
    poe_hook_shared::module::stack_refs(main, rsp as usize, 12)
        .iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the guard knows about one connection attempt.
struct Target {
    ip: [u8; 4],
    port: u16,
    external: bool,
    /// Shown in the log instead of `ip:port` (a host name the guard does not resolve).
    label: Option<String>,
    /// Entered into the connection table (an attempt without an address is not).
    record: bool,
}

impl Target {
    fn from_sockaddr(name: *const SOCKADDR) -> Self {
        let mut t = Target {
            ip: [0; 4],
            port: 0,
            external: false,
            label: None,
            record: !name.is_null(),
        };
        if name.is_null() {
            return t;
        }
        let ipv4 = unsafe { (*name).sa_family } == 2;
        if ipv4 {
            let a = unsafe { &*(name as *const SOCKADDR_IN) };
            t.ip = unsafe { a.sin_addr.S_un.S_addr }.to_ne_bytes();
            t.port = u16::from_be(a.sin_port);
        }
        // One decision for the whole hook: loopback or `trusted_servers` is ours, everything
        // else (IPv6 and other families included) is external.
        t.external = !(ipv4 && poe_hook_shared::trust::is_trusted_v4(t.ip, t.port));
        t
    }

    fn display(&self) -> String {
        self.label.clone().unwrap_or_else(|| {
            let ip = self.ip;
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], self.port)
        })
    }
}

/// The decision, log line and table entry shared by every connect API. Returns false when the
/// attempt is refused (the caller then fails the call with `WSAECONNREFUSED`).
fn admit(api: &str, sock: usize, t: &Target, rsp: u64) -> bool {
    let target = t.display();
    let trusted_remote = !t.external && t.label.is_none() && t.ip[0] != 127;
    let verdict = netguard::decide(t.external, BLOCK_EXTERNAL.load(Ordering::SeqCst));
    if verdict == Verdict::Block {
        log::warn!(
            "blocked {api} sock={sock} to {target} stack=[{}]",
            backtrace(rsp)
        );
        return false;
    }
    if verdict == (Verdict::Allow { latch: true }) && !READ_ONLY.swap(true, Ordering::SeqCst) {
        log::warn!("external connection to {target} ({api}): read-only latch on");
    }
    let seq = SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    log::info!(
        "connect #{seq} sock={sock} {target}{} api={api} stack=[{}]",
        if t.external {
            " (external)"
        } else if trusted_remote {
            " (trusted server)"
        } else {
            ""
        },
        backtrace(rsp)
    );
    if t.record {
        let mut list = CONNECTIONS.lock().unwrap();
        if list.len() >= 256 {
            list.remove(0);
        }
        list.push(Connection {
            socket: sock as u64,
            ip: t.ip,
            port: t.port,
            external: t.external,
            seq,
            unix_ms: poe_hook_shared::unix_ms(),
        });
    }
    true
}

fn refuse() {
    unsafe { WSASetLastError(WSAECONNREFUSED) };
}

/// connect and WSAConnect share the first three arguments; WSAConnect has four more.
type WsaConnectFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const c_void,
    *const c_void,
    *const c_void,
    *const c_void,
) -> i32;

unsafe extern "win64" fn on_connect(regs: *mut Registers, original: usize, _: usize) -> usize {
    let r = unsafe { &*regs };
    let (sock, name, len) = (r.rcx, r.rdx as *const SOCKADDR, r.r8 as i32);
    let t = Target::from_sockaddr(name);
    if !admit("connect", sock as usize, &t, r.rsp) {
        refuse();
        return SOCKET_ERROR as u32 as usize;
    }
    // Forward all seven argument slots; plain connect ignores the extra ones.
    let (a4, a5, a6, a7) = unsafe {
        (
            r.r9 as *const c_void,
            r.get_stack(5) as *const c_void,
            r.get_stack(6) as *const c_void,
            r.get_stack(7) as *const c_void,
        )
    };
    let f: WsaConnectFn = unsafe { std::mem::transmute(original) };
    unsafe { f(sock as SOCKET, name, len, a4, a5, a6, a7) as u32 as usize }
}

/// `ConnectEx(s, name, namelen, sendbuf, sendlen, bytes_sent, overlapped) -> BOOL`.
type ConnectExFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const c_void,
    u32,
    *mut u32,
    *mut c_void,
) -> i32;

unsafe extern "win64" fn on_connect_ex(regs: *mut Registers, original: usize, _: usize) -> usize {
    let r = unsafe { &*regs };
    let (sock, name, len) = (r.rcx, r.rdx as *const SOCKADDR, r.r8 as i32);
    let t = Target::from_sockaddr(name);
    if !admit("ConnectEx", sock as usize, &t, r.rsp) {
        refuse();
        return 0;
    }
    let (sendbuf, sendlen, sent, ov) = unsafe {
        (
            r.r9 as *const c_void,
            r.get_stack(5) as u32,
            r.get_stack(6) as *mut u32,
            r.get_stack(7) as *mut c_void,
        )
    };
    let f: ConnectExFn = unsafe { std::mem::transmute(original) };
    unsafe { f(sock as SOCKET, name, len, sendbuf, sendlen, sent, ov) as u32 as usize }
}

/// `WSAConnectByName(s, node, service, local_len, local, remote_len, remote, timeout, reserved)`.
type ConnectByNameFn = unsafe extern "system" fn(
    SOCKET,
    *const c_void,
    *const c_void,
    *mut u32,
    *mut c_void,
    *mut u32,
    *mut c_void,
    *const c_void,
    *mut c_void,
) -> i32;

/// Reads a NUL-terminated string (at most 256 characters; null is empty).
unsafe fn read_cstr<T: Copy + Into<u32>>(p: *const T) -> String {
    let mut s = String::new();
    if p.is_null() {
        return s;
    }
    for i in 0..256 {
        let c: u32 = unsafe { *p.add(i) }.into();
        if c == 0 {
            break;
        }
        s.push(char::from_u32(c).unwrap_or('?'));
    }
    s
}

unsafe fn connect_by_name(api: &str, regs: *mut Registers, original: usize, wide: bool) -> usize {
    let r = unsafe { &*regs };
    let (sock, node, service) = (r.rcx, r.rdx as *const c_void, r.r8 as *const c_void);
    let (node_s, service_s) = unsafe {
        if wide {
            (
                read_cstr(node as *const u16),
                read_cstr(service as *const u16),
            )
        } else {
            (
                read_cstr(node as *const u8),
                read_cstr(service as *const u8),
            )
        }
    };
    // No name resolution here (loader context, and a name can change): only a numeric target
    // can be trusted.
    let numeric = netguard::parse_v4_target(&node_s, &service_s);
    let t = Target {
        ip: numeric.map_or([0; 4], |n| n.0),
        port: numeric.map_or(0, |n| n.1),
        external: netguard::name_target_external(&node_s, &service_s),
        label: Some(format!("{node_s}:{service_s}")),
        record: true,
    };
    if !admit(api, sock as usize, &t, r.rsp) {
        refuse();
        return 0;
    }
    let (a4, a5, a6, a7, a8, a9) = unsafe {
        (
            r.r9 as *mut u32,
            r.get_stack(5) as *mut c_void,
            r.get_stack(6) as *mut u32,
            r.get_stack(7) as *mut c_void,
            r.get_stack(8) as *const c_void,
            r.get_stack(9) as *mut c_void,
        )
    };
    let f: ConnectByNameFn = unsafe { std::mem::transmute(original) };
    unsafe { f(sock as SOCKET, node, service, a4, a5, a6, a7, a8, a9) as u32 as usize }
}

unsafe extern "win64" fn on_connect_by_name_w(
    regs: *mut Registers,
    original: usize,
    _: usize,
) -> usize {
    unsafe { connect_by_name("WSAConnectByNameW", regs, original, true) }
}

unsafe extern "win64" fn on_connect_by_name_a(
    regs: *mut Registers,
    original: usize,
    _: usize,
) -> usize {
    unsafe { connect_by_name("WSAConnectByNameA", regs, original, false) }
}

/// `WSAConnectByList(s, list, local_len, local, remote_len, remote, timeout, reserved)`.
type ConnectByListFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKET_ADDRESS_LIST,
    *mut u32,
    *mut c_void,
    *mut u32,
    *mut c_void,
    *const c_void,
    *mut c_void,
) -> i32;

unsafe extern "win64" fn on_connect_by_list(
    regs: *mut Registers,
    original: usize,
    _: usize,
) -> usize {
    let r = unsafe { &*regs };
    let (sock, list) = (r.rcx, r.rdx as *const SOCKET_ADDRESS_LIST);
    // The API tries the entries in turn, so the whole list has to be trusted.
    let mut entries = Vec::new();
    if !list.is_null() {
        let count = unsafe { (*list).iAddressCount }.clamp(0, 64) as usize;
        let first = unsafe { (*list).Address.as_ptr() };
        for i in 0..count {
            let a = unsafe { &*first.add(i) };
            let sa = a.lpSockaddr as *const SOCKADDR;
            let v4 = !sa.is_null() && unsafe { (*sa).sa_family } == 2;
            entries.push(v4.then(|| {
                let a = unsafe { &*(sa as *const SOCKADDR_IN) };
                (
                    unsafe { a.sin_addr.S_un.S_addr }.to_ne_bytes(),
                    u16::from_be(a.sin_port),
                )
            }));
        }
    }
    let first = entries.first().copied().flatten();
    let t = Target {
        ip: first.map_or([0; 4], |n| n.0),
        port: first.map_or(0, |n| n.1),
        external: netguard::list_external(&entries),
        label: (entries.len() > 1).then(|| format!("list of {} addresses", entries.len())),
        record: true,
    };
    if !admit("WSAConnectByList", sock as usize, &t, r.rsp) {
        refuse();
        return 0;
    }
    let (a3, a4, a5, a6, a7, a8) = unsafe {
        (
            r.r8 as *mut u32,
            r.r9 as *mut c_void,
            r.get_stack(5) as *mut u32,
            r.get_stack(6) as *mut c_void,
            r.get_stack(7) as *const c_void,
            r.get_stack(8) as *mut c_void,
        )
    };
    let f: ConnectByListFn = unsafe { std::mem::transmute(original) };
    unsafe { f(sock as SOCKET, list, a3, a4, a5, a6, a7, a8) as u32 as usize }
}

/// `WSAIoctl(s, code, in, in_len, out, out_len, bytes_returned, overlapped, completion)`.
type WsaIoctlFn = unsafe extern "system" fn(
    SOCKET,
    u32,
    *const c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut c_void,
    *const c_void,
) -> i32;

/// Hooks the `ConnectEx` implementation the system returned (once per address).
fn wrap_connect_ex(ptr: usize) -> Result<(), String> {
    if ptr == 0 {
        return Err("null ConnectEx pointer".into());
    }
    let mut done = CONNECT_EX_HOOKED.lock().unwrap();
    if done.contains(&ptr) {
        return Ok(());
    }
    hook_at(ptr, on_connect_ex, "ConnectEx")?;
    done.push(ptr);
    log::info!("network guard: ConnectEx at {ptr:#x} hooked");
    Ok(())
}

unsafe extern "win64" fn on_wsa_ioctl(regs: *mut Registers, original: usize, _: usize) -> usize {
    let r = unsafe { &*regs };
    let (sock, code, input, in_len) = (r.rcx, r.rdx as u32, r.r8 as *const u8, r.r9 as u32);
    let (output, out_len, ret_len, ov, cb) = unsafe {
        (
            r.get_stack(5) as *mut c_void,
            r.get_stack(6) as u32,
            r.get_stack(7) as *mut u32,
            r.get_stack(8) as *mut c_void,
            r.get_stack(9) as *const c_void,
        )
    };
    let f: WsaIoctlFn = unsafe { std::mem::transmute(original) };
    let result = unsafe {
        f(
            sock as SOCKET,
            code,
            input as *const c_void,
            in_len,
            output,
            out_len,
            ret_len,
            ov,
            cb,
        )
    };
    let guid = (!input.is_null() && in_len <= 64)
        .then(|| unsafe { std::slice::from_raw_parts(input, in_len as usize) });
    if result == 0
        && !output.is_null()
        && out_len as usize >= std::mem::size_of::<usize>()
        && netguard::is_connect_ex_request(code, guid)
    {
        let last_error = unsafe { WSAGetLastError() };
        let ptr = unsafe { *(output as *const usize) };
        match wrap_connect_ex(ptr) {
            Ok(()) => unsafe { WSASetLastError(last_error) },
            Err(e) if READ_ONLY.load(Ordering::SeqCst) => {
                // Official play only observes: the pointer stays, the connection goes unlogged.
                log::warn!("network guard: ConnectEx not hooked ({e}); read-only, left as is");
                unsafe { WSASetLastError(last_error) };
            }
            Err(e) => {
                // Fail closed: without our hook the game could connect anywhere.
                log::error!("network guard: ConnectEx request refused ({e})");
                unsafe {
                    *(output as *mut usize) = 0;
                    WSASetLastError(WSAEOPNOTSUPP);
                }
                return SOCKET_ERROR as u32 as usize;
            }
        }
    }
    result as u32 as usize
}
