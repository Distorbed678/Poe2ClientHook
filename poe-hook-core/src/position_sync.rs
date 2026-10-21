//! Position reports: sends the player's position and current action to the instance server
//! every simulation frame.
//!
//! The server's movement simulation is authoritative and never reads these reports into the
//! simulation. The client runs in lockstep, but the server's pathfinding and collision only
//! approximate the client's, so the two can drift apart near walls and the client snaps back
//! when the server next sends a position. The server compares the reports with its own position
//! (its drift checker, `[dev] drift_check`) to measure that drift.
//!
//! Transport: one UDP datagram per frame to the game's connection to the instance server
//! (`position_sync_port`; the server listens for UDP on the same port). Only trusted servers
//! (loopback or `trusted_servers`) and never while read-only: [`crate::side::allowed`] gates
//! every send. Without a configured port, the last trusted connection is used, which breaks
//! when the game later connects to another service.
//!
//! The datagram is a sealed side-channel frame (`Kind::Report`, session id, counter, HMAC tag;
//! `poe_hook_shared::sidechannel`, docs/protocol/side-channel.md). Without a session (the
//! instance connection has not delivered its key material yet) nothing is sent.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
};

use windows_sys::Win32::Networking::WinSock::{
    AF_INET, INVALID_SOCKET, IPPROTO_UDP, SOCK_DGRAM, SOCKADDR, SOCKADDR_IN, SOCKET, sendto, socket,
};

pub static ENABLED: AtomicBool = AtomicBool::new(false);
/// The instance server's port (0: any loopback connection).
pub static PORT: AtomicU16 = AtomicU16::new(0);

/// The report target: the newest trusted connection to [`PORT`] (from the loader's connection
/// table): socket, destination and its address (ip, port).
static TARGET: Mutex<Option<(u64, SOCKADDR_IN, [u8; 4], u16)>> = Mutex::new(None);
static SOCK: AtomicUsize = AtomicUsize::new(INVALID_SOCKET);

fn target() -> Option<(SOCKADDR_IN, [u8; 4], u16)> {
    let wanted = PORT.load(Ordering::Relaxed);
    let newest = crate::host::connections()
        .into_iter()
        .rev()
        .find(|c| !c.external && (wanted == 0 || c.port == wanted))?;
    let mut target = TARGET.lock().unwrap();
    if target.as_ref().is_none_or(|t| t.0 != newest.socket) {
        let mut dest: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        dest.sin_family = AF_INET;
        dest.sin_port = newest.port.to_be();
        dest.sin_addr.S_un.S_addr = u32::from_ne_bytes(newest.ip);
        log::info!(
            "position sync: target {}.{}.{}.{}:{} (socket {:#x})",
            newest.ip[0],
            newest.ip[1],
            newest.ip[2],
            newest.ip[3],
            newest.port,
            newest.socket
        );
        *target = Some((newest.socket, dest, newest.ip, newest.port));
    }
    let (_, dest, ip, port) = target.as_ref()?;
    Some((*dest, *ip, *port))
}

/// The instance server's address (ip, port) the side channel talks to, if trusted.
pub fn server_addr() -> Option<([u8; 4], u16)> {
    let (_, ip, port) = target()?;
    crate::side::allowed(ip, port).then_some((ip, port))
}

/// One report for the player entity (from the per-frame entity tick).
pub fn report(entity: usize, frame: u32) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    // Never while read-only (official servers): this talks to our server.
    if crate::host::read_only() {
        return;
    }
    let Some((dest, ip, port)) = target() else {
        return;
    };
    if !crate::side::allowed(ip, port) {
        return;
    }
    use poe_hook_shared::mem::read;
    let o = crate::sigs::off();
    let Some(comps) = read::<usize>(entity + o.entity_components_begin) else {
        return;
    };
    let (Some(pos), Some(actor)) = (read::<usize>(comps), read::<usize>(comps + 9 * 8)) else {
        return;
    };
    const CELL: f32 = 250.0 / 23.0;
    let x = read::<f32>(pos + o.positioned_world_x).unwrap_or(0.0) / CELL;
    let y = read::<f32>(pos + o.positioned_world_y).unwrap_or(0.0) / CELL;
    let action = |off: usize| {
        read::<usize>(actor + off)
            .filter(|&a| a != 0)
            .and_then(|a| read::<u16>(a + o.action_type))
            .unwrap_or(0)
    };
    // Actor +0x2a2 bit 5: sprint key held (set by the server's 0x2e7).
    let flags = read::<u8>(actor + o.actor_sprint_flags).unwrap_or(0) as u16;
    let (cx, cy, w, h) = cursor().unwrap_or_default();
    let payload = poe_hook_shared::sidechannel::ReportPayload {
        flags,
        frame,
        x,
        y,
        action: action(o.actor_action0),
        action2: action(o.actor_action1),
        cursor: (cx, cy),
        window: (w, h),
    }
    .encode();
    let Some(msg) = crate::side::seal_udp(poe_hook_shared::sidechannel::Kind::Report, &payload)
    else {
        return;
    };
    let mut s = SOCK.load(Ordering::Relaxed);
    if s == INVALID_SOCKET {
        s = unsafe { socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP) };
        if s == INVALID_SOCKET {
            return;
        }
        SOCK.store(s, Ordering::Relaxed);
    }
    unsafe {
        sendto(
            s,
            msg.as_ptr(),
            msg.len() as i32,
            0,
            &dest as *const SOCKADDR_IN as *const SOCKADDR,
            size_of::<SOCKADDR_IN>() as i32,
        )
    };
}

/// The cursor in the game window's client area and the area's size: (x, y, width, height).
fn cursor() -> Option<(i16, i16, u16, u16)> {
    use windows_sys::Win32::{
        Foundation::{HWND, POINT, RECT},
        Graphics::Gdi::ScreenToClient,
        UI::WindowsAndMessaging::{GetClientRect, GetCursorPos},
    };
    static WINDOW: AtomicUsize = AtomicUsize::new(0);
    let mut hwnd = WINDOW.load(Ordering::Relaxed);
    if hwnd == 0 {
        hwnd = crate::auto_keys::game_window()? as usize;
        WINDOW.store(hwnd, Ordering::Relaxed);
    }
    let hwnd = hwnd as HWND;
    let mut p = POINT { x: 0, y: 0 };
    let mut r: RECT = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetCursorPos(&mut p) != 0
            && ScreenToClient(hwnd, &mut p) != 0
            && GetClientRect(hwnd, &mut r) != 0
    };
    ok.then(|| {
        (
            p.x.clamp(-32768, 32767) as i16,
            p.y.clamp(-32768, 32767) as i16,
            (r.right - r.left).clamp(0, 65535) as u16,
            (r.bottom - r.top).clamp(0, 65535) as u16,
        )
    })
}

/// Closes the report socket (core stop).
pub fn stop() {
    let s = SOCK.swap(INVALID_SOCKET, Ordering::SeqCst);
    if s != INVALID_SOCKET {
        unsafe { windows_sys::Win32::Networking::WinSock::closesocket(s) };
    }
}

/// The report socket and target (instance server address, ip and port), for the debug link
/// ([`crate::devlink`]).
pub fn link() -> Option<(SOCKET, SOCKADDR_IN, [u8; 4], u16)> {
    let s = SOCK.load(Ordering::Relaxed);
    if s == INVALID_SOCKET {
        return None;
    }
    let target = TARGET.lock().unwrap();
    let (_, dest, ip, port) = target.as_ref()?;
    Some((s, *dest, *ip, *port))
}
