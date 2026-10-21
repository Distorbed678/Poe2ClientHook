//! Research aid (`[features] path_log` or `POE_HOOK_PATH_LOG=1`): logs every path the client
//! plans for the local player, to compare a port of its pathfinder against the real one.
//!
//! Hooks the client's grid pathfinder (`0x141ed0390`, JPS-style search with an A* fallback,
//! [docs/re/pathfinding.md](../../../../docs/re/pathfinding.md) in the main repository), calls
//! the original and logs its inputs and result as one `PATHPLAN` line. Read-only: the arguments
//! and the result are passed through untouched.

use ilhook::x64::{HookType, Registers};
use poe_hook_shared::mem::read;
use poe_hook_shared::module::Module;

use std::sync::atomic::{AtomicU32, Ordering};

/// Positioned component bytes logged with each plan (`+0x1e0..+0x210`: flags, sizes, levels).
const POSITIONED_DUMP: (usize, usize) = (0x1e0, 0x30);
/// Layer index byte of the Positioned component (`+0x498`).
const POSITIONED_LAYER: usize = 0x498;

type PlanFn = unsafe extern "win64" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;

static SEQ: AtomicU32 = AtomicU32::new(0);

pub fn init(_main: &Module) -> Result<(), String> {
    let at = crate::sigs::addr("path_plan")?;
    crate::hooks::install(at, HookType::Retn(on_plan), at)
        .map_err(|e| format!("hook path plan: {e}"))
}

unsafe extern "win64" fn on_plan(regs: *mut Registers, original: usize, _at: usize) -> usize {
    let mut guard = crate::hook_guard!("path_log::on_plan");
    let r = unsafe { &*regs };
    let f: PlanFn = unsafe { std::mem::transmute(original) };
    let (goal_p, entity, params_p) = (r.rcx as usize, r.rdx as usize, r.r8 as usize);
    let (out_path, out_count, out_flag) = (
        r.get_stack(5) as usize,
        r.get_stack(6) as usize,
        r.get_stack(7) as usize,
    );
    let ret = guard.original(|| unsafe {
        f(
            r.rcx as usize,
            r.rdx as usize,
            r.r8 as usize,
            r.r9 as usize,
            r.get_stack(5) as usize,
            r.get_stack(6) as usize,
            r.get_stack(7) as usize,
            r.get_stack(8) as usize,
            r.get_stack(9) as usize,
            r.get_stack(10) as usize,
            r.get_stack(11) as usize,
        )
    });
    if entity != 0 && entity == crate::dump_types::player() {
        log_plan(
            r, goal_p, entity, params_p, out_path, out_count, out_flag, ret,
        );
    }
    ret
}

#[allow(clippy::too_many_arguments)]
fn log_plan(
    r: &Registers,
    goal_p: usize,
    entity: usize,
    params_p: usize,
    out_path: usize,
    out_count: usize,
    out_flag: usize,
    ret: usize,
) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let goal = (
        read::<i32>(goal_p).unwrap_or(0),
        read::<i32>(goal_p + 4).unwrap_or(0),
    );
    let positioned = read::<usize>(entity + 0x98).unwrap_or(0);
    let start = (
        read::<i32>(positioned + 0x444).unwrap_or(0),
        read::<i32>(positioned + 0x448).unwrap_or(0),
    );
    let params: Vec<String> = (0..7)
        .map(|i| format!("{:x}", read::<u32>(params_p + 4 * i).unwrap_or(0)))
        .collect();
    let dump: String = (0..POSITIONED_DUMP.1)
        .map(|i| {
            format!(
                "{:02x}",
                read::<u8>(positioned + POSITIONED_DUMP.0 + i).unwrap_or(0)
            )
        })
        .collect();
    let count = read::<u64>(out_count).unwrap_or(0).min(0x88) as usize;
    let path: Vec<String> = (0..count)
        .map(|i| {
            format!(
                "{},{}",
                read::<i32>(out_path + 8 * i).unwrap_or(0),
                read::<i32>(out_path + 8 * i + 4).unwrap_or(0)
            )
        })
        .collect();
    log::info!(
        "PATHPLAN #{seq} frame={} goal={},{} start={},{} params={} a4={:#x} p9={:#x} p10={:#x} p11={:#x} layer={:#x} pos1e0={dump} ok={} reached={} count={count} path={}",
        crate::dump_types::player_frame(),
        goal.0,
        goal.1,
        start.0,
        start.1,
        params.join("/"),
        r.r9 as u8,
        unsafe { r.get_stack(9) } as u8,
        unsafe { r.get_stack(10) } as u32,
        unsafe { r.get_stack(11) } as u8,
        read::<u8>(positioned + POSITIONED_LAYER).unwrap_or(0xff),
        ret as u8,
        read::<u8>(out_flag).unwrap_or(0xff),
        path.join(" ")
    );
}
