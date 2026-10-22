//! Runs a game function so that a C++ exception nobody handles ends the call with an error
//! instead of killing the process (`gen_batch`: the terrain generator throws
//! `TerrainGenerationException` when a layout cannot be built, "Dungeon generation failed: No
//! possible rooms found ...", and the client's own caller is not prepared to survive that on a
//! thread of ours).
//!
//! How: a `setjmp`-like assembly entry ([`call`]) records the callee-saved registers and the
//! stack position, then calls the function. The process-wide unhandled-exception filter, which
//! Windows only reaches when no frame between the throw and the thread start has a matching
//! `catch` (so the game's own internal `try`/`catch` keep working), looks for a thread that is
//! inside [`call`] and, for a C++ exception, redirects that thread to the recovery entry, which
//! restores the registers and makes [`call`] return `Err`. The frames in between are skipped, so
//! their destructors do not run: whatever the callee held (memory, a lock) stays held. The
//! caller must treat the objects the call touched as lost (the batch leaks them or destroys them
//! in another guarded call) and must not use this for anything else than throws it expects.
//! Other exceptions (access violations ...) go to the previous filter: the client crashes and
//! the driver restarts it.

use std::{
    arch::global_asm,
    cell::{Cell, RefCell},
    sync::atomic::{AtomicUsize, Ordering},
};

use poe_hook_shared::mem::{read, readable};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, RtlRestoreContext, SetUnhandledExceptionFilter,
};

/// What was thrown.
#[derive(Debug, Clone, Default)]
pub struct Caught {
    pub type_name: String,
    pub message: String,
}

impl std::fmt::Display for Caught {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = self
            .type_name
            .trim_start_matches(".?AU")
            .trim_start_matches(".?AV");
        let t = t.split('@').next().unwrap_or(t);
        write!(f, "{t}: {}", self.message)
    }
}

/// rbx rbp rdi rsi r12 r13 r14 r15, rsp after the return, return address, xmm6-xmm15.
#[repr(C)]
struct JmpBuf {
    regs: [usize; 10],
    xmm: [[u8; 16]; 10],
}

thread_local! {
    /// The text of the first `*Generation*` exception thrown inside the guarded call, read when
    /// it is thrown (the exception that reaches the unhandled filter is a rethrown wrapper whose
    /// string buffer may be freed and reused by another thread by then).
    static FIRST: RefCell<Option<Caught>> = const { RefCell::new(None) };
    static ACTIVE: Cell<*mut JmpBuf> = const { Cell::new(std::ptr::null_mut()) };
    static CAUGHT: RefCell<Option<Caught>> = const { RefCell::new(None) };
}

/// The game's `__vcrt_getptd` (0: none).
static GET_PTD: AtomicUsize = AtomicUsize::new(0);
/// How much of the thread's C++ exception state is saved around a guarded call (its fields
/// used by the runtime's throw / catch code lie below +0x90).
const PTD_SAVED: usize = 0x98;

/// The filter that was installed before ours (0: none).
static PREVIOUS: AtomicUsize = AtomicUsize::new(0);
static OURS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "win64" {
    fn gb_try_call(jb: *mut JmpBuf, f: usize, a: usize, b: usize) -> u32;
    fn gb_longjmp();
}

// win64: rcx = jmp buffer, rdx = function, r8 / r9 = its first two arguments. Returns 0 when the
// function returned, 1 when `gb_longjmp` brought control back. `.seh_*` give the stack walker
// (the first pass of exception dispatch) the frame it needs to get past this function.
global_asm!(
    r#"
    .globl gb_try_call
    .seh_proc gb_try_call
gb_try_call:
    sub rsp, 40
    .seh_stackalloc 40
    .seh_endprologue
    mov [rcx + 0x00], rbx
    mov [rcx + 0x08], rbp
    mov [rcx + 0x10], rdi
    mov [rcx + 0x18], rsi
    mov [rcx + 0x20], r12
    mov [rcx + 0x28], r13
    mov [rcx + 0x30], r14
    mov [rcx + 0x38], r15
    lea rax, [rsp + 48]
    mov [rcx + 0x40], rax
    mov rax, [rsp + 40]
    mov [rcx + 0x48], rax
    movups [rcx + 0x50], xmm6
    movups [rcx + 0x60], xmm7
    movups [rcx + 0x70], xmm8
    movups [rcx + 0x80], xmm9
    movups [rcx + 0x90], xmm10
    movups [rcx + 0xa0], xmm11
    movups [rcx + 0xb0], xmm12
    movups [rcx + 0xc0], xmm13
    movups [rcx + 0xd0], xmm14
    movups [rcx + 0xe0], xmm15
    mov rax, rdx
    mov rcx, r8
    mov rdx, r9
    call rax
    xor eax, eax
    add rsp, 40
    ret
    .seh_endproc

    .globl gb_longjmp
gb_longjmp:
    mov rbx, [rcx + 0x00]
    mov rbp, [rcx + 0x08]
    mov rdi, [rcx + 0x10]
    mov rsi, [rcx + 0x18]
    mov r12, [rcx + 0x20]
    mov r13, [rcx + 0x28]
    mov r14, [rcx + 0x30]
    mov r15, [rcx + 0x38]
    movups xmm6, [rcx + 0x50]
    movups xmm7, [rcx + 0x60]
    movups xmm8, [rcx + 0x70]
    movups xmm9, [rcx + 0x80]
    movups xmm10, [rcx + 0x90]
    movups xmm11, [rcx + 0xa0]
    movups xmm12, [rcx + 0xb0]
    movups xmm13, [rcx + 0xc0]
    movups xmm14, [rcx + 0xd0]
    movups xmm15, [rcx + 0xe0]
    mov rsp, [rcx + 0x40]
    mov eax, 1
    jmp qword ptr [rcx + 0x48]
"#
);

/// The calling thread's C++ exception state (the game's statically linked runtime keeps a
/// per-thread chain of "frame infos" of the catch blocks being executed; abandoning a throw
/// leaves entries that point into dead stack, and the next throw on the thread reads them).
fn thread_state() -> Option<(usize, [u8; PTD_SAVED])> {
    let getter = GET_PTD.load(Ordering::Relaxed);
    if getter == 0 {
        return None;
    }
    let get: unsafe extern "win64" fn() -> usize = unsafe { std::mem::transmute(getter) };
    let ptd = unsafe { get() };
    read::<[u8; PTD_SAVED]>(ptd).map(|saved| (ptd, saved))
}

/// Installs the filter (once; again after the game replaced it: it is cheap). `get_ptd` is the
/// game's `__vcrt_getptd`.
pub fn install(get_ptd: usize) {
    GET_PTD.store(get_ptd, Ordering::Relaxed);
    static VEH: std::sync::Once = std::sync::Once::new();
    VEH.call_once(|| unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler(
            1,
            Some(first_chance),
        );
    });
    let ours = filter as *const () as usize;
    // Replacing the same filter again returns it: keep the first predecessor.
    let previous = unsafe { SetUnhandledExceptionFilter(Some(filter)) };
    let previous = previous.map_or(0, |f| f as usize);
    if previous != ours {
        PREVIOUS.store(previous, Ordering::SeqCst);
    }
    OURS.store(ours, Ordering::SeqCst);
}

/// Calls `f(a, b)` (a win64 function). `Err` when it threw a C++ exception that nothing caught.
///
/// # Safety
/// `f` must be a function of at most two integer arguments; see the module docs for what an
/// error leaves behind.
pub unsafe fn call(f: usize, a: usize, b: usize) -> Result<(), Caught> {
    let mut jb = JmpBuf {
        regs: [0; 10],
        xmm: [[0; 16]; 10],
    };
    let state = thread_state();
    ACTIVE.with(|c| c.set(&mut jb));
    CAUGHT.with(|c| *c.borrow_mut() = None);
    FIRST.with(|f| *f.borrow_mut() = None);
    let r = unsafe { gb_try_call(&mut jb, f, a, b) };
    ACTIVE.with(|c| c.set(std::ptr::null_mut()));
    if r == 0 {
        return Ok(());
    }
    if let Some((ptd, saved)) = state {
        unsafe { std::ptr::copy_nonoverlapping(saved.as_ptr(), ptd as *mut u8, PTD_SAVED) };
    }
    let mut caught = CAUGHT
        .with(|c| c.borrow_mut().take())
        .unwrap_or_else(|| Caught {
            type_name: String::new(),
            message: "unknown exception".into(),
        });
    if let Some(first) = FIRST.with(|f| f.borrow_mut().take()) {
        caught.message = first.message;
    }
    Err(caught)
}

/// First-chance look at C++ exceptions of a thread inside a guarded call: remembers the first
/// generation exception with its text. Never handles anything.
unsafe extern "system" fn first_chance(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = unsafe { &*(*info).ExceptionRecord };
    if record.ExceptionCode as u32 == 0xE06D_7363
        && ACTIVE.with(|c| !c.get().is_null())
        && FIRST.with(|f| f.borrow().is_none())
    {
        let caught = describe(record);
        if caught.type_name.contains("Generation") && !caught.message.is_empty() {
            FIRST.with(|f| *f.borrow_mut() = Some(caught));
        }
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

unsafe extern "system" fn filter(info: *const EXCEPTION_POINTERS) -> i32 {
    const CPP_EXCEPTION: u32 = 0xE06D_7363;
    let (record, context) = unsafe { (&*(*info).ExceptionRecord, &mut *(*info).ContextRecord) };
    let jb = ACTIVE.with(|c| c.get());
    if record.ExceptionCode as u32 == CPP_EXCEPTION && !jb.is_null() {
        let caught = describe(record);
        ACTIVE.with(|c| c.set(std::ptr::null_mut()));
        CAUGHT.with(|c| *c.borrow_mut() = Some(caught));
        context.Rip = gb_longjmp as *const () as usize as u64;
        context.Rcx = jb as u64;
        // Any valid, 16-byte aligned stack: the recovery entry loads its own.
        context.Rsp = (context.Rsp & !0xf) - 0x20;
        // Returning EXCEPTION_CONTINUE_EXECUTION would raise STATUS_NONCONTINUABLE_EXCEPTION
        // (a C++ throw is noncontinuable): restore the context ourselves instead.
        unsafe { RtlRestoreContext(context, std::ptr::null()) };
        return -1;
    }
    let previous = PREVIOUS.load(Ordering::SeqCst);
    if previous != 0 {
        let f: unsafe extern "system" fn(*const EXCEPTION_POINTERS) -> i32 =
            unsafe { std::mem::transmute(previous) };
        return unsafe { f(info) };
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

fn describe(record: &windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD) -> Caught {
    let Some((object, type_name)) = crate::crash::cpp_exception_type(record) else {
        return Caught::default();
    };
    Caught {
        message: message_of(object),
        type_name,
    }
}

/// The text of a thrown game exception. Its layout is not decoded: the object holds a
/// `std::wstring` or the buffer of a string stream (pointers to UTF-16 text), so this takes the
/// first printable text of at least 8 characters it finds, directly or behind a pointer. A
/// stream buffer is not NUL-terminated and may hold older text after the end, so when the
/// object has a pointer into that text (the stream's write position) the text ends there.
fn message_of(object: usize) -> String {
    let printable = |u: u16| (0x20..0x7f).contains(&u) || u == 0xa;
    let run = |p: usize| -> Vec<u16> {
        if !readable(p, 32) {
            return Vec::new();
        }
        let mut units = Vec::new();
        for i in 0..400 {
            match read::<u16>(p + i * 2) {
                Some(u) if printable(u) => units.push(u),
                _ => break,
            }
        }
        units
    };
    let pointers: Vec<usize> = (0..0x160)
        .step_by(8)
        .filter_map(|off| read::<usize>(object + off))
        .collect();
    let finish = |p: usize, mut units: Vec<u16>| {
        let end = pointers
            .iter()
            .filter(|&&q| q > p && q % 2 == 0 && (q - p) / 2 >= 8 && (q - p) / 2 <= units.len())
            .min();
        if let Some(&q) = end {
            units.truncate((q - p) / 2);
        }
        String::from_utf16_lossy(&units)
    };
    for off in (0..0x160).step_by(8) {
        let a = object + off;
        let units = run(a);
        if units.len() >= 8 {
            return finish(a, units);
        }
        if let Some(p) = read::<usize>(a)
            && p > 0x10000
        {
            let units = run(p);
            if units.len() >= 8 {
                return finish(p, units);
            }
        }
    }
    String::new()
}
