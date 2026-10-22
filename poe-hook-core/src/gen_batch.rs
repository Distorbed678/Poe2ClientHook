//! In-client batch terrain generation (`[gen_batch]`, `POE_HOOK_GEN_BATCH=<dir>`): runs the
//! client's own base terrain generator in a loop on worker threads, for a list of
//! `area seed topology orientation` jobs, without a login, a session or rendering. Private mode
//! only (refused when the config says official, and again before every job when the loader's
//! read-only latch is on). How and why it works: `docs/re/terrain/batch.md` in the main
//! repository.
//!
//! One job:
//! 1. a fresh world object (`ClientWorld` constructor, so every virtual works and the terrain
//!    object at world +0x8d0 is built), its area row (+0x98) set to the `WorldAreas` row,
//!    league mode 1, the forced topology / orientation as stats 0xb92 / 0xb93 in the world's stat
//!    map (+0x128), seed at +0x4b4;
//! 2. what `HeadlessWorld_LoadArea` does: base generator constructor, `TerrainGen_Run`;
//! 3. read the tile hash (world +0x114), doodad hash (+0x118) and the map size; the layout,
//!    doodads and grids for jobs of the export list;
//! 4. the generator's and the world's destructors.
//!
//! Results go to `<dir>/batch-results.tsv`, one line per job, flushed per line; jobs already
//! in the file are skipped (resume). Each worker writes its current job to
//! `<dir>/inflight-<n>.txt`, so a driver that sees the client die knows what was running.
//! A file `<dir>/batch-stop` makes the workers finish the job in hand and stop (`batch-stopped`
//! is written), so a driver can restart the client (memory cap) without losing anything.

use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::cxx_guard;
use poe_hook_shared::{
    batch_jobs::{Job, done_keys, read_jobs},
    config::GenBatchConfig,
    mem::{read, readable, wide_string},
};

/// The `ClientWorld` object: `new(0x17e8)` in `world_replace`.
const WORLD_SIZE: usize = 0x17e8;
/// The base generator (`local_2e8`, 704 bytes, in `HeadlessWorld_LoadArea`) with room to spare.
const GEN_SIZE: usize = 0x400;
/// World stats the generator reads (`terrain_topology_pick`): forced topology (1-based index)
/// and forced orientation + 1.
const STAT_FORCE_TOPOLOGY: i32 = 0xb92;
const STAT_FORCE_ORIENTATION: i32 = 0xb93;
/// WorldAreas row: `u16` hash at +0x2a, first qword the id string pointer.
const AREA_HASH16: usize = 0x2a;

type Alloc = unsafe extern "win64" fn(usize) -> *mut u8;
type Free = unsafe extern "win64" fn(*mut u8);
type WorldCtor = unsafe extern "win64" fn(*mut u8, u8, u8) -> *mut u8;
type GenCtor = unsafe extern "win64" fn(*mut u8, *mut u8) -> *mut u8;
type GenCall = unsafe extern "win64" fn(*mut u8);
type FlatSet = unsafe extern "win64" fn(*mut u8, i32, i32);
type TableGet = unsafe extern "win64" fn(*mut usize) -> *mut usize;
type TerrainOf = unsafe extern "win64" fn(*mut u8) -> usize;

/// Runtime addresses, resolved once from the signature table.
#[derive(Clone, Copy)]
struct Env {
    alloc: Alloc,
    free: Free,
    world_ctor: WorldCtor,
    gen_ctor: GenCtor,
    gen_run: GenCall,
    gen_dtor: GenCall,
    flat_set: FlatSet,
    table_get: usize,
    wait_loaded: usize,
    get_ptd: usize,
}

impl Env {
    fn resolve() -> Result<Self, String> {
        use crate::sigs::addr;
        let f = |n: &str| addr(n);
        // SAFETY: the signature table verified these are the functions named.
        unsafe {
            Ok(Self {
                alloc: std::mem::transmute::<usize, Alloc>(f("game_alloc")?),
                free: std::mem::transmute::<usize, Free>(f("game_free")?),
                world_ctor: std::mem::transmute::<usize, WorldCtor>(f("world_construct_client")?),
                gen_ctor: std::mem::transmute::<usize, GenCtor>(f("terrain_gen_construct")?),
                gen_run: std::mem::transmute::<usize, GenCall>(f("terrain_driver")?),
                gen_dtor: std::mem::transmute::<usize, GenCall>(f("terrain_gen_destroy")?),
                flat_set: std::mem::transmute::<usize, FlatSet>(f("flat_map_set")?),
                table_get: f("world_areas_table")?,
                wait_loaded: f("resource_wait_loaded")?,
                get_ptd: f("vcrt_getptd")?,
            })
        }
    }
}

/// What a job produced.
#[derive(Default)]
struct Out {
    tile_hash: u32,
    doodad_hash: u32,
    width: u32,
    height: u32,
}

struct Shared {
    env: Env,
    areas: HashMap<String, usize>,
    /// The WorldAreas table object (our reference on it stays for the whole run).
    table: usize,
    jobs: Vec<Job>,
    next: AtomicUsize,
    done: AtomicUsize,
    errors: AtomicUsize,
    exports: HashSet<String>,
    dir: PathBuf,
    results: Mutex<File>,
    stop: AtomicBool,
    /// A worker saw `batch-stop`.
    paused: AtomicBool,
    start: Instant,
}

/// Starts the batch when `[gen_batch]` asks for it; the work runs on its own threads.
pub fn init(config: &GenBatchConfig, read_only: bool) -> Result<(), String> {
    if read_only {
        return Err("refused: read-only (official) mode".into());
    }
    let dir = config
        .dir
        .clone()
        .ok_or("no directory (POE_HOOK_GEN_BATCH or [gen_batch] dir)")?;
    let env = Env::resolve()?;
    let config = config.clone();
    crate::hooks::spawn(move || {
        if let Err(e) = run(env, config, dir) {
            log::error!("gen_batch: {e}");
        }
    });
    Ok(())
}

fn run(env: Env, config: GenBatchConfig, dir: PathBuf) -> Result<(), String> {
    // The client must have loaded its data (and its main thread must be running).
    if !crate::hooks::sleep(Duration::from_secs(config.start_delay_seconds)) {
        return Ok(());
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (areas, table) = loop {
        match load_areas(&env, &dir) {
            Ok(a) => break a,
            Err(e) => {
                log::warn!("gen_batch: WorldAreas not ready: {e}");
                if !crate::hooks::sleep(Duration::from_secs(5)) {
                    return Ok(());
                }
            }
        }
    };
    log::info!("gen_batch: {} WorldAreas rows", areas.len());
    let results_path = dir.join("batch-results.tsv");
    let done = done_keys(&std::fs::read_to_string(&results_path).unwrap_or_default());
    let mut jobs = read_jobs(&dir.join("jobs.txt"));
    let total = jobs.len();
    jobs.retain(|j| !done.contains(&j.key()));
    // Suspects (jobs running when the client last died) go first, one at a time.
    let suspects: Vec<Job> = read_jobs(&dir.join("suspects.txt"))
        .into_iter()
        .filter(|j| !done.contains(&j.key()))
        .collect();
    let exports: HashSet<String> = read_jobs(&dir.join("export.txt"))
        .iter()
        .map(Job::key)
        .collect();
    log::info!(
        "gen_batch: {total} jobs, {} done, {} to run ({} suspects first), {} exports, {} threads",
        total - jobs.len(),
        jobs.len(),
        suspects.len(),
        exports.len(),
        config.threads.max(1)
    );
    let is_new = !results_path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&results_path)
        .map_err(|e| format!("{}: {e}", results_path.display()))?;
    if is_new {
        let _ = writeln!(
            file,
            "# area\tseed\ttopology\torientation\tstatus\ttile_hash\tdoodad_hash\twidth\theight\tms\tdetail"
        );
    }
    let shared = Shared {
        env,
        areas,
        table,
        jobs,
        next: AtomicUsize::new(0),
        done: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
        exports,
        dir: dir.clone(),
        results: Mutex::new(file),
        stop: AtomicBool::new(false),
        paused: AtomicBool::new(false),
        start: Instant::now(),
    };
    // Suspects: this thread, alone.
    for job in &suspects {
        if shared.stop.load(Ordering::Relaxed) || !crate::hooks::running() {
            return Ok(());
        }
        do_job(&shared, 0, job);
    }
    let shared = &shared;
    std::thread::scope(|s| {
        for n in 0..config.threads.max(1) {
            s.spawn(move || worker(shared, n));
        }
    });
    let (done, errors) = (
        shared.done.load(Ordering::Relaxed),
        shared.errors.load(Ordering::Relaxed),
    );
    log::info!(
        "gen_batch: finished {done} jobs ({errors} errors) in {:.1} s",
        shared.start.elapsed().as_secs_f64()
    );
    if !shared.stop.load(Ordering::Relaxed) && crate::hooks::running() {
        for n in 0..config.threads.max(1) {
            let _ = std::fs::remove_file(dir.join(format!("inflight-{n}.txt")));
        }
        // `batch-stopped`: every worker has finished its job after a `batch-stop` request.
        let marker = if shared.paused.load(Ordering::Relaxed) {
            "batch-stopped"
        } else {
            "batch-done"
        };
        let _ = std::fs::write(dir.join(marker), format!("{done} jobs, {errors} errors\n"));
    }
    Ok(())
}

fn worker(shared: &Shared, n: usize) {
    loop {
        if shared.stop.load(Ordering::Relaxed) || !crate::hooks::running() {
            return;
        }
        // The driver asks for a pause (memory cap, restart every N jobs): finish the job in
        // hand, take no new one.
        if shared.dir.join("batch-stop").exists() {
            shared.paused.store(true, Ordering::Relaxed);
            return;
        }
        // The loader's latch can switch on later (a connection to an untrusted server).
        if crate::host::read_only() {
            log::error!("gen_batch: read-only latch on, stopping");
            shared.stop.store(true, Ordering::Relaxed);
            return;
        }
        let i = shared.next.fetch_add(1, Ordering::Relaxed);
        let Some(job) = shared.jobs.get(i) else {
            return;
        };
        do_job(shared, n, job);
    }
}

fn do_job(shared: &Shared, n: usize, job: &Job) {
    let _ = std::fs::write(
        shared.dir.join(format!("inflight-{n}.txt")),
        format!("{}\n", job.key()),
    );
    cxx_guard::install(shared.env.get_ptd);
    let started = Instant::now();
    let capture = shared.exports.contains(&job.key());
    let result = match shared.areas.get(&job.area.to_ascii_lowercase()) {
        None => Err(format!("unknown area {}", job.area)),
        Some(&row) => unsafe {
            generate(&shared.env, job, row, shared.table, capture, &shared.dir)
        },
    };
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    let line = match result {
        Ok(o) => format!(
            "{}\tok\t{}\t{}\t{}\t{}\t{ms:.1}\t",
            job.key(),
            o.tile_hash,
            o.doodad_hash,
            o.width,
            o.height
        ),
        Err(e) => {
            shared.errors.fetch_add(1, Ordering::Relaxed);
            format!(
                "{}\terror\t0\t0\t0\t0\t{ms:.1}\t{}",
                job.key(),
                e.replace(['\t', '\n'], " ")
            )
        }
    };
    {
        // One write per line, so a crash cannot leave half of one.
        let mut f = shared.results.lock().unwrap();
        let _ = f.write_all(format!("{line}\n").as_bytes());
        let _ = f.flush();
    }
    let n_done = shared.done.fetch_add(1, Ordering::Relaxed) + 1;
    if n_done.is_multiple_of(500) {
        let secs = shared.start.elapsed().as_secs_f64();
        log::info!(
            "gen_batch: {n_done} jobs, {:.1} per second, {} errors",
            n_done as f64 / secs,
            shared.errors.load(Ordering::Relaxed)
        );
    }
}

/// All `WorldAreas` rows by lowercase id.
fn load_areas(env: &Env, dir: &Path) -> Result<(HashMap<String, usize>, usize), String> {
    use crate::sigs::off;
    let o = off();
    let mut table = 0usize;
    let get: TableGet = unsafe { std::mem::transmute(env.table_get) };
    unsafe { get(&mut table) };
    // The reference stays: the rows must not go away while the batch runs.
    if table == 0 {
        return Err("table getter returned null".into());
    }
    if read::<u32>(table + o.resource_state) != Some(2) {
        let wait: GenCall = unsafe { std::mem::transmute(env.wait_loaded) };
        unsafe { wait(table as *mut u8) };
    }
    let vec = read::<usize>(table + o.table_rows).ok_or("table +rows unreadable")?;
    let (begin, end) = (
        read::<usize>(vec).ok_or("rows begin unreadable")?,
        read::<usize>(vec + 8).ok_or("rows end unreadable")?,
    );
    // The row count: areas.tsv has one line per row (written from the same game data).
    let count = std::fs::read_to_string(
        poe_hook_shared::exe_dir()
            .join("poe-hook-data")
            .join("areas.tsv"),
    )
    .map_err(|e| format!("poe-hook-data/areas.tsv: {e}"))?
    .lines()
    .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    .count();
    let bytes = end.checked_sub(begin).ok_or("rows end before begin")?;
    if count == 0 || bytes == 0 || bytes % count != 0 {
        return Err(format!(
            "rows span {bytes:#x} bytes, {count} areas: no whole stride"
        ));
    }
    let stride = bytes / count;
    let _ = std::fs::write(
        dir.join("areas-probe.txt"),
        format!("table {table:#x} rows {begin:#x}..{end:#x} count {count} stride {stride:#x}\n"),
    );
    let mut out = HashMap::new();
    for i in 0..count {
        let row = begin + i * stride;
        let id = read::<usize>(row)
            .and_then(|p| wide_string(p, 128))
            .ok_or_else(|| format!("row {i}: id unreadable"))?;
        out.insert(id.to_ascii_lowercase(), row);
    }
    if !readable(begin, bytes) {
        return Err("rows not readable".into());
    }
    Ok((out, table))
}

/// Runs one job on the calling thread.
///
/// # Safety
/// `env` must hold the verified game functions and `row` a `WorldAreas` row.
unsafe fn generate(
    env: &Env,
    job: &Job,
    row: usize,
    table: usize,
    capture: bool,
    dir: &Path,
) -> Result<Out, String> {
    use crate::sigs::off;
    let o = off();
    let topologies = read::<usize>(row + o.area_topology_count).unwrap_or(0);
    if job.topology as usize > topologies {
        return Err(format!(
            "topology {} but the row has {topologies}",
            job.topology
        ));
    }
    if job.orientation > 7 {
        return Err(format!("orientation {}", job.orientation));
    }
    unsafe {
        let world = (env.alloc)(WORLD_SIZE);
        if world.is_null() {
            return Err("world allocation failed".into());
        }
        std::ptr::write_bytes(world, 0, WORLD_SIZE);
        (env.world_ctor)(world, 0, 0);
        let w = world as usize;
        (w + o.world_area).wr(row);
        // The world holds a counted reference on the table its area row belongs to (some
        // terrain code, like the Incursion temple rooms, reads it; the destructor releases it).
        (w + o.world_area_table).wr(table);
        (*((table + o.resource_refs) as *const std::sync::atomic::AtomicI32))
            .fetch_add(1, Ordering::SeqCst);
        (w + o.world_league_mode).wr(1u32);
        let stats = world.add(o.world_stats);
        if job.topology > 0 {
            (env.flat_set)(stats, STAT_FORCE_TOPOLOGY, job.topology as i32);
        }
        if job.orientation >= 0 {
            (env.flat_set)(stats, STAT_FORCE_ORIENTATION, job.orientation + 1);
        }
        (w + o.world_gen_flag).wr(0u8);
        (w + o.world_gen_state).wr(0u32);
        (w + o.world_gen_seed).wr(job.seed);

        let generator = (env.alloc)(GEN_SIZE);
        std::ptr::write_bytes(generator, 0, GEN_SIZE);
        let g = generator as usize;
        // The generator throws `TerrainGenerationException` for layouts it cannot build; the
        // guard turns that into an error (see cxx_guard.rs). The client's own caller does not
        // catch it either, so the client could never generate those (area, seed) pairs.
        let built = cxx_guard::call(env.gen_ctor as usize, g, w);
        let ran = match built {
            Ok(()) => {
                // The client generator clears this (`ClientWorld_LoadArea`): the tile map
                // validation pass is the server's, and throws where the client carries on.
                (g + o.generator_validate).wr(0u8);
                crate::terrain_tools::batch_begin(capture);
                let r = cxx_guard::call(env.gen_run as usize, g, 0);
                crate::terrain_tools::batch_end();
                r
            }
            Err(e) => Err(e),
        };
        let captured = crate::terrain_tools::batch_take();
        let out = match ran {
            Ok(()) => read_result(world, o, job, row, capture, captured, dir),
            Err(e) => Err(e.to_string()),
        };

        // What the generator and the world hold goes back; a destructor that throws leaks.
        let _ = cxx_guard::call(env.gen_dtor as usize, g, 0);
        (env.free)(generator);
        let vt = read::<usize>(w).unwrap_or(0);
        if let Some(dtor) = read::<usize>(vt + o.world_vt_delete) {
            let _ = cxx_guard::call(dtor, w, 1);
        }
        out
    }
}

trait Wr {
    unsafe fn wr<T>(self, v: T);
}

impl Wr for usize {
    unsafe fn wr<T>(self, v: T) {
        unsafe { (self as *mut T).write_unaligned(v) }
    }
}

/// Hashes and size from the finished world; the export for jobs on the export list.
unsafe fn read_result(
    world: *mut u8,
    o: &poe_hook_shared::offsets::Offsets,
    job: &Job,
    row: usize,
    capture: bool,
    captured: Option<crate::terrain_tools::Captured>,
    dir: &Path,
) -> Result<Out, String> {
    let w = world as usize;
    let tile_hash = read::<u32>(w + o.world_tile_hash).ok_or("tile hash unreadable")?;
    let doodad_hash = read::<u32>(w + o.world_doodad_hash).ok_or("doodad hash unreadable")?;
    let vt = read::<usize>(w).ok_or("world vtable")?;
    let terrain_of = read::<usize>(vt + o.world_vt_terrain).ok_or("terrain slot")?;
    let terrain_of: TerrainOf = unsafe { std::mem::transmute(terrain_of) };
    let terrain = unsafe { terrain_of(world) };
    let width = read::<u32>(terrain + o.terrain_width).unwrap_or(0);
    let height = read::<u32>(terrain + o.terrain_height).unwrap_or(0);
    if tile_hash == 0 && width == 0 {
        return Err("no terrain generated".into());
    }
    if capture {
        export(dir, job, row, terrain, tile_hash, doodad_hash, captured);
    }
    Ok(Out {
        tile_hash,
        doodad_hash,
        width,
        height,
    })
}

/// `exports/<area>_<seed>_<topology>_<orientation>/`: layout, doodads, grids and meta of one
/// job (the same files as an area export).
fn export(
    dir: &Path,
    job: &Job,
    row: usize,
    terrain: usize,
    tile_hash: u32,
    doodad_hash: u32,
    captured: Option<crate::terrain_tools::Captured>,
) {
    let out = dir.join("exports").join(job.dir_name());
    if let Err(e) = std::fs::create_dir_all(&out) {
        log::error!("gen_batch export {}: {e}", out.display());
        return;
    }
    let write = |name: &str, data: &[u8]| {
        if let Err(e) = std::fs::write(out.join(name), data) {
            log::error!("gen_batch export {name}: {e}");
        }
    };
    let hash16 = read::<u16>(row + AREA_HASH16).unwrap_or(0);
    let mut meta = format!(
        "area\t{}\narea_hash16\t{hash16:#06x}\nseed\t{}\ntopology\t{}\norientation\t{}\ntile_hash\t{tile_hash}\ndoodad_hash\t{doodad_hash}\n",
        job.area, job.seed, job.topology, job.orientation
    );
    if let Some(t) = crate::terrain_tools::tiles(terrain) {
        let (text, computed) = crate::terrain_tools::layout(&t);
        let ok = computed == tile_hash || (computed == 0 && tile_hash == 1);
        let _ = writeln!(
            meta,
            "size_tiles\t{}\t{}\ncomputed_tile_hash\t{computed}\t{}",
            t.w,
            t.h,
            if ok { "match" } else { "MISMATCH" }
        );
        write("layout.tsv", text.as_bytes());
        if let Some(grids) = crate::dump_types::grid_bytes(terrain, t.w, t.h) {
            write("grids.bin", &grids);
        }
    }
    if let Some(c) = captured {
        let _ = writeln!(meta, "generator_objects\t{}", c.objects.len());
        let computed = c.doodads.iter().fold(0u32, |h, &(x, y, _, ph, _)| {
            h.wrapping_add(y as u32)
                .wrapping_add(ph)
                .wrapping_add((x as u32) << 16)
        });
        let _ = writeln!(
            meta,
            "computed_doodad_hash\t{computed}\t{}",
            if computed == doodad_hash {
                "match"
            } else {
                "MISMATCH"
            }
        );
        let mut text = String::from("# x\ty\tangle\tpath hash\tpath\n");
        for (x, y, a, h, p) in &c.doodads {
            let _ = writeln!(text, "{x}\t{y}\t{a:.4}\t{h}\t{p}");
        }
        write("doodads.tsv", text.as_bytes());
    }
    write("meta.txt", meta.as_bytes());
}
