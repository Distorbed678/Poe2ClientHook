# Mod manifest (`mod.toml`)

Status: **implemented** (manifest v1 and v2, package verification). The launcher installs, enables and orders client
mods by this format (it still reads only v1 until its mod-sync work package lands); the DLL loader (`poe-hook`,
`poe-hook/src/mods.rs`, logic in the host-testable `poe-hook-mods` crate) loads the enabled mods that have an entry DLL
and checks their ABI. Not yet applied by the loader: the `[data]` sections (data-only mods count as loaded, with a
warning). The client mod ABI is defined in [The mod ABI](#the-mod-abi) below; the **server** mod ABI and the SDK
(templates, packer) live in the public repository [Poe2ModSDK](https://github.com/Distorbed678/Poe2ModSDK).

**Versions.** `manifest_version = 1` is the client-only format that has always existed and keeps working unchanged.
`manifest_version = 2` adds the mod's `side` (`client`, `server` or `both`), the `[client]` and `[server]` sections and
data-tier `[[commands]]`, so one package can carry a client DLL, a server library and data. Readers accept 1 and 2 and
refuse anything newer.

A mod is a folder with a `mod.toml` at its root. Mods are installed into `poe-hook-mods/` next to
`PathOfExileSteam.exe` (`<game dir>/poe-hook-mods/<id>/`), never into the game files themselves. The launcher installs,
enables, disables and orders mods; the loader reads the same folders. This directory name and `state.toml` are what
the launcher writes (`modules/launcher/src-tauri/src/mods.rs`); there is no other `mods/` directory.

```
poe-hook-mods/
  state.toml            enabled = ["core-lib", "my-mod"]   (the enabled mods, in load order)
  my-mod/
    mod.toml
    my_mod.dll          entry DLL (optional)
    data/               data files (optional)
```

From the repository, `cargo xtask deploy-mod [dir]` (or `deploy-client --sample-mod`) installs a mod into `GameFiles/`
through `poe-hook-deploy` in this same layout; never copy files into a game folder by hand.

## Format

### Version 1 (client mods)

```toml
# Required ---------------------------------------------------------------
manifest_version = 1                 # this spec's version
id = "my-mod"                        # [a-z0-9][a-z0-9_-]{1,63}; unique; also the folder name
name = "My Mod"                      # display name
version = "1.2.0"                    # semver

# Optional metadata ------------------------------------------------------
description = "One sentence."
authors = ["Someone"]
license = "MIT"
homepage = "https://example.invalid/my-mod"

# Which client the mod was made for ---------------------------------------
[game]
# Exact client versions the mod is known to work with. The launcher refuses to enable the mod
# on others unless the user overrides; the loader only logs a warning (when the build is known).
versions = ["0.5.5e"]
# The mod ABI the mod was built against (see "The mod ABI"). A mod with an entry DLL must state it; the
# loader loads it only when it equals its own `HOOK_API_VERSION`.
hook_api = 1

# Load order -------------------------------------------------------------
[load]
# Soft hints: this mod loads after/before the listed mod ids if they are present.
after = ["other-mod"]
before = []
# Mods that must not be enabled together with this one.
conflicts = []

# Dependencies (hard) ---------------------------------------------------------
# id = semver requirement. The launcher enables dependencies first and refuses to enable the
# mod when one is missing; the loader skips the mod and logs why.
[dependencies]
core-lib = ">=1.0, <2"

# What the mod contains ---------------------------------------------------
[entry]
# A DLL loaded into the client process, relative to the mod folder. Exports (C ABI, see
# "The mod ABI"):
#   poe_mod_init(api: *const HookApi) -> i32   (required; 0 = ok)
#   poe_mod_abi_version() -> u32                (optional; repeats the ABI version)
dll = "my_mod.dll"

# Data files (all optional); paths are relative to the mod folder.
[data]
# Overlays on game data tables, merged by the loader in load order (later wins).
tables = ["data/tables"]
# Opcode table additions or overrides for the protocol layer (same format as Poe2Protocol opcodes/).
opcodes = ["data/opcodes"]
# Extra settings the mod reads from its own section of poe-hook.toml.
config_defaults = "data/defaults.toml"
```

### Version 2 (sides)

A v2 manifest has the same header, `[game] versions`, `[load]` and `[dependencies]`, plus:

```toml
manifest_version = 2
id = "faster-rolls"
name = "Faster rolls"
version = "1.0.0"
side = "both"                  # "client" | "server" | "both"; required in v2

[client]                       # the client half; the v1 spellings below mean the same
dll = "client/faster_rolls.dll"
hook_api = 1                   # required when there is a DLL
tables = ["client/data/tables"]
opcodes = []
config_defaults = "client/defaults.toml"

[server]                       # the server half
server_api = 1                 # required when there is a library
tables = ["server/data/tables"]            # data overlays, applied by the server
opcodes = []
config_defaults = "server/defaults.toml"

[server.library]               # the native server library per platform (a Rust cdylib)
linux = "server/libfaster_rolls.so"        # must end in .so
windows = "server/faster_rolls.dll"        # must end in .dll

[[commands]]                   # a chat command without code (the data tier); several allowed
name = "rollinfo"              # !rollinfo; [a-z][a-z0-9_-]{0,31}
help = "Shows the roll tuning."           # up to 200 characters
reply = "Roll distance is 1.5x on this server, {player}."   # exactly one of reply and alias
# alias = "announce {args}"    # run another command line as the caller (no leading !)
role = "player"                # "player" (default) or "admin"
```

- `[client]` is `[entry] dll` + `game.hook_api` + `[data]` under one name. The v1 spellings stay valid in v2 and mean
  the client half; giving a setting in both spellings is an error.
- `server_api` may also be written `game.server_api` (parallel to `game.hook_api`).
- `reply`/`alias` text may use `{player}` (the caller's character name) and `{args}` (the rest of the line); the server
  substitutes them. `reply` and `alias` are limited to 1000 characters.
- A v2 manifest is the only place `side`, `[client]`, `[server]`, `[[commands]]` and `game.server_api` exist. In a v1
  manifest they are errors ("needs manifest_version = 2"), not silently ignored keys.

## Sides

| `side` | Needs | Must not have | Loaded by |
|---|---|---|---|
| `client` (v1 manifests are always this) | `[entry]`/`[client]` DLL or client data | `[server]`, `[[commands]]`, `server_api` | the client hook |
| `server` | a server library, server data or `[[commands]]` | `[client]`, `[entry]`, `[data]`, `hook_api` | the server |
| `both` | a client half and a server half | | both; the client hook ignores the server half |

- A DLL must say which API it was built against: v2 requires `hook_api` for a client DLL and `server_api` for a server
  library (v1 keeps its old leniency; the loader's ABI check still refuses a v1 DLL mod without `hook_api`).
- **Dependencies and conflicts are about the mod, not a half.** A `both` mod may depend on a server-only mod (the
  dependency matters on the server, so the client skips it); a mod that has only this program's half may not depend on
  a mod that lacks it. A conflict between two enabled mods holds on every side.
- The client hook and the launcher ignore `[server]` and `[[commands]]`; the server ignores `[client]`/`[entry]`.
- Unknown keys are ignored and logged, **except** in `[server]`, `[server.library]` and `[[commands]]`, where a typo is
  an error (a silently misspelled server setting is worse than a refused mod).
- Game versions are shared: `game.versions` lists the client builds the mod was made for (the server compares it to its
  own game version).

### Fail closed

A pure server mod must never be mistaken for a client mod by a program that predates `side`. Every reader checks
`manifest_version` first, and all programs that read only v1 (the launcher until its mod-sync work package, and
`poe-hook` releases before this one) refuse a v2 manifest with `manifest_version 2 is not supported`. So: a
server-only or `both` mod is always v2; a client mod that has to keep working with those older programs stays v1.
The shared parser has `parse_manifest_max(text, 1)`, which behaves like such a reader (used in the tests).
The current client loader refuses a server-only mod with `server-only mod (side = "server"): it has no client half`,
before any file is touched, and never maps a DLL for it.

## Package

A distributable mod is `<id>-<version>.zip` and a sidecar `<id>-<version>.zip.sha256` (the `sha256sum` format,
`<64 hex>  <file name>`). The SHA-256 of the whole zip is the package's identity (what a server advertises and a launcher
pins). Layout:

```
faster-rolls-1.0.0.zip
  mod.toml                       at the root (not inside a folder)
  client/faster_rolls.dll        the client half (any layout works; client/ is the convention)
  server/libfaster_rolls.so      the server half, one library per platform
  server/faster_rolls.dll
  data/...                       data overlays
  README.md, LICENSE, ...        optional documents at the root
```

Rules, enforced by `poe_hook_mods::verify_package` (feature `package`, on by default; the loader DLL is built without
it) and `poe-mod verify` of the SDK:

- `mod.toml` at the root, valid, and the file named `<id>-<version>.zip` (a mismatch is refused); every file or folder
  the manifest names is in the zip (a DLL, library or `config_defaults` must be a file; `tables`/`opcodes` may be folders).
- Paths are relative and `/`-separated: no `..`, no empty parts, no backslash, drive colon or control character, no
  duplicates (compared case-insensitively), no symbolic links, no encrypted entries.
- Limits (configurable `Limits`): package 512 MiB, 4096 files, 1 GiB per file, 2 GiB unpacked, paths 240 bytes. Every entry is
  decompressed against its declared size and CRC (a stream longer than declared is refused).
- The `.sha256` sidecar is required and must equal the zip's hash.
- Warnings, not refusals: unknown manifest keys, no `game.versions`, a server library for one platform only.

`poe-mod pack` writes the package **reproducibly**: entries sorted by path, one fixed timestamp (1980-01-01), fixed
permissions, Deflate; the same inputs give the same bytes (with the same tool version), so the hash is stable.
A launcher installing a `both` package takes the client half and may leave `server/` out; the server serves the whole zip.

## The loader

The loader runs once per process, on the loader's start-up thread after the debug core is up. It never throws the
client off: every failure is logged and the mod is skipped.

1. **Official mode, or a read-only latch that is already set: nothing loads and nothing is read** from
   `poe-hook-mods/` (not even `state.toml`). One line `mods: official mode is read-only: no mod is loaded`.
   The latch can also come on later (the client connects to an untrusted server): mods that send, alter or inject
   anything must watch `HookApi::read_only` and stop.
2. No `poe-hook-mods/state.toml`: no mod is enabled, nothing else happens. Otherwise the signature table is
   resolved for the mods (about 0.3 s, only when mods exist) **before the debug core starts**, because the core hooks
   function starts and a table resolved afterwards would no longer find them. `sig_addr` therefore answers about the
   unhooked image.
3. `state.toml` is read in order. A broken `state.toml` loads no mod. For every id: valid id, readable and valid
   `mod.toml`, folder name equal to `id`, **a client half** (a `side = "server"` mod is skipped with
   `server-only mod ...`; the server half of a `both` mod is ignored), the ABI check, the entry DLL file exists. A mod that fails is skipped with
   its reason; **its DLL is never mapped**.
4. For every remaining mod, in order: dependencies must have loaded (earlier) in a satisfying version and no loaded
   mod may conflict with it (a mod whose dependency was skipped or failed is skipped too); then the DLL is mapped
   (`LoadLibraryExW`, `LOAD_WITH_ALTERED_SEARCH_PATH`, so its own DLLs next to it resolve), the optional
   `poe_mod_abi_version` export is compared, and `poe_mod_init` is called. A DLL that does not map, lacks
   `poe_mod_init`, reports another ABI or returns non-zero is unmapped again and skipped.
5. Mods stay loaded for the life of the process; `poe_mod_shutdown` is not called in ABI 1.

Log lines (in `poe-hook.log`, target `poe_hook::mods`; a mod's own lines carry the target `mod:<id>`):

```
mods: signature table 0.5.5e resolved in 190 ms (verified build)
mods: loaded sample-mod 0.1.0 (3 ms)
mods: skipped some-mod: built for mod ABI 2, this loader offers 1 (update poe-hook)
mods: skipped srv-mod: server-only mod (side = "server"): it has no client half, install it into the server's mods folder
mods: 1 of 2 enabled loaded, 1 skipped
```

## The mod ABI

Defined in the dependency-free crate `poe-hook-mod-api` (`poe-hook-mod-api/src/lib.rs`), which a Rust mod depends on
(any language works: it is a plain C ABI). Only `#[repr(C)]` data and `extern "C"` functions cross it.

**Version**: `HOOK_API_VERSION = 1` (the `game.hook_api` of the manifest; the launcher's `HOOK_API` is the same
number). It changes whenever a field or function below changes meaning, moves or is removed; appending fields at the
end of `HookApi` does not need a bump (a mod reads `HookApi::size` before it uses a later field). The loader offers
exactly its own version: a mod built for a **newer** one is refused ("update poe-hook"), one built for an **older**
one too ("rebuild the mod"), and a mod with an entry DLL that states none is refused. The manifest is checked before
the DLL is mapped; the optional export `poe_mod_abi_version` is checked right after.

**Exports of the mod DLL** (C calling convention):

| Export | Signature | |
|---|---|---|
| `poe_mod_init` | `int32_t poe_mod_init(const HookApi *api)` | required; 0 = started. Anything else: the loader logs it, unmaps the DLL and skips the mod, so it must have undone what it did. |
| `poe_mod_abi_version` | `uint32_t poe_mod_abi_version(void)` | optional; must return `HOOK_API_VERSION`. |

**`HookApi`** (one instance per mod, valid for the whole process; layout pinned by a test, 144 bytes on x64):

| Field | |
|---|---|
| `abi_version: u32`, `size: u32` | the loader's `HOOK_API_VERSION` and `size_of::<HookApi>()` |
| `ctx: *const c_void` | pass as the first argument of `log` |
| `mod_id`, `mod_dir`, `exe_dir`: `Str` | the mod's id, its folder, the game folder |
| `game_version`, `build_revision`: `Str` | `0.5.5e` and `323943` of the signature table that matched (empty: no usable table) |
| `build_verified: u32` | 1: the exe is exactly the build the table was made for; 0: unknown build, addresses are candidates only |
| `log(ctx, level, message: Str)` | one record in `poe-hook.log` and the overlay's Log tab, target `mod:<id>`; `level` 1..5 = error..trace |
| `read_only() -> bool` | the read-only latch |
| `sig_addr(name: Str) -> usize` | runtime address of a signature of `signatures/<version>.toml`; 0 if unknown or unresolved |
| `feature_ok(feature: Str) -> bool` | every signature and field of that table feature resolved |
| `field(name: Str, out: *mut usize) -> bool` | a resolved struct offset of the table |

`Str` is borrowed UTF-8 (`ptr`, `len`), valid for the call only (the strings inside `HookApi` live forever). The
Rust crate adds safe helpers (`api.info("...")`, `api.game_version()`, `api.sig_addr("...")`).

This is the **client** ABI (`HOOK_API_VERSION`, `game.hook_api`/`client.hook_api`). The server has its own, separately
versioned ABI (`SERVER_API_VERSION`, `server.server_api`) in the SDK's `poe-mod-api` crate; the two never share a
number or a struct.

The API deliberately offers nothing that writes to the game: a mod that hooks or patches code does that itself with
the addresses it got and is responsible for the read-only latch.

## Sample mod

`examples/sample-mod/` (package `poe-hook-sample-mod`, `sample_mod.dll`) logs `hello`, the game build and the state of
a signature through this ABI. `cargo xtask build-dll` builds it with the DLLs; `cargo xtask deploy-mod` (or
`deploy-client --sample-mod`) installs and enables it in `GameFiles/poe-hook-mods/sample-mod/`; the next client start
logs, for example:

```
[mod:sample-mod] hello from sample-mod 0.1.0: game build 0.5.5e (revision 323943, table verified), read_only=false
```

## Tests

`cargo test` in this repository covers the manifest parser (v1 compatibility, every v2 key and `side` rule, invalid
cases, a v1-only parser refusing v2), `state.toml`, the load plan (order, skipping, a server-only mod refused, a `both`
mod loading only its client half, official mode), the ABI checks, the dependency/conflict set across sides, package
verification (hash, names, paths, symlinks, limits, CRC), the install tooling (`poe-hook-mods`, `poe-hook-mod-api`,
`poe-hook-deploy`), and that the sample mod's manifest is valid for this loader.

## Open points

- `[data]` / `[client]` tables, opcodes and config defaults are parsed and validated but not applied by the loader yet.
- Hooks and packet observers are not part of ABI 1 (mods use `sig_addr` and their own hooks); they are added as
  appended fields or a new major.
- `poe_mod_shutdown` and unloading mods (needed for hot-reloading a mod) are not implemented (never planned for the server).
- Signatures (ed25519 by the author) are not specified; the package identity is the SHA-256 only.
- The launcher still has its own v1 parser (it accepts a DLL mod without `game.hook_api` and refuses v2); it moves to the
  shared parser in the mod-sync work package, which also makes it show a `side` badge.
