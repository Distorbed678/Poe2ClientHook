# Mod manifest (`mod.toml`)

Status: **specification only**. No loader reads this yet. The DLL loader (`poe-hook`) and the launcher are meant to
agree on this one format, so it is fixed here first.

A mod is a folder with a `mod.toml` at its root. Mods are installed into the hook's `mods/` directory next to
`PathOfExileSteam.exe` (`<game dir>/poe-hook-mods/<id>/`), never into the game files themselves. The launcher installs,
enables, disables and orders mods; the loader reads the same folders.

```
poe-hook-mods/
  my-mod/
    mod.toml
    my_mod.dll          entry DLL (optional)
    data/               data files (optional)
```

## Format

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
# on others unless the user overrides; the loader logs a warning.
versions = ["0.5.5e"]
# Hook API the mod is built against (see "Entry DLL"); the loader refuses a newer major.
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
# A DLL loaded into the client process, relative to the mod folder. Exports (C ABI):
#   poe_mod_init(api: *const HookApi) -> i32   (0 = ok)
#   poe_mod_shutdown()                          (optional)
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

## Rules

- `id`, `name`, `version` and `manifest_version` are required; unknown keys are ignored (and logged by the launcher), so
  newer manifests degrade gracefully.
- A mod needs at least one of `[entry] dll` or `[data]` entries.
- `version` and `dependencies` use semver. `game.versions` is compared as a string against the client version.
- Load order is: topological order of `dependencies` and `load.after/before`, ties broken by id. A cycle disables the
  mods involved and is reported.
- Enabled mods and their order are stored by the launcher/loader in `poe-hook-mods/state.toml`
  (`enabled = ["id", ...]`, in load order); the manifest itself is never modified.
- Mods must not touch the game files, and must respect the hook's mode: in `official` mode the loader loads no mod DLLs
  (read-only observation only).

## Open points

- The `HookApi` struct handed to `poe_mod_init` (logging, config, hook registration, packet observers) lives in
  `poe-hook-shared` and is not defined yet.
- Packaging (a zip with the folder at its root) and signature/hash fields for distribution are not specified.
