# Poe2ClientHook

The client side of [Poe2ModdingProject](https://github.com/Distorbed678/Poe2ModdingProject) (private repo; this repo is
its submodule `modules/client-hook`): DLLs injected into **Path of Exile 2 client 0.5.5e** through the `version.dll`
proxy, and the host-side library that deploys and launches them.

| Crate | Target | Role |
|---|---|---|
| `poe-hook` | `x86_64-pc-windows-msvc` cdylib | `version.dll`: proxy, permanent hooks (network guard, Vulkan, window) and the loader of the core |
| `poe-hook-core` | `x86_64-pc-windows-msvc` cdylib | `poe_hook_core.dll`: features and the in-game debug overlay; hot-reloadable while the game runs |
| `poe-hook-shared` | Windows | Config (`poe-hook.toml`), the loader <-> core ABI, guarded memory helpers, the signature table in a process (`sigs`, `offsets`), packet redaction rules (`redact`) |
| `poe-hook-mod-api` | host (pure Rust) | The mod ABI (`HookApi`, export names) a mod DLL builds against; no dependencies |
| `poe-hook-mods` | host (pure Rust) | Mod loader logic: `mod.toml`, `state.toml`, load plan, ABI check, official-mode refusal. The loader itself is `poe-hook/src/mods.rs` |
| `poe-hook-sig` | host (pure Rust) | The signature table matcher: patterns, PE reader, scanner, resolver. Used by the DLLs and by the host tools (`cargo xtask check-build`) |
| `poe-hook-deploy` | host (Linux/Windows) | Gateway list edit, `poe-hook.toml`, `steam_appid.txt`, DLL install/backup/revert, Proton launch, crash-dump moving |

`signatures/<version>.toml` is the **signature table**: every hook address, patch site and game struct offset the DLLs use, as byte patterns with the 0.5.5e values as checks (see below).

`protocol/` is Poe2Protocol as a nested submodule (`poe-hook-core` uses `poe-proto` from it, including the compiled-in
opcode tables `poe_proto::opcodes::v0_5_5e`).

The mod manifest format and the mod ABI (read by the launcher and by the DLL's mod loader, `poe-hook-mods/<id>/` plus `state.toml`; no mod loads in official mode) are specified in [docs/mod-manifest.md](docs/mod-manifest.md); `examples/sample-mod/` is a tiny mod (`cargo xtask deploy-mod` installs it in the main repository).
Behavior of the DLLs is documented in the main repository (`docs/architecture/client-dll.md`).

## Clone

```
git clone --recursive git@github.com:Distorbed678/Poe2ClientHook.git
# or, after a plain clone:  git submodule update --init --recursive
```

## Build and test

Host crates (a plain `cargo` command builds only `poe-hook-deploy`, `poe-hook-sig`, `poe-hook-mod-api` and `poe-hook-mods`):

```
cargo test
cargo fmt --all --check
cargo clippy --all-targets
```

The DLLs, for `x86_64-pc-windows-msvc`:

- On Windows: `cargo build --release -p poe-hook -p poe-hook-core -p poe-hook-sample-mod --target x86_64-pc-windows-msvc`
- On Linux with [cargo-xwin](https://github.com/rust-cross/cargo-xwin):
  `cargo xwin build --release -p poe-hook -p poe-hook-core -p poe-hook-sample-mod --target x86_64-pc-windows-msvc`
  (inside Poe2ModdingProject: `cargo xtask build-dll`).

Output: `target/x86_64-pc-windows-msvc/release/{poe_hook.dll,poe_hook_core.dll,sample_mod.dll}`. `poe_hook.dll` is installed as the game's
`version.dll`.

## Signature table

The DLLs have no fixed Ghidra addresses and no fixed struct offsets in code: `signatures/0.5.5e.toml` (85 signatures, 51
struct-offset fields) is embedded at build time (`include_str!`, so a table can never be older or newer than the code it
was made for), selected by the executable's PE timestamp and size (and checked with the build revision string
`323943`), and resolved **once** when a DLL loads. A signature that matches zero or several times, or whose address holds
other bytes, switches off the features that list it, with a log line naming it; nothing is hooked or patched on a guess,
and on an unknown build with the read-only latch on only the observers start. Format, rules and the list of what is
still literal: `docs/architecture/client-dll.md` in the main repository (section "Signature table").

```
# resolve the embedded table against an exe file and compare with the 0.5.5e values
cargo run --release -p poe-hook-sig --example resolve -- /path/to/PathOfExileSteam.exe [table.toml] [--quiet]
cargo test -p poe-hook-sig        # unit tests; tests/real_exe.rs also runs on ../../GameFiles/PathOfExileSteam.exe (or $POE_EXE) if present
```

`poe-hook-sig` has no Windows dependencies; other tools can depend on it by path (`poe_hook_sig::resolve_embedded`,
`poe_hook_sig::{Table, Image, resolve}`). The table is generated from a spec of Ghidra addresses by
`scripts/re/sig_gen.py` in the main repository.

## `poe-hook-deploy` API

Nothing in it knows a repository layout; every directory is a parameter.

```rust
use poe_hook_deploy::{deploy, deploy_core, revert, DeployOptions, GatewayEntry, Mode, launch::ProtonLaunch};

deploy(&DeployOptions {
    game_dir, dll_dir,                 // client folder; build output folder
    mode: Mode::Private,               // or Mode::Official (read-only, original gateway list)
    gateway: Some(GatewayEntry { region, display_name, host, port }),
    position_sync_port: Some(6112),
    dump_dir: Some(dumps),             // written to poe-hook.toml as a path the client can read (Z:\... under Wine)
    login_mode: LoginMode::Standalone, // `login_mode`; Mode::Official always writes "steam"
    trusted_servers: vec!["192.168.1.20:20481".into(), "192.168.1.20:6112".into()], // host:port, names resolved to IPv4; Official: empty
})?;
deploy_core(&game_dir, &dll_dir)?;     // only the core; a running client reloads it
revert(&game_dir)?;                    // restores gateway_list.txt, removes installed files

ProtonLaunch { steam_root, proton: "Proton - Experimental".into(), prefix_dir, game_dir,
               crash_dump_dir: Some(dir) }.launch()?;
```

Launcher auto-login (standalone client): `write_login_token(prefix_or_documents_dir, account, token: [u8; 32])`
writes the remember-me token file `Documents/My Games/Path of Exile 2/poe2_production_login.credentials` and sets
`[LOGIN] username=<account>` and `save_login=true` in `poe2_production_Config.ini` there. `write_login_token_with` takes
`LoginTokenFiles` (credentials/ini file names, section and key names) because `config.json` can override the file name
with `GGG_CREDENTIAL_FILE_NAME`; the default `poe2_production_login.credentials` is confirmed on disk. The client reads both files itself, so the DLL needs no code: with an empty password box, Login sends the token
(`0x0003`, `token_login = 1`). `login_token::parse_token_hex` reads 64 hex digits.

Also public: `resolve_trusted_servers`, `set_hook_key`, `hook_path`, `gateway::select_gateway_in_prefix`, `launch::quarantine_crash_dumps`,
`backup_once`, `install_file`.

## `poe-hook.toml`: login and trust

- `login_mode = "standalone" | "steam"` (default `standalone` in private mode; **always `steam` in official mode**, enforced
  by the deploy and again when the DLL reads the file). `standalone` makes the loader (`version.dll`, in `DllMain`) patch
  the client's `ClientPlatform_Detect` (`40 55 53` -> `31 C0 C3`, Ghidra `0x142196ec0` in 0.5.5e) so it shows the account-name and
  password screen and sends `0x0003`. The function is found by signature and its original bytes are verified first (another
  build, or a signature that does not match exactly once: patch skipped, error logged); an already cached platform value
  (`0x144717118`, guard `0x144717114` in 0.5.5e, also by signature) is reset to 0. Table entries: `client_platform_detect`,
  `standalone_patcher_run`, `platform_cache_guard`, `platform_cache_value`; byte logic: `poe-hook-shared/src/login.rs`.
- `trusted_servers = ["ip:port", "ip:*", "ip"]` (IPv4 literals; loopback is always trusted; empty in official mode).
  `poe_hook_shared::trust::is_trusted` is the one decision used by the network guard (refuse / latch), `Connection::external`
  (`= !trusted`), the crypto bypass and the overlay's `custom_server()`. A trusted server is neither refused by
  `block_external` nor latches read-only and gets the crypto bypass; every other remote stays read-only exactly as before.

## Rules

Never touch the Steam install or its Proton prefix; deploy only into a copy of the game files. Official servers are
read-only: in `official` mode the DLL only observes and logs.

License: MIT OR Apache-2.0.
