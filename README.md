# Poe2ClientHook

The client side of [Poe2ModdingProject](https://github.com/Distorbed678/Poe2ModdingProject) (private repo; this repo is
its submodule `modules/client-hook`): DLLs injected into **Path of Exile 2 client 0.5.5e** through the `version.dll`
proxy, and the host-side library that deploys and launches them.

| Crate | Target | Role |
|---|---|---|
| `poe-hook` | `x86_64-pc-windows-msvc` cdylib | `version.dll`: proxy, permanent hooks (network guard, Vulkan, window) and the loader of the core |
| `poe-hook-core` | `x86_64-pc-windows-msvc` cdylib | `poe_hook_core.dll`: features and the in-game debug overlay; hot-reloadable while the game runs |
| `poe-hook-shared` | Windows | Config (`poe-hook.toml`), the loader <-> core ABI, guarded memory helpers |
| `poe-hook-deploy` | host (Linux/Windows) | Gateway list edit, `poe-hook.toml`, `steam_appid.txt`, DLL install/backup/revert, Proton launch, crash-dump moving |

`protocol/` is Poe2Protocol as a nested submodule (`poe-hook-core` uses `poe-proto` from it, including the compiled-in
opcode tables `poe_proto::opcodes::v0_5_5e`).

The mod manifest format (read by the launcher; the DLL loader is planned) is specified in [docs/mod-manifest.md](docs/mod-manifest.md).
Behavior of the DLLs is documented in the main repository (`docs/architecture/client-dll.md`).

## Clone

```
git clone --recursive git@github.com:Distorbed678/Poe2ClientHook.git
# or, after a plain clone:  git submodule update --init --recursive
```

## Build and test

Host crates (a plain `cargo` command builds only `poe-hook-deploy`):

```
cargo test
cargo fmt --all --check
cargo clippy --all-targets
```

The DLLs, for `x86_64-pc-windows-msvc`:

- On Windows: `cargo build --release -p poe-hook -p poe-hook-core --target x86_64-pc-windows-msvc`
- On Linux with [cargo-xwin](https://github.com/rust-cross/cargo-xwin):
  `cargo xwin build --release -p poe-hook -p poe-hook-core --target x86_64-pc-windows-msvc`
  (inside Poe2ModdingProject: `cargo xtask build-dll`).

Output: `target/x86_64-pc-windows-msvc/release/{poe_hook.dll,poe_hook_core.dll}`. `poe_hook.dll` is installed as the game's
`version.dll`.

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
  the client's `ClientPlatform_Detect` (`40 55 53` -> `31 C0 C3`, Ghidra `0x142196ec0`) so it shows the account-name and
  password screen and sends `0x0003`. The original bytes are verified first (another build: patch skipped, error logged);
  an already cached platform value (`0x144717118`, guard `0x144717114`) is reset to 0. Addresses: `poe-hook-shared/src/login.rs`.
- `trusted_servers = ["ip:port", "ip:*", "ip"]` (IPv4 literals; loopback is always trusted; empty in official mode).
  `poe_hook_shared::trust::is_trusted` is the one decision used by the network guard (refuse / latch), `Connection::external`
  (`= !trusted`), the crypto bypass and the overlay's `custom_server()`. A trusted server is neither refused by
  `block_external` nor latches read-only and gets the crypto bypass; every other remote stays read-only exactly as before.

## Rules

Never touch the Steam install or its Proton prefix; deploy only into a copy of the game files. Official servers are
read-only: in `official` mode the DLL only observes and logs.

License: MIT OR Apache-2.0.
