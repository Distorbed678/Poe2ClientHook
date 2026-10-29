# Releasing the client hook

How a release of the DLLs is made and what is in it. The Poe2 launcher downloads these releases ("Client hook"), so a user needs neither a Rust toolchain nor cargo-xwin.

## Cutting a release

1. Pick the version. The DLLs report `[workspace.package] version` of `Cargo.toml`; the workflow refuses a tag that disagrees. Bump it (and `Cargo.lock`: run `cargo build`), commit and push to `main`; CI must be green.
2. Tag the commit and push the tag:
   ```sh
   git tag hook-v0.2.0
   git push origin hook-v0.2.0
   ```
   The tag is `hook-v<major>.<minor>.<patch>`, optionally with a suffix (`hook-v0.3.0-rc1`; a suffix makes it a pre-release on GitHub and the launcher prefers any stable release over it).
3. Watch the run of [`.github/workflows/release.yml`](../.github/workflows/release.yml) ("Release hook"). When it is green the release `Client hook <version> (game <game versions>)` has the zip, its `.sha256` and `SHA256SUMS`, and notes made from the commits since the previous `hook-v*` tag.

A failed run can be re-run from the Actions page; if the release exists the files are replaced (`gh release upload --clobber`). To try the build without a release, start the workflow by hand (Actions, "Release hook", Run workflow): it builds and packages everything and keeps the package as a workflow artifact for 14 days; the version is then `<crate version>-dev.<commit>`.

## What the workflow does

| Job | |
|---|---|
| `version` | derives the version from the tag and checks it against `Cargo.toml` |
| `build` (`windows-latest`) | plain checkout with `submodules: recursive` (the nested Poe2Protocol), `cargo build --release --locked -p poe-hook -p poe-hook-core --target x86_64-pc-windows-msvc` with the MSVC toolchain the runner has, `cargo test -p poe-hook-shared`; uploads the two DLLs |
| `package` (`ubuntu-latest`) | [`.github/scripts/package-hook.py`](../.github/scripts/package-hook.py) makes the zip, the `.sha256` and `SHA256SUMS` and checks them |
| `release` (tags only) | creates (or updates) the GitHub release with `gh`; no secrets, only the workflow's `GITHUB_TOKEN` with `contents: write` for this job |

`actionlint` (`third_party/actionlint/actionlint` in Poe2ModdingProject) checks the workflow syntax. The package script can be run on any machine with Python 3: `.github/scripts/package-hook.py 0.2.0 <folder with the two DLLs> <out folder>` (the DLLs from `cargo xtask build-dll` in Poe2ModdingProject work).

## The package

`poe-hook-v<version>-game-<game versions>-windows-x86_64.zip`, with `.sha256` (the line `sha256sum` prints, so `sha256sum -c` verifies it) next to it. The game versions are the `signatures/<game version>.toml` tables shipped, joined with `_` (`game-0.5.5e.hotfix1`, later e.g. `game-0.5.5e.hotfix1_0.6.0`). The DLLs are Windows binaries whatever system the game is played on, hence no other platform.

One top folder `poe-hook-v<version>-game-<...>-windows-x86_64/` with:

| File | |
|---|---|
| `poe_hook.dll` | the loader, installed as the game's `version.dll` |
| `poe_hook_core.dll` | features and the overlay |
| `signatures/<game version>.toml` | the tables the DLLs were built with (also compiled in; here for reference) |
| `LICENSE`, `NOTICE`, `README.txt` | |
| `release.json` | below |

`release.json` (schema 1) is what the launcher reads:

```json
{
  "schema": 1,
  "name": "poe-hook-v0.5.0-game-0.5.5e.hotfix1-windows-x86_64",
  "hook_version": "0.2.0",
  "game_versions": ["0.5.5e.hotfix1"],
  "mod_abi": 1,
  "platform": "windows",
  "arch": "x86_64",
  "commit": "<git sha>",
  "files": [{"path": "poe_hook.dll", "size": 123, "sha256": "..."}]
}
```

`mod_abi` is `HOOK_API_VERSION` of `poe-hook-mod-api` (the version mods are checked against, [mod-manifest.md](mod-manifest.md)); `files` lists every file of the package except `release.json` itself.

### What the launcher checks

1. The archive against the release's `.sha256` (and the size the release states), before anything is unpacked.
2. The zip: no path outside the folder, no links, bounded entry count and size.
3. `release.json`: schema 1, `windows`/`x86_64`, a version, supported game versions, both DLLs listed, only safe relative paths.
4. Every listed file exists with the listed size and SHA-256, **and no unlisted file is in the package**.
5. The package supports the launcher's selected game version (Official (read-only) is matched against the newest private version, the same DLLs run in official mode).
6. Again right before each Play: the installed files still match `release.json`.

A package that fails any check is deleted and nothing is installed. The checksums protect against corrupted downloads and a swapped asset; nothing signs the DLLs.

## Adding a game version

Add `signatures/<version>.toml` (generated, see Poe2ModdingProject `docs/re/update-compatibility.md`) and the version to the main project; the next release then lists both game versions in its name and `release.json`, and the launcher picks it for either. Keep the old table as long as the old build should still work.
