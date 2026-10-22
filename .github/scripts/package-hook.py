#!/usr/bin/env python3
"""Stages and archives a client hook release (used by .github/workflows/release.yml, runnable
locally to check a package).

    package-hook.py <hook version> <dll dir> <out dir>

<dll dir> holds the built poe_hook.dll and poe_hook_core.dll (for example
target/x86_64-pc-windows-msvc/release). The package is a zip with one top folder:

    poe_hook.dll  poe_hook_core.dll  signatures/<game version>.toml  LICENSE  NOTICE  README.txt
    release.json

release.json (read by the launcher, specification: docs/releasing.md):
    schema, name, hook_version, game_versions (one per signatures/<v>.toml), mod_abi
    (HOOK_API_VERSION of poe-hook-mod-api), platform, arch, commit, and `files`: path, size and
    SHA-256 of every other file in the package.

Writes <out dir>/<name>.zip and <name>.sha256 (the line `sha256sum` prints, so `sha256sum -c`
verifies it). Game versions are joined with `_` in the file name.
"""
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

DLLS = ["poe_hook.dll", "poe_hook_core.dll"]
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")
GAME_RE = re.compile(r"^[0-9][0-9A-Za-z.]*$")
README = """\
Poe2ClientHook {version} for Path of Exile 2 client {games}

poe_hook.dll       the loader, installed as the game's version.dll
poe_hook_core.dll  the features and the debug overlay
signatures/        the signature tables the DLLs were built with (they are also compiled in)
release.json       version, supported game versions, mod ABI and the SHA-256 of every file

The Poe2 launcher downloads, verifies and deploys this package for you. By hand:
cargo xtask deploy-client in Poe2ModdingProject, or copy poe_hook.dll to the game folder as
version.dll next to poe_hook_core.dll and poe-hook.toml (see docs/guides/setup.md there).
Official servers: read-only observation only (docs/guides/official-mode.md there).
"""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    version, dll_dir, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    root = Path(__file__).resolve().parents[2]
    if not VERSION_RE.match(version):
        print(f"'{version}' is not <major>.<minor>.<patch>[-suffix]", file=sys.stderr)
        return 1
    games = sorted(p.stem for p in (root / "signatures").glob("*.toml"))
    if not games or not all(GAME_RE.match(g) for g in games):
        print("signatures/ has no usable <game version>.toml", file=sys.stderr)
        return 1
    api = re.search(
        r"pub const HOOK_API_VERSION: u32 = (\d+);",
        (root / "poe-hook-mod-api/src/lib.rs").read_text(),
    )
    if not api:
        print("HOOK_API_VERSION not found in poe-hook-mod-api", file=sys.stderr)
        return 1
    for d in DLLS:
        if not (dll_dir / d).is_file():
            print(f"{dll_dir / d} not found", file=sys.stderr)
            return 1

    name = f"poe-hook-v{version}-game-{'_'.join(games)}-windows-x86_64"
    entries: dict[str, bytes | Path] = {}
    for d in DLLS:
        entries[d] = dll_dir / d
    for g in games:
        entries[f"signatures/{g}.toml"] = root / "signatures" / f"{g}.toml"
    for extra in ("LICENSE", "NOTICE"):
        if (root / extra).is_file():
            entries[extra] = root / extra
    entries["README.txt"] = README.format(version=version, games=", ".join(games)).encode()

    files = []
    for rel in sorted(entries):
        src = entries[rel]
        data = src if isinstance(src, bytes) else src.read_bytes()
        files.append({"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    commit = os.environ.get("GITHUB_SHA", "unknown")
    release = {
        "schema": 1,
        "name": name,
        "hook_version": version,
        "game_versions": games,
        "mod_abi": int(api.group(1)),
        "platform": "windows",
        "arch": "x86_64",
        "commit": commit,
        "files": files,
    }

    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"{name}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        def add(rel: str, data: bytes) -> None:
            info = zipfile.ZipInfo(f"{name}/{rel}", date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)

        for rel in sorted(entries):
            src = entries[rel]
            add(rel, src if isinstance(src, bytes) else src.read_bytes())
        add("release.json", (json.dumps(release, indent=2) + "\n").encode())
    digest = sha256(archive)
    (out / f"{name}.sha256").write_text(f"{digest}  {archive.name}\n")
    print(archive)
    print(f"{digest}  {archive.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
