//! The mod package: what a mod is distributed as, and the check every program that receives
//! one runs (the server before it serves or loads it, the launcher before it installs it, the
//! SDK's `poe-mod verify`). Spec: `docs/mod-manifest.md`, "Package".
//!
//! A package is `<id>-<version>.zip` plus a sidecar `<id>-<version>.zip.sha256` in the
//! `sha256sum` format (`<64 hex>  <file name>`). The zip has `mod.toml` at its root and the
//! files it names next to it (by convention `client/`, `server/` and `data/`); the SHA-256 of
//! the whole zip is the package's identity. Packing is done by `poe-mod pack` of the SDK
//! (reproducible: sorted entries, fixed timestamps and permissions); this module only checks.

use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

use crate::{MANIFEST_FILE, Manifest, Platform, parse_manifest};

/// File extension of a package.
pub const PACKAGE_EXTENSION: &str = "zip";

/// `<id>-<version>.zip`.
pub fn package_file_name(id: &str, version: &str) -> String {
    format!("{id}-{version}.{PACKAGE_EXTENSION}")
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The text of a `.sha256` sidecar for `file_name`.
pub fn sha256_file_text(hash: &str, file_name: &str) -> String {
    format!("{hash}  {file_name}\n")
}

/// Reads a `.sha256` sidecar: the hash and, when present, the file name it names. Accepts the
/// `sha256sum` text format (`<hash>  <name>` or `<hash> *<name>`) and a bare hash.
pub fn parse_sha256_file(text: &str) -> Result<(String, Option<String>), String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or("the .sha256 file is empty")?;
    let (hash, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let hash = hash.to_ascii_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "the .sha256 file does not start with a SHA-256 (64 hex digits): {hash:?}"
        ));
    }
    let name = rest.trim().trim_start_matches('*').trim();
    Ok((hash, (!name.is_empty()).then(|| name.to_owned())))
}

/// Size limits of the check. All are bounds on untrusted input, not on legitimate mods.
#[derive(Debug, Clone)]
pub struct Limits {
    /// The zip itself.
    pub max_package_bytes: u64,
    /// Files in the zip.
    pub max_files: usize,
    /// One file, unpacked.
    pub max_file_bytes: u64,
    /// All files, unpacked.
    pub max_unpacked_bytes: u64,
    /// One path, in bytes.
    pub max_path_bytes: usize,
    /// `mod.toml`.
    pub max_manifest_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_package_bytes: 512 << 20,
            max_files: 4096,
            max_file_bytes: 1 << 30,
            max_unpacked_bytes: 2 << 30,
            max_path_bytes: 240,
            max_manifest_bytes: 64 << 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFile {
    /// Path inside the zip, `/`-separated.
    pub path: String,
    /// Unpacked size.
    pub size: u64,
}

/// What a package that passed [`verify_package`] contains.
#[derive(Debug, Clone)]
pub struct PackageReport {
    pub manifest: Manifest,
    pub unknown_keys: Vec<String>,
    /// SHA-256 of the zip.
    pub sha256: String,
    /// Size of the zip.
    pub size: u64,
    /// Every file, sorted by path.
    pub files: Vec<PackageFile>,
    /// Findings that do not refuse the package.
    pub warnings: Vec<String>,
}

/// Checks `<id>-<version>.zip` on disk against its `.sha256` sidecar (required, next to it as
/// `<zip>.sha256`) and the rules of [`verify_package_bytes`].
pub fn verify_package(zip: &Path, limits: &Limits) -> Result<PackageReport, Vec<String>> {
    let file_name = zip.file_name().and_then(|n| n.to_str()).map(str::to_owned);
    let meta =
        std::fs::metadata(zip).map_err(|e| vec![format!("cannot read {}: {e}", zip.display())])?;
    if meta.len() > limits.max_package_bytes {
        return Err(vec![format!(
            "the package is {} bytes, more than the limit of {}",
            meta.len(),
            limits.max_package_bytes
        )]);
    }
    let bytes =
        std::fs::read(zip).map_err(|e| vec![format!("cannot read {}: {e}", zip.display())])?;
    let mut sidecar = zip.as_os_str().to_owned();
    sidecar.push(".sha256");
    let sidecar = std::path::PathBuf::from(sidecar);
    let text = std::fs::read_to_string(&sidecar).map_err(|e| {
        vec![format!(
            "the package needs its checksum file {}: {e}",
            sidecar.display()
        )]
    })?;
    let (hash, named) = parse_sha256_file(&text).map_err(|e| vec![e])?;
    if let (Some(named), Some(file)) = (&named, &file_name)
        && named != file
    {
        return Err(vec![format!(
            "the .sha256 file is for {named:?}, not {file:?}"
        )]);
    }
    verify_package_bytes(&bytes, file_name.as_deref(), Some(&hash), limits)
}

/// Checks a package held in memory. `file_name`, when given, must be `<id>-<version>.zip` of
/// the manifest; `expected_sha256` (lower-case hex) must equal the zip's hash.
///
/// Refused: a hash mismatch; a path that is absolute, has `..`, a backslash or a drive colon,
/// is a symlink, is encrypted, repeats (also case-insensitively), or exceeds a limit; a file
/// whose unpacked size or CRC disagrees with the zip; no `mod.toml` at the root or an invalid
/// one; a manifest that names a file the zip does not contain.
pub fn verify_package_bytes(
    bytes: &[u8],
    file_name: Option<&str>,
    expected_sha256: Option<&str>,
    limits: &Limits,
) -> Result<PackageReport, Vec<String>> {
    if bytes.len() as u64 > limits.max_package_bytes {
        return Err(vec![format!(
            "the package is {} bytes, more than the limit of {}",
            bytes.len(),
            limits.max_package_bytes
        )]);
    }
    let sha256 = sha256_hex(bytes);
    if let Some(want) = expected_sha256
        && !want.eq_ignore_ascii_case(&sha256)
    {
        return Err(vec![format!(
            "SHA-256 mismatch: the package hashes to {sha256}, expected {}",
            want.to_ascii_lowercase()
        )]);
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| vec![format!("not a readable zip: {e}")])?;
    if archive.len() > limits.max_files {
        return Err(vec![format!(
            "{} entries, more than the limit of {}",
            archive.len(),
            limits.max_files
        )]);
    }

    let mut errors: Vec<String> = Vec::new();
    let mut files: Vec<PackageFile> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut manifest_text: Option<String> = None;
    let mut unpacked: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("entry {i}: {e}"));
                continue;
            }
        };
        let name = entry.name().to_owned();
        if entry.is_dir() {
            if let Err(why) = check_entry_path(name.trim_end_matches('/'), limits) {
                errors.push(format!("{name:?}: {why}"));
            }
            continue;
        }
        if let Err(why) = check_entry_path(&name, limits) {
            errors.push(format!("{name:?}: {why}"));
            continue;
        }
        if entry.encrypted() {
            errors.push(format!("{name:?}: encrypted entries are not allowed"));
            continue;
        }
        if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            errors.push(format!("{name:?}: symbolic links are not allowed"));
            continue;
        }
        if !seen.insert(name.to_lowercase()) {
            errors.push(format!(
                "{name:?}: the path appears twice (paths compare case-insensitively)"
            ));
            continue;
        }
        let declared = entry.size();
        if declared > limits.max_file_bytes {
            errors.push(format!(
                "{name:?}: {declared} bytes unpacked, more than the limit of {}",
                limits.max_file_bytes
            ));
            continue;
        }
        unpacked = unpacked.saturating_add(declared);
        if unpacked > limits.max_unpacked_bytes {
            errors.push(format!(
                "more than {} bytes unpacked in total",
                limits.max_unpacked_bytes
            ));
            break;
        }
        // Read it fully: the CRC is checked at the end of the stream, and a stream that is
        // longer than the zip declares is a zip bomb.
        let is_manifest = name == MANIFEST_FILE;
        if is_manifest && declared > limits.max_manifest_bytes {
            errors.push(format!(
                "{MANIFEST_FILE} is larger than {} bytes",
                limits.max_manifest_bytes
            ));
            continue;
        }
        let mut sink = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        let mut read: u64 = 0;
        let mut failed = None;
        loop {
            match (&mut entry).take(declared + 1 - read).read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    read += n as u64;
                    if is_manifest {
                        sink.extend_from_slice(&buf[..n]);
                    }
                }
                Err(e) => {
                    failed = Some(e.to_string());
                    break;
                }
            }
        }
        if let Some(e) = failed {
            errors.push(format!("{name:?}: {e}"));
            continue;
        }
        if read != declared {
            errors.push(format!(
                "{name:?}: unpacks to {read} bytes, the zip says {declared}"
            ));
            continue;
        }
        if is_manifest {
            match String::from_utf8(sink) {
                Ok(t) => manifest_text = Some(t),
                Err(_) => errors.push(format!("{MANIFEST_FILE} is not UTF-8")),
            }
        }
        files.push(PackageFile {
            path: name,
            size: declared,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let Some(text) = manifest_text else {
        if errors.is_empty() {
            errors.push(format!(
                "{MANIFEST_FILE} is missing at the root of the package"
            ));
        }
        return Err(errors);
    };
    let parsed = match parse_manifest(&text) {
        Ok(p) => p,
        Err(e) => {
            errors.extend(e.into_iter().map(|m| format!("{MANIFEST_FILE}: {m}")));
            return Err(errors);
        }
    };
    let m = &parsed.manifest;
    if let Some(name) = file_name {
        let want = package_file_name(&m.id, &m.version);
        if name != want {
            errors.push(format!(
                "the file is named {name:?}, but the manifest says {want:?} (<id>-<version>.zip)"
            ));
        }
    }
    for rel in m.referenced_paths() {
        let as_file = files.iter().any(|f| f.path == rel);
        let prefix = format!("{rel}/");
        let as_dir = files.iter().any(|f| f.path.starts_with(&prefix));
        let must_be_file = [
            m.entry_dll.as_deref(),
            m.server_linux.as_deref(),
            m.server_windows.as_deref(),
            m.config_defaults.as_deref(),
            m.server_config_defaults.as_deref(),
        ]
        .contains(&Some(rel));
        if !(as_file || (!must_be_file && as_dir)) {
            errors.push(format!(
                "{MANIFEST_FILE} names {rel:?}, which the package does not contain"
            ));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut warnings: Vec<String> = parsed
        .unknown_keys
        .iter()
        .map(|k| format!("unknown key {k} in {MANIFEST_FILE}"))
        .collect();
    if m.has_server_library() {
        for p in Platform::ALL {
            if m.server_library(p).is_none() {
                warnings.push(format!(
                    "no server library for {}: a {} server cannot load this mod",
                    p.as_str(),
                    p.as_str()
                ));
            }
        }
    }
    if m.game_versions.is_empty() {
        warnings.push(
            "game.versions is empty: the mod does not say which client it was made for".into(),
        );
    }
    Ok(PackageReport {
        manifest: parsed.manifest,
        unknown_keys: parsed.unknown_keys,
        sha256,
        size: bytes.len() as u64,
        files,
        warnings,
    })
}

/// A path inside a package: relative, `/`-separated, nothing that leaves the folder or means
/// something special on Windows.
fn check_entry_path(p: &str, limits: &Limits) -> Result<(), String> {
    if p.is_empty() {
        return Err("empty path".into());
    }
    if p.len() > limits.max_path_bytes {
        return Err(format!("path longer than {} bytes", limits.max_path_bytes));
    }
    if p.contains(['\\', ':']) || p.chars().any(char::is_control) {
        return Err("a path may not contain backslashes, colons or control characters".into());
    }
    let path = Path::new(p);
    if path.is_absolute()
        || p.split('/').any(|s| s.is_empty() || s == "." || s == "..")
        || !path.components().all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("a path must be relative and may not contain .. or empty parts".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    const MANIFEST: &str = r#"manifest_version = 2
id = "hello"
name = "Hello"
version = "1.0.0"
side = "both"

[game]
versions = ["0.5.5e.hotfix1"]

[client]
dll = "client/hello.dll"
hook_api = 1

[server]
server_api = 1

[server.library]
linux = "server/libhello.so"
windows = "server/hello.dll"

[[commands]]
name = "hello"
reply = "hi"
"#;

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn good() -> Vec<u8> {
        zip_of(&[
            ("mod.toml", MANIFEST.as_bytes()),
            ("client/hello.dll", b"MZ"),
            ("server/libhello.so", b"\x7fELF"),
            ("server/hello.dll", b"MZ"),
        ])
    }

    fn check(bytes: &[u8]) -> Result<PackageReport, Vec<String>> {
        verify_package_bytes(bytes, Some("hello-1.0.0.zip"), None, &Limits::default())
    }

    fn err(bytes: &[u8]) -> String {
        check(bytes).unwrap_err().join("\n")
    }

    #[test]
    fn a_good_package_verifies_and_reports_its_contents() {
        let bytes = good();
        let r = verify_package_bytes(
            &bytes,
            Some("hello-1.0.0.zip"),
            Some(&sha256_hex(&bytes)),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(r.manifest.id, "hello");
        assert_eq!(r.sha256.len(), 64);
        assert_eq!(r.size, bytes.len() as u64);
        let paths: Vec<&str> = r.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "client/hello.dll",
                "mod.toml",
                "server/hello.dll",
                "server/libhello.so"
            ]
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    #[test]
    fn hash_name_and_manifest_are_checked() {
        let bytes = good();
        let e = verify_package_bytes(&bytes, None, Some(&"0".repeat(64)), &Limits::default())
            .unwrap_err()
            .join("\n");
        assert!(e.contains("SHA-256 mismatch"), "{e}");
        let e = verify_package_bytes(&bytes, Some("other-1.0.0.zip"), None, &Limits::default())
            .unwrap_err()
            .join("\n");
        assert!(e.contains("hello-1.0.0.zip"), "{e}");
        assert!(err(b"not a zip").contains("not a readable zip"));
        assert!(err(&zip_of(&[("client/hello.dll", b"MZ")])).contains("mod.toml is missing"));
        assert!(
            err(&zip_of(&[("mod.toml", b"id = [")]))
                .contains("mod.toml: mod.toml is not valid TOML")
        );
    }

    #[test]
    fn a_nested_manifest_is_not_a_root_manifest() {
        let bytes = zip_of(&[("hello/mod.toml", MANIFEST.as_bytes())]);
        assert!(err(&bytes).contains("mod.toml is missing at the root"));
    }

    #[test]
    fn every_file_the_manifest_names_must_exist() {
        let bytes = zip_of(&[
            ("mod.toml", MANIFEST.as_bytes()),
            ("client/hello.dll", b"MZ"),
            ("server/libhello.so", b"x"),
        ]);
        let e = err(&bytes);
        assert!(
            e.contains("\"server/hello.dll\", which the package does not contain"),
            "{e}"
        );
        assert!(!e.contains("libhello"), "{e}");
    }

    #[test]
    fn data_paths_may_be_folders() {
        let m = "manifest_version = 2\nid = \"hello\"\nname = \"H\"\nversion = \"1.0.0\"\nside = \"server\"\n[server]\ntables = [\"data/tables\"]\nconfig_defaults = \"data/d.toml\"\n";
        let ok = zip_of(&[
            ("mod.toml", m.as_bytes()),
            ("data/tables/a.datc64", b"1"),
            ("data/d.toml", b""),
        ]);
        assert!(check(&ok).is_ok());
        // An empty folder does not count, and config_defaults must be a file.
        let bad = zip_of(&[("mod.toml", m.as_bytes()), ("data/d.toml/x", b"1")]);
        let e = err(&bad);
        assert!(e.contains("\"data/tables\""), "{e}");
        assert!(e.contains("\"data/d.toml\""), "{e}");
    }

    #[test]
    fn dangerous_paths_are_refused() {
        for bad in [
            "../evil.dll",
            "a/../../evil.dll",
            "/abs/evil.dll",
            "a\\b.dll",
            "C:/x.dll",
            "a//b",
            "con\u{0}.dll",
        ] {
            let bytes = zip_of(&[("mod.toml", MANIFEST.as_bytes()), (bad, b"x")]);
            let e = check(&bytes).unwrap_err().join("\n");
            assert!(
                e.contains("path") || e.contains("relative"),
                "{bad:?} accepted: {e}"
            );
        }
    }

    #[test]
    fn duplicate_paths_are_refused_even_by_case() {
        let bytes = zip_of(&[
            ("mod.toml", MANIFEST.as_bytes()),
            ("client/hello.dll", b"MZ"),
            ("client/HELLO.dll", b"MZ"),
            ("server/libhello.so", b"x"),
            ("server/hello.dll", b"MZ"),
        ]);
        assert!(err(&bytes).contains("appears twice"));
    }

    #[test]
    fn symlinks_are_refused() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let o = SimpleFileOptions::default();
        w.start_file("mod.toml", o).unwrap();
        w.write_all(MANIFEST.as_bytes()).unwrap();
        w.add_symlink("client/hello.dll", "/etc/passwd", o).unwrap();
        let bytes = w.finish().unwrap().into_inner();
        assert!(err(&bytes).contains("symbolic links"));
    }

    #[test]
    fn limits_are_enforced() {
        let bytes = good();
        let tiny = Limits {
            max_files: 2,
            ..Limits::default()
        };
        assert!(
            verify_package_bytes(&bytes, None, None, &tiny).unwrap_err()[0].contains("entries")
        );
        let tiny = Limits {
            max_package_bytes: 10,
            ..Limits::default()
        };
        assert!(verify_package_bytes(&bytes, None, None, &tiny).unwrap_err()[0].contains("limit"));
        let tiny = Limits {
            max_file_bytes: 1,
            ..Limits::default()
        };
        assert!(
            verify_package_bytes(&bytes, None, None, &tiny)
                .unwrap_err()
                .join("\n")
                .contains("unpacked")
        );
        let tiny = Limits {
            max_unpacked_bytes: 100,
            ..Limits::default()
        };
        assert!(
            verify_package_bytes(&bytes, None, None, &tiny)
                .unwrap_err()
                .join("\n")
                .contains("in total")
        );
    }

    #[test]
    fn a_corrupted_entry_fails_its_crc() {
        // Stored data is easy to flip without breaking the zip structure.
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let o = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        w.start_file("mod.toml", o).unwrap();
        w.write_all(MANIFEST.as_bytes()).unwrap();
        let mut bytes = w.finish().unwrap().into_inner();
        let at = bytes
            .windows(5)
            .position(|w| w == b"hello")
            .expect("manifest text is stored verbatim");
        bytes[at] = b'j';
        let e = err(&bytes);
        assert!(
            e.to_lowercase().contains("checksum") || e.contains("crc"),
            "{e}"
        );
    }

    #[test]
    fn warnings_do_not_refuse() {
        let m = "manifest_version = 2\nid = \"hello\"\nname = \"H\"\nversion = \"1.0.0\"\nside = \"server\"\nodd = 1\n[server]\nserver_api = 1\n[server.library]\nlinux = \"server/libhello.so\"\n";
        let r = check(&zip_of(&[
            ("mod.toml", m.as_bytes()),
            ("server/libhello.so", b"x"),
        ]))
        .unwrap();
        let w = r.warnings.join("\n");
        assert!(w.contains("unknown key odd"), "{w}");
        assert!(w.contains("no server library for windows"), "{w}");
        assert!(w.contains("game.versions is empty"), "{w}");
    }

    #[test]
    fn sha256_sidecar_text_round_trips() {
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let text = sha256_file_text(&h, "hello-1.0.0.zip");
        assert_eq!(text, format!("{h}  hello-1.0.0.zip\n"));
        assert_eq!(
            parse_sha256_file(&text).unwrap(),
            (h.clone(), Some("hello-1.0.0.zip".into()))
        );
        assert_eq!(parse_sha256_file(&h).unwrap(), (h.clone(), None));
        assert_eq!(
            parse_sha256_file(&format!("{} *a.zip", h.to_uppercase())).unwrap(),
            (h, Some("a.zip".into()))
        );
        assert!(parse_sha256_file("").is_err());
        assert!(parse_sha256_file("xyz  a.zip").is_err());
    }

    #[test]
    fn verify_package_reads_the_sidecar() {
        let t = tempfile::tempdir().unwrap();
        let zip = t.path().join("hello-1.0.0.zip");
        let bytes = good();
        std::fs::write(&zip, &bytes).unwrap();
        // No sidecar: refused.
        let e = verify_package(&zip, &Limits::default())
            .unwrap_err()
            .join("\n");
        assert!(e.contains("checksum file"), "{e}");
        let side = t.path().join("hello-1.0.0.zip.sha256");
        std::fs::write(
            &side,
            sha256_file_text(&sha256_hex(&bytes), "hello-1.0.0.zip"),
        )
        .unwrap();
        assert!(verify_package(&zip, &Limits::default()).is_ok());
        // A sidecar for another file, and a wrong hash.
        std::fs::write(&side, sha256_file_text(&sha256_hex(&bytes), "other.zip")).unwrap();
        assert!(verify_package(&zip, &Limits::default()).unwrap_err()[0].contains("is for"));
        std::fs::write(&side, sha256_file_text(&"1".repeat(64), "hello-1.0.0.zip")).unwrap();
        assert!(verify_package(&zip, &Limits::default()).unwrap_err()[0].contains("mismatch"));
    }
}
