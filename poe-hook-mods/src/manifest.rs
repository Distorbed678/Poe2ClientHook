//! `mod.toml` (spec: `docs/mod-manifest.md`). Every problem is reported at once; unknown keys
//! are collected (and logged by the loader), never fatal, except in the server half
//! (`[server]`, `[[commands]]`), where a silent typo is worse than a refused mod.
//!
//! Two versions are read. **v1** is the client-only format the launcher and the loader have
//! always read. **v2** adds the mod's `side` (client, server or both), the `[client]` and
//! `[server]` sections and data-tier `[[commands]]`. v2 is additive: a v1 manifest parses to
//! the same client mod it always was, and the v1 spellings (`[entry]`, `[data]`,
//! `game.hook_api`) stay valid in v2 as the client half.
//!
//! **Fail closed.** `manifest_version` is checked first, and a parser that reads only v1
//! ([`parse_manifest_max`] with 1, which is what every loader and launcher shipped before this
//! one does) refuses any v2 manifest, so a server-only mod can never be mistaken for a client
//! mod. A mod that has to keep working with those old programs stays a v1 client mod.

use std::{
    collections::BTreeMap,
    path::{Component, Path},
};

use semver::{Version, VersionReq};

use crate::MANIFEST_VERSION;

/// Which program loads a mod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Side {
    /// The client hook (`poe-hook-mods/<id>/`). What a v1 manifest always is.
    #[default]
    Client,
    /// The server (`mods/<id>/`).
    Server,
    /// One package with both halves.
    Both,
}

impl Side {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Self::Client),
            "server" => Some(Self::Server),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Both => "both",
        }
    }

    pub fn includes_client(self) -> bool {
        matches!(self, Self::Client | Self::Both)
    }

    pub fn includes_server(self) -> bool {
        matches!(self, Self::Server | Self::Both)
    }
}

/// An operating system a server library is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Platform {
    Linux,
    Windows,
}

impl Platform {
    pub const ALL: [Platform; 2] = [Platform::Linux, Platform::Windows];

    /// The platform this program was built for (`None` elsewhere, e.g. macOS).
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(windows) {
            Some(Self::Windows)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }

    /// The file extension of a library of this platform, without the dot.
    pub fn library_extension(self) -> &'static str {
        match self {
            Self::Linux => "so",
            Self::Windows => "dll",
        }
    }
}

/// Who may run a data-tier command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommandRole {
    #[default]
    Player,
    Admin,
}

impl CommandRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Player => "player",
            Self::Admin => "admin",
        }
    }
}

/// One `[[commands]]` entry: a chat command (`!name`) without code. Exactly one of `reply` and
/// `alias` is set. The text may use `{player}` (the caller's character name) and `{args}` (the
/// rest of the line); the server substitutes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: String,
    pub help: String,
    /// A fixed text sent back to the caller.
    pub reply: Option<String>,
    /// Another command line to run as the caller (without the `!`).
    pub alias: Option<String>,
    pub role: CommandRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    /// The `manifest_version` the file was written for (1 or 2).
    pub manifest_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub authors: Vec<String>,
    pub license: String,
    pub homepage: String,
    /// `side` (always [`Side::Client`] for v1).
    pub side: Side,
    /// `[game] versions`; empty = not stated. Shared by both halves.
    pub game_versions: Vec<String>,
    pub after: Vec<String>,
    pub before: Vec<String>,
    pub conflicts: Vec<String>,
    /// id -> semver requirement text. A dependency is on the mod, whatever its side.
    pub dependencies: BTreeMap<String, String>,

    // Client half: `[client]`, or its v1 spellings `[entry]`, `[data]` and `game.hook_api`.
    /// The mod ABI the client DLL was built against (`hook_api`).
    pub hook_api: Option<u32>,
    /// The client DLL, relative to the mod folder.
    pub entry_dll: Option<String>,
    pub data_tables: Vec<String>,
    pub data_opcodes: Vec<String>,
    pub config_defaults: Option<String>,

    // Server half: `[server]` and `[[commands]]` (v2 only).
    /// The server mod ABI the server library was built against (`server_api`).
    pub server_api: Option<u32>,
    /// `[server.library] linux`, relative to the mod folder.
    pub server_linux: Option<String>,
    /// `[server.library] windows`, relative to the mod folder.
    pub server_windows: Option<String>,
    pub server_tables: Vec<String>,
    pub server_opcodes: Vec<String>,
    pub server_config_defaults: Option<String>,
    pub commands: Vec<CommandSpec>,
}

impl Manifest {
    /// Anything the client hook would load or apply.
    pub fn has_client_content(&self) -> bool {
        self.entry_dll.is_some()
            || !self.data_tables.is_empty()
            || !self.data_opcodes.is_empty()
            || self.config_defaults.is_some()
    }

    /// Anything the server would load or apply.
    pub fn has_server_content(&self) -> bool {
        self.server_linux.is_some()
            || self.server_windows.is_some()
            || !self.server_tables.is_empty()
            || !self.server_opcodes.is_empty()
            || self.server_config_defaults.is_some()
            || !self.commands.is_empty()
    }

    /// The server library for `platform`, relative to the mod folder.
    pub fn server_library(&self, platform: Platform) -> Option<&str> {
        match platform {
            Platform::Linux => self.server_linux.as_deref(),
            Platform::Windows => self.server_windows.as_deref(),
        }
    }

    /// Whether the mod has native server code at all.
    pub fn has_server_library(&self) -> bool {
        self.server_linux.is_some() || self.server_windows.is_some()
    }

    /// Every file or folder the manifest names, relative to the mod folder (for packing and
    /// package verification). Sorted, without duplicates.
    pub fn referenced_paths(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        v.extend(self.entry_dll.as_deref());
        v.extend(self.data_tables.iter().map(String::as_str));
        v.extend(self.data_opcodes.iter().map(String::as_str));
        v.extend(self.config_defaults.as_deref());
        v.extend(self.server_linux.as_deref());
        v.extend(self.server_windows.as_deref());
        v.extend(self.server_tables.iter().map(String::as_str));
        v.extend(self.server_opcodes.iter().map(String::as_str));
        v.extend(self.server_config_defaults.as_deref());
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// A parsed manifest plus its non-fatal findings.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub manifest: Manifest,
    pub unknown_keys: Vec<String>,
}

const KNOWN_TOP_V1: &[&str] = &[
    "manifest_version",
    "id",
    "name",
    "version",
    "description",
    "authors",
    "license",
    "homepage",
    "game",
    "load",
    "dependencies",
    "entry",
    "data",
];
/// Keys that exist from v2 on.
const TOP_V2_ONLY: &[&str] = &["side", "client", "server", "commands"];
const KNOWN_SECTIONS: &[(&str, &[&str])] = &[
    ("game", &["versions", "hook_api"]),
    ("load", &["after", "before", "conflicts"]),
    ("entry", &["dll"]),
    ("data", &["tables", "opcodes", "config_defaults"]),
];
const CLIENT_KEYS: &[&str] = &["dll", "hook_api", "tables", "opcodes", "config_defaults"];
const SERVER_KEYS: &[&str] = &[
    "server_api",
    "library",
    "tables",
    "opcodes",
    "config_defaults",
];
const COMMAND_KEYS: &[&str] = &["name", "help", "reply", "alias", "role"];

/// Length limits of data-tier commands.
const COMMAND_NAME_MAX: usize = 32;
const COMMAND_HELP_MAX: usize = 200;
const COMMAND_TEXT_MAX: usize = 1000;

/// `[a-z0-9][a-z0-9_-]{1,63}`
pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    (2..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// `[a-z][a-z0-9_-]{0,31}`: what a chat command may be called (`!name`).
pub fn valid_command_name(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=COMMAND_NAME_MAX).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Parses and validates `mod.toml` text (v1 and v2); the error lists every problem found.
pub fn parse_manifest(text: &str) -> Result<Parsed, Vec<String>> {
    parse_manifest_max(text, MANIFEST_VERSION)
}

/// Like [`parse_manifest`], for a parser that reads manifest versions up to `max_version`.
/// `parse_manifest_max(text, 1)` behaves like the loaders and launchers that predate v2: any
/// v2 manifest, and with it every server-only mod, is refused.
pub fn parse_manifest_max(text: &str, max_version: u32) -> Result<Parsed, Vec<String>> {
    let table: toml::Table = text
        .parse()
        .map_err(|e| vec![format!("mod.toml is not valid TOML: {e}")])?;
    let mut errors: Vec<String> = Vec::new();

    // The version decides what the rest means, so it comes first and a newer one stops here:
    // nothing else in a manifest of an unknown format can be judged.
    let version = match table.get("manifest_version") {
        None => {
            errors.push("manifest_version is required".into());
            1
        }
        Some(v) => match v.as_integer() {
            Some(n) if n > i64::from(max_version) => {
                return Err(vec![format!(
                    "manifest_version {n} is not supported (this parser reads 1 to {max_version})"
                )]);
            }
            Some(n) if n >= 1 => n as u32,
            Some(n) => {
                errors.push(format!(
                    "manifest_version {n} is not supported (this parser reads 1 to {max_version})"
                ));
                1
            }
            None => {
                errors.push("manifest_version must be an integer".into());
                1
            }
        },
    };
    let v2 = version >= 2;

    let mut unknown: Vec<String> = table
        .keys()
        .filter(|k| {
            !KNOWN_TOP_V1.contains(&k.as_str()) && !(v2 && TOP_V2_ONLY.contains(&k.as_str()))
        })
        .cloned()
        .collect();
    for k in TOP_V2_ONLY {
        if !v2 && table.contains_key(*k) {
            unknown.retain(|u| u != k);
            errors.push(format!("{k} needs manifest_version = 2"));
        }
    }
    for (sec, keys) in KNOWN_SECTIONS {
        if let Some(t) = table.get(*sec).and_then(toml::Value::as_table) {
            for k in t.keys().filter(|k| !keys.contains(&k.as_str())) {
                if v2 && *sec == "game" && k == "server_api" {
                    continue;
                }
                if !v2 && *sec == "game" && k == "server_api" {
                    errors.push("game.server_api needs manifest_version = 2".into());
                    continue;
                }
                unknown.push(format!("{sec}.{k}"));
            }
        }
    }

    let mut m = Manifest {
        manifest_version: version,
        ..Manifest::default()
    };
    let string = |key: &str, required: bool, errors: &mut Vec<String>| -> String {
        match table.get(key) {
            Some(toml::Value::String(s)) => s.clone(),
            Some(_) => {
                errors.push(format!("{key} must be a string"));
                String::new()
            }
            None => {
                if required {
                    errors.push(format!("{key} is required"));
                }
                String::new()
            }
        }
    };
    m.id = string("id", true, &mut errors);
    m.name = string("name", true, &mut errors);
    m.version = string("version", true, &mut errors);
    m.description = string("description", false, &mut errors);
    m.license = string("license", false, &mut errors);
    m.homepage = string("homepage", false, &mut errors);
    m.authors = string_list(&table, None, "authors", &mut errors);

    if table.contains_key("id") && !valid_id(&m.id) {
        errors.push(format!(
            "id {:?} must match [a-z0-9][a-z0-9_-]{{1,63}}",
            m.id
        ));
    }
    if table.contains_key("name") && m.name.trim().is_empty() {
        errors.push("name is empty".into());
    }
    if table.contains_key("version") && Version::parse(&m.version).is_err() {
        errors.push(format!("version {:?} is not a semantic version", m.version));
    }

    if v2 {
        match table.get("side") {
            None => errors.push(
                "side is required in manifest_version 2 (\"client\", \"server\" or \"both\")"
                    .into(),
            ),
            Some(toml::Value::String(s)) => match Side::parse(s) {
                Some(side) => m.side = side,
                None => errors.push(format!(
                    "side {s:?} must be \"client\", \"server\" or \"both\""
                )),
            },
            Some(_) => errors.push("side must be a string".into()),
        }
    }

    // [game]: versions are shared; hook_api is the client half's, server_api the server half's.
    let mut game_hook_api = None;
    let mut game_server_api = None;
    if let Some(g) = sub(&table, "game", &mut errors) {
        m.game_versions = string_list(g, Some("game"), "versions", &mut errors);
        game_hook_api = abi_number(g, "game", "hook_api", &mut errors);
        game_server_api = abi_number(g, "game", "server_api", &mut errors);
    }
    if let Some(l) = sub(&table, "load", &mut errors) {
        for (key, slot) in [
            ("after", &mut m.after),
            ("before", &mut m.before),
            ("conflicts", &mut m.conflicts),
        ] {
            *slot = string_list(l, Some("load"), key, &mut errors);
            for id in slot.iter() {
                if !valid_id(id) {
                    errors.push(format!("load.{key}: {id:?} is not a valid mod id"));
                } else if *id == m.id {
                    errors.push(format!("load.{key}: a mod cannot refer to itself"));
                }
            }
        }
    }
    if let Some(d) = sub(&table, "dependencies", &mut errors) {
        for (id, req) in d {
            if !valid_id(id) {
                errors.push(format!("dependencies: {id:?} is not a valid mod id"));
                continue;
            }
            if *id == m.id {
                errors.push("dependencies: a mod cannot depend on itself".into());
            }
            match req.as_str() {
                Some(r) if VersionReq::parse(r).is_ok() => {
                    m.dependencies.insert(id.clone(), r.to_owned());
                }
                _ => errors.push(format!(
                    "dependencies.{id}: {req} is not a semver requirement"
                )),
            }
        }
    }

    // Client half, in its two spellings.
    let mut entry_dll = None;
    if let Some(e) = sub(&table, "entry", &mut errors) {
        entry_dll = dll_path(e, "entry", &mut errors);
    }
    let mut v1_data = DataKeys::default();
    if let Some(d) = sub(&table, "data", &mut errors) {
        v1_data = DataKeys::read(d, "data", &mut errors);
    }
    let mut c_dll = None;
    let mut c_hook_api = None;
    let mut c_data = DataKeys::default();
    let mut has_client_section = false;
    if v2 && let Some(c) = sub(&table, "client", &mut errors) {
        has_client_section = true;
        for k in c.keys().filter(|k| !CLIENT_KEYS.contains(&k.as_str())) {
            unknown.push(format!("client.{k}"));
        }
        c_dll = dll_path(c, "client", &mut errors);
        c_hook_api = abi_number(c, "client", "hook_api", &mut errors);
        c_data = DataKeys::read(c, "client", &mut errors);
    }
    m.entry_dll = alias(entry_dll, "entry.dll", c_dll, "client.dll", &mut errors);
    m.hook_api = alias(
        game_hook_api,
        "game.hook_api",
        c_hook_api,
        "client.hook_api",
        &mut errors,
    );
    m.data_tables = alias_list(
        v1_data.tables,
        "data.tables",
        c_data.tables,
        "client.tables",
        &mut errors,
    );
    m.data_opcodes = alias_list(
        v1_data.opcodes,
        "data.opcodes",
        c_data.opcodes,
        "client.opcodes",
        &mut errors,
    );
    m.config_defaults = alias(
        v1_data.config_defaults,
        "data.config_defaults",
        c_data.config_defaults,
        "client.config_defaults",
        &mut errors,
    );
    let has_client_keys = has_client_section
        || table.contains_key("entry")
        || table.contains_key("data")
        || m.hook_api.is_some();

    // Server half.
    let mut has_server_section = false;
    if v2 && let Some(s) = sub(&table, "server", &mut errors) {
        has_server_section = true;
        for k in s.keys().filter(|k| !SERVER_KEYS.contains(&k.as_str())) {
            errors.push(format!(
                "server.{k} is not a known key (keys: {})",
                SERVER_KEYS.join(", ")
            ));
        }
        let s_api = abi_number(s, "server", "server_api", &mut errors);
        m.server_api = alias(
            game_server_api,
            "game.server_api",
            s_api,
            "server.server_api",
            &mut errors,
        );
        if let Some(lib) = sub(s, "library", &mut errors) {
            for k in lib.keys() {
                if Platform::ALL.iter().all(|p| p.as_str() != k) {
                    errors.push(format!(
                        "server.library.{k}: unknown platform (use {})",
                        Platform::ALL.map(|p| p.as_str()).join(", ")
                    ));
                }
            }
            for p in Platform::ALL {
                let label = format!("server.library.{}", p.as_str());
                match lib.get(p.as_str()) {
                    None => {}
                    Some(toml::Value::String(path)) => {
                        check_rel_path(&label, path, &mut errors);
                        let ext_ok = Path::new(path)
                            .extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| e.eq_ignore_ascii_case(p.library_extension()));
                        if !ext_ok {
                            errors.push(format!(
                                "{label} {path:?} must be a .{} file",
                                p.library_extension()
                            ));
                        }
                        match p {
                            Platform::Linux => m.server_linux = Some(path.clone()),
                            Platform::Windows => m.server_windows = Some(path.clone()),
                        }
                    }
                    Some(_) => errors.push(format!("{label} must be a string")),
                }
            }
        }
        let d = DataKeys::read(s, "server", &mut errors);
        m.server_tables = d.tables;
        m.server_opcodes = d.opcodes;
        m.server_config_defaults = d.config_defaults;
    } else if v2 {
        m.server_api = game_server_api;
    }
    let has_commands = v2 && table.contains_key("commands");
    if v2 {
        m.commands = commands(&table, &mut errors);
    }

    // What each side needs. A v1 manifest keeps its old rules (its ABI check is the loader's).
    let client_missing = "a client mod needs at least one of [entry]/[client] dll or [data]/[client] tables, opcodes or config_defaults";
    match m.side {
        Side::Client => {
            if !m.has_client_content() {
                errors.push(client_missing.into());
            }
            if has_server_section || has_commands || m.server_api.is_some() {
                errors.push(
                    "side is \"client\" but the manifest has server entries ([server], [[commands]] or server_api): set side = \"both\" or remove them"
                        .into(),
                );
            }
        }
        Side::Server => {
            if !m.has_server_content() {
                errors.push("a server mod needs at least one of [server.library], [server] tables, opcodes or config_defaults, or [[commands]]".into());
            }
            if has_client_keys {
                errors.push(
                    "side is \"server\" but the manifest has client entries ([client], [entry], [data] or hook_api): set side = \"both\" or remove them"
                        .into(),
                );
            }
        }
        Side::Both => {
            if !m.has_client_content() {
                errors.push(format!(
                    "side is \"both\": the client half is empty. {client_missing}"
                ));
            }
            if !m.has_server_content() {
                errors.push("side is \"both\": the server half is empty. A server half needs at least one of [server.library], [server] tables, opcodes or config_defaults, or [[commands]]".into());
            }
        }
    }
    // v2 is strict about ABI numbers: a library says which API it was built for.
    if v2 {
        if m.entry_dll.is_some() && m.hook_api.is_none() {
            errors.push("a client DLL must state the mod ABI it was built against: set client.hook_api (or game.hook_api)".into());
        }
        if m.has_server_library() && m.server_api.is_none() {
            errors.push("a server library must state the server API it was built against: set server.server_api".into());
        }
        if !m.has_server_library() && m.server_api.is_some() && m.side.includes_server() {
            // Harmless but a sign of a mistake worth stating.
            unknown.push("server.server_api (no server library to apply it to)".into());
        }
    }

    if errors.is_empty() {
        Ok(Parsed {
            manifest: m,
            unknown_keys: unknown,
        })
    } else {
        Err(errors)
    }
}

/// The `tables`, `opcodes` and `config_defaults` keys of a section (`[data]`, `[client]`,
/// `[server]`).
#[derive(Default)]
struct DataKeys {
    tables: Vec<String>,
    opcodes: Vec<String>,
    config_defaults: Option<String>,
}

impl DataKeys {
    fn read(t: &toml::Table, section: &str, errors: &mut Vec<String>) -> Self {
        let tables = string_list(t, Some(section), "tables", errors);
        let opcodes = string_list(t, Some(section), "opcodes", errors);
        let config_defaults = match t.get("config_defaults") {
            None => None,
            Some(toml::Value::String(s)) => {
                check_rel_path(&format!("{section}.config_defaults"), s, errors);
                Some(s.clone())
            }
            Some(_) => {
                errors.push(format!("{section}.config_defaults must be a string"));
                None
            }
        };
        for p in tables.iter().chain(&opcodes) {
            check_rel_path(&format!("{section} data path"), p, errors);
        }
        Self {
            tables,
            opcodes,
            config_defaults,
        }
    }
}

fn dll_path(t: &toml::Table, section: &str, errors: &mut Vec<String>) -> Option<String> {
    match t.get("dll") {
        None => None,
        Some(toml::Value::String(s)) => {
            check_rel_path(&format!("{section}.dll"), s, errors);
            Some(s.clone())
        }
        Some(_) => {
            errors.push(format!("{section}.dll must be a string"));
            None
        }
    }
}

fn abi_number(t: &toml::Table, section: &str, key: &str, errors: &mut Vec<String>) -> Option<u32> {
    let v = t.get(key)?;
    match v.as_integer().and_then(|n| u32::try_from(n).ok()) {
        Some(n) => Some(n),
        None => {
            errors.push(format!("{section}.{key} must be a non-negative integer"));
            None
        }
    }
}

/// One setting with two spellings (the v1 one and the v2 section): both set is a mistake.
fn alias<T>(
    a: Option<T>,
    a_name: &str,
    b: Option<T>,
    b_name: &str,
    errors: &mut Vec<String>,
) -> Option<T> {
    match (a, b) {
        (Some(_), Some(_)) => {
            errors.push(format!(
                "{a_name} and {b_name} are the same setting: give only one"
            ));
            None
        }
        (x, None) | (None, x) => x,
    }
}

fn alias_list(
    a: Vec<String>,
    a_name: &str,
    b: Vec<String>,
    b_name: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    if !a.is_empty() && !b.is_empty() {
        errors.push(format!(
            "{a_name} and {b_name} are the same setting: give only one"
        ));
        return Vec::new();
    }
    if a.is_empty() { b } else { a }
}

fn commands(table: &toml::Table, errors: &mut Vec<String>) -> Vec<CommandSpec> {
    let Some(v) = table.get("commands") else {
        return Vec::new();
    };
    let Some(list) = v.as_array().filter(|a| a.iter().all(toml::Value::is_table)) else {
        errors.push("commands must be an array of tables ([[commands]])".into());
        return Vec::new();
    };
    let mut out: Vec<CommandSpec> = Vec::new();
    for (i, item) in list.iter().enumerate() {
        let t = item.as_table().expect("checked above");
        let label = |t: &toml::Table| match t.get("name").and_then(toml::Value::as_str) {
            Some(n) => format!("commands \"{n}\""),
            None => format!("commands[{i}]"),
        };
        let l = label(t);
        for k in t.keys().filter(|k| !COMMAND_KEYS.contains(&k.as_str())) {
            errors.push(format!(
                "{l}: {k} is not a known key (keys: {})",
                COMMAND_KEYS.join(", ")
            ));
        }
        let text = |key: &str, max: usize, errors: &mut Vec<String>| -> Option<String> {
            match t.get(key)? {
                toml::Value::String(s) if s.trim().is_empty() => {
                    errors.push(format!("{l}: {key} is empty"));
                    None
                }
                toml::Value::String(s) if s.chars().count() > max => {
                    errors.push(format!("{l}: {key} is longer than {max} characters"));
                    None
                }
                toml::Value::String(s) => Some(s.clone()),
                _ => {
                    errors.push(format!("{l}: {key} must be a string"));
                    None
                }
            }
        };
        let name = match t.get("name") {
            Some(toml::Value::String(n)) if valid_command_name(n) => Some(n.clone()),
            Some(toml::Value::String(n)) => {
                errors.push(format!(
                    "{l}: name {n:?} must match [a-z][a-z0-9_-]{{0,{}}}",
                    COMMAND_NAME_MAX - 1
                ));
                None
            }
            Some(_) => {
                errors.push(format!("{l}: name must be a string"));
                None
            }
            None => {
                errors.push(format!("{l}: name is required"));
                None
            }
        };
        let help = text("help", COMMAND_HELP_MAX, errors).unwrap_or_default();
        let reply = text("reply", COMMAND_TEXT_MAX, errors);
        let alias_line = text("alias", COMMAND_TEXT_MAX, errors);
        if let Some(a) = &alias_line
            && a.trim_start().starts_with('!')
        {
            errors.push(format!(
                "{l}: alias is a command line without the leading !"
            ));
        }
        if t.contains_key("reply") == t.contains_key("alias") {
            errors.push(format!("{l}: give exactly one of reply and alias"));
        }
        let role = match t.get("role") {
            None => CommandRole::Player,
            Some(toml::Value::String(r)) if r == "player" => CommandRole::Player,
            Some(toml::Value::String(r)) if r == "admin" => CommandRole::Admin,
            Some(_) => {
                errors.push(format!("{l}: role must be \"player\" or \"admin\""));
                CommandRole::Player
            }
        };
        if let Some(name) = name {
            if out.iter().any(|c| c.name == name) {
                errors.push(format!("{l}: the command is defined twice"));
            }
            out.push(CommandSpec {
                name,
                help,
                reply,
                alias: alias_line,
                role,
            });
        }
    }
    out
}

fn sub<'a>(t: &'a toml::Table, key: &str, errors: &mut Vec<String>) -> Option<&'a toml::Table> {
    match t.get(key)? {
        toml::Value::Table(t) => Some(t),
        _ => {
            errors.push(format!("[{key}] must be a table"));
            None
        }
    }
}

fn string_list(
    t: &toml::Table,
    section: Option<&str>,
    key: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let label = section.map_or(key.to_owned(), |s| format!("{s}.{key}"));
    match t.get(key) {
        None => Vec::new(),
        Some(toml::Value::Array(a)) => {
            let mut out = Vec::new();
            for v in a {
                match v.as_str() {
                    Some(s) => out.push(s.to_owned()),
                    None => errors.push(format!("{label} must be a list of strings")),
                }
            }
            out
        }
        Some(_) => {
            errors.push(format!("{label} must be a list of strings"));
            Vec::new()
        }
    }
}

/// A relative path that stays inside the mod folder (no `..`, no drive or stream colon, no backslash).
pub(crate) fn check_rel_path(what: &str, p: &str, errors: &mut Vec<String>) {
    let path = Path::new(p);
    let ok = !p.is_empty()
        && !p.contains(['\\', ':'])
        && !path.is_absolute()
        && path.components().all(|c| matches!(c, Component::Normal(_)));
    if !ok {
        errors.push(format!(
            "{what} {p:?} must be a relative path inside the mod folder"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
manifest_version = 1
id = "my-mod"
name = "My Mod"
version = "1.2.0"
description = "One sentence."
authors = ["Someone"]
extra = true

[game]
versions = ["0.5.5e"]
hook_api = 1
nope = 1

[load]
after = ["other-mod"]
conflicts = ["bad-mod"]

[dependencies]
core-lib = ">=1.0, <2"

[entry]
dll = "my_mod.dll"

[data]
tables = ["data/tables"]
config_defaults = "data/defaults.toml"
"#;

    /// A both mod using every v2 key.
    const V2_BOTH: &str = r#"
manifest_version = 2
id = "faster-rolls"
name = "Faster rolls"
version = "1.0.0"
description = "Rolls further."
authors = ["Someone"]
license = "MIT"
side = "both"
future = 1

[game]
versions = ["0.5.5e"]

[load]
conflicts = ["slow-rolls"]

[dependencies]
core-lib = "^1"

[client]
dll = "client/faster_rolls.dll"
hook_api = 1
tables = ["client/data"]

[server]
server_api = 1
config_defaults = "server/defaults.toml"

[server.library]
linux = "server/libfaster_rolls.so"
windows = "server/faster_rolls.dll"

[[commands]]
name = "rollinfo"
help = "Shows the roll tuning."
reply = "Roll distance is 1.5x on this server, {player}."

[[commands]]
name = "r"
alias = "rollinfo {args}"
role = "admin"
"#;

    fn v2(side: &str, body: &str) -> String {
        format!(
            "manifest_version = 2\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\nside = \"{side}\"\n{body}"
        )
    }

    fn errs(text: &str) -> String {
        parse_manifest(text).unwrap_err().join("\n")
    }

    #[test]
    fn manifest_parses_every_field() {
        let p = parse_manifest(GOOD).unwrap();
        let m = p.manifest;
        assert_eq!(m.manifest_version, 1);
        assert_eq!(m.side, Side::Client);
        assert_eq!(m.id, "my-mod");
        assert_eq!(m.name, "My Mod");
        assert_eq!(m.version, "1.2.0");
        assert_eq!(m.authors, ["Someone"]);
        assert_eq!(m.game_versions, ["0.5.5e"]);
        assert_eq!(m.hook_api, Some(1));
        assert_eq!(m.after, ["other-mod"]);
        assert_eq!(m.conflicts, ["bad-mod"]);
        assert_eq!(m.dependencies["core-lib"], ">=1.0, <2");
        assert_eq!(m.entry_dll.as_deref(), Some("my_mod.dll"));
        assert_eq!(m.data_tables, ["data/tables"]);
        assert_eq!(m.config_defaults.as_deref(), Some("data/defaults.toml"));
        assert!(!m.has_server_content());
        // Unknown keys are reported, not fatal.
        assert_eq!(p.unknown_keys, ["extra", "game.nope"]);
    }

    #[test]
    fn manifest_minimal_needs_only_the_required_keys_and_an_entry() {
        let ok = "manifest_version = 1\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\n[entry]\ndll = \"a.dll\"\n";
        let m = parse_manifest(ok).unwrap().manifest;
        assert_eq!(m.hook_api, None);
        assert!(m.game_versions.is_empty());
        // Nothing to load or apply.
        let none = "manifest_version = 1\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\n";
        let e = parse_manifest(none).unwrap_err();
        assert!(e.iter().any(|m| m.contains("at least one of")), "{e:?}");
    }

    #[test]
    fn manifest_reports_all_problems_at_once() {
        let bad = "manifest_version = 1\nid = \"Bad Id\"\nversion = \"1.x\"\n[entry]\ndll = \"../evil.dll\"\n";
        let e = parse_manifest(bad).unwrap_err();
        let all = e.join("\n");
        for needle in [
            "name is required",
            "id \"Bad Id\"",
            "not a semantic version",
            "relative path",
        ] {
            assert!(all.contains(needle), "{needle} missing in {all}");
        }
        assert!(parse_manifest("not = [valid").unwrap_err()[0].contains("not valid TOML"));
    }

    #[test]
    fn manifest_rejects_paths_outside_the_mod_folder() {
        for dll in ["/abs/x.dll", "..\\x.dll", "a/../../x.dll", "C:/x.dll", ""] {
            let t = format!(
                "manifest_version = 1\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\n[entry]\ndll = {dll:?}\n"
            );
            assert!(parse_manifest(&t).is_err(), "{dll:?} accepted");
        }
    }

    #[test]
    fn ids_follow_the_spec_pattern() {
        for ok in ["ab", "my-mod", "a_b-9", "0x"] {
            assert!(valid_id(ok), "{ok}");
        }
        for bad in ["a", "-ab", "_ab", "Ab", "a b", "a/b", "a.b", ""] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert!(!valid_id(&"a".repeat(65)));
        assert!(valid_id(&"a".repeat(64)));
    }

    // ---- v1 compatibility ----

    #[test]
    fn v1_manifests_keep_meaning_exactly() {
        // The shipped sample mod and the fixtures above are v1 client mods.
        let m = parse_manifest(GOOD).unwrap().manifest;
        assert_eq!(m.side, Side::Client);
        assert!(m.has_client_content());
        assert_eq!(m.server_api, None);
        assert!(m.commands.is_empty());
        assert_eq!(m.server_library(Platform::Linux), None);
        // A v1 DLL mod without hook_api still parses (the loader's ABI check refuses it).
        let no_api = "manifest_version = 1\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\n[entry]\ndll = \"a.dll\"\n";
        assert!(parse_manifest(no_api).is_ok());
    }

    #[test]
    fn v2_keys_in_a_v1_manifest_are_errors_not_ignored_keys() {
        for body in [
            "side = \"client\"\n",
            "[client]\ndll = \"a.dll\"\n",
            "[server]\nserver_api = 1\n",
            "[[commands]]\nname = \"hi\"\nreply = \"x\"\n",
            "[game]\nserver_api = 1\n",
        ] {
            let t = format!(
                "manifest_version = 1\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\n[entry]\ndll = \"a.dll\"\n{body}"
            );
            // Keys after a table header belong to that table: put top-level keys first.
            let t = if body.starts_with("side") {
                format!("{body}{t}")
            } else {
                t
            };
            let e = errs(&t);
            assert!(e.contains("needs manifest_version = 2"), "{body}: {e}");
        }
    }

    #[test]
    fn a_v1_only_parser_refuses_every_v2_manifest_so_server_mods_fail_closed() {
        let server_only = v2("server", "[[commands]]\nname = \"hi\"\nreply = \"x\"\n");
        assert!(parse_manifest(&server_only).is_ok());
        let e = parse_manifest_max(&server_only, 1).unwrap_err();
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(
            e[0].contains("manifest_version 2 is not supported"),
            "{e:?}"
        );
        // A both mod and a v2 client mod are refused by it too; v1 client mods still load.
        assert!(parse_manifest_max(V2_BOTH, 1).is_err());
        assert!(parse_manifest_max(GOOD, 1).is_ok());
        // And this parser refuses what is newer than itself.
        let e = errs(&GOOD.replace("manifest_version = 1", "manifest_version = 3"));
        assert!(e.contains("manifest_version 3 is not supported"), "{e}");
    }

    // ---- v2 ----

    #[test]
    fn v2_both_mod_parses_every_field() {
        let p = parse_manifest(V2_BOTH).unwrap();
        let m = &p.manifest;
        assert_eq!(m.manifest_version, 2);
        assert_eq!(m.side, Side::Both);
        assert_eq!(m.game_versions, ["0.5.5e"]);
        assert_eq!(m.entry_dll.as_deref(), Some("client/faster_rolls.dll"));
        assert_eq!(m.hook_api, Some(1));
        assert_eq!(m.data_tables, ["client/data"]);
        assert_eq!(m.server_api, Some(1));
        assert_eq!(
            m.server_library(Platform::Linux),
            Some("server/libfaster_rolls.so")
        );
        assert_eq!(
            m.server_library(Platform::Windows),
            Some("server/faster_rolls.dll")
        );
        assert_eq!(
            m.server_config_defaults.as_deref(),
            Some("server/defaults.toml")
        );
        assert_eq!(m.commands.len(), 2);
        assert_eq!(m.commands[0].name, "rollinfo");
        assert!(m.commands[0].reply.as_deref().unwrap().contains("{player}"));
        assert_eq!(m.commands[0].role, CommandRole::Player);
        assert_eq!(m.commands[1].alias.as_deref(), Some("rollinfo {args}"));
        assert_eq!(m.commands[1].role, CommandRole::Admin);
        assert_eq!(p.unknown_keys, ["future"]);
        assert!(m.side.includes_client() && m.side.includes_server());
        assert_eq!(
            m.referenced_paths(),
            [
                "client/data",
                "client/faster_rolls.dll",
                "server/defaults.toml",
                "server/faster_rolls.dll",
                "server/libfaster_rolls.so"
            ]
        );
    }

    #[test]
    fn v2_server_only_and_client_only_mods() {
        // A server mod with only data: commands.
        let m = parse_manifest(&v2(
            "server",
            "[[commands]]\nname = \"motd\"\nreply = \"hi\"\n",
        ))
        .unwrap()
        .manifest;
        assert_eq!(m.side, Side::Server);
        assert!(!m.has_client_content() && m.has_server_content());
        assert!(!m.has_server_library());
        // A server mod with a native library for one platform.
        let m = parse_manifest(&v2(
            "server",
            "[server]\nserver_api = 1\n[server.library]\nlinux = \"server/libx.so\"\n",
        ))
        .unwrap()
        .manifest;
        assert!(m.has_server_library());
        assert_eq!(m.server_library(Platform::Windows), None);
        // A v2 client mod in the v1 spelling and in the v2 spelling mean the same.
        let a = parse_manifest(&v2(
            "client",
            "[entry]\ndll = \"a.dll\"\n[game]\nhook_api = 1\n",
        ))
        .unwrap()
        .manifest;
        let b = parse_manifest(&v2("client", "[client]\ndll = \"a.dll\"\nhook_api = 1\n"))
            .unwrap()
            .manifest;
        assert_eq!(a.entry_dll, b.entry_dll);
        assert_eq!(a.hook_api, b.hook_api);
        assert_eq!(a.hook_api, Some(1));
    }

    #[test]
    fn game_server_api_is_an_accepted_spelling_of_server_api() {
        let m = parse_manifest(&v2(
            "server",
            "[game]\nserver_api = 1\n[server.library]\nlinux = \"server/libx.so\"\n[server]\n",
        ))
        .unwrap()
        .manifest;
        assert_eq!(m.server_api, Some(1));
    }

    #[test]
    fn side_rules_are_exact() {
        // side is required in v2, and one of three values.
        let none = "manifest_version = 2\nid = \"ab\"\nname = \"x\"\nversion = \"0.1.0\"\n[client]\ndll = \"a.dll\"\nhook_api = 1\n";
        assert!(errs(none).contains("side is required"));
        assert!(
            errs(&v2(
                "everywhere",
                "[client]\ndll = \"a.dll\"\nhook_api = 1\n"
            ))
            .contains("side \"everywhere\"")
        );
        // A client mod with a server half, and a server mod with a client half.
        let e = errs(&v2(
            "client",
            "[client]\ndll = \"a.dll\"\nhook_api = 1\n[[commands]]\nname = \"hi\"\nreply = \"x\"\n",
        ));
        assert!(
            e.contains("side is \"client\" but the manifest has server entries"),
            "{e}"
        );
        let e = errs(&v2(
            "server",
            "[client]\ndll = \"a.dll\"\nhook_api = 1\n[[commands]]\nname = \"hi\"\nreply = \"x\"\n",
        ));
        assert!(
            e.contains("side is \"server\" but the manifest has client entries"),
            "{e}"
        );
        // Empty halves.
        assert!(errs(&v2("client", "")).contains("at least one of"));
        assert!(errs(&v2("server", "")).contains("a server mod needs"));
        let e = errs(&v2("both", "[client]\ndll = \"a.dll\"\nhook_api = 1\n"));
        assert!(e.contains("the server half is empty"), "{e}");
        let e = errs(&v2("both", "[[commands]]\nname = \"hi\"\nreply = \"x\"\n"));
        assert!(e.contains("the client half is empty"), "{e}");
    }

    #[test]
    fn v2_dll_mods_must_state_their_api() {
        let e = errs(&v2("client", "[client]\ndll = \"a.dll\"\n"));
        assert!(e.contains("client.hook_api"), "{e}");
        let e = errs(&v2(
            "server",
            "[server.library]\nlinux = \"server/libx.so\"\n",
        ));
        assert!(e.contains("server.server_api"), "{e}");
    }

    #[test]
    fn two_spellings_of_one_setting_are_refused() {
        let e = errs(&v2(
            "client",
            "[entry]\ndll = \"a.dll\"\n[client]\ndll = \"b.dll\"\nhook_api = 1\n",
        ));
        assert!(e.contains("entry.dll and client.dll"), "{e}");
        let e = errs(&v2(
            "client",
            "[game]\nhook_api = 1\n[client]\ndll = \"b.dll\"\nhook_api = 1\n",
        ));
        assert!(e.contains("game.hook_api and client.hook_api"), "{e}");
    }

    #[test]
    fn server_library_names_and_platforms_are_checked() {
        let lib = |body: &str| {
            v2(
                "server",
                &format!("[server]\nserver_api = 1\n[server.library]\n{body}"),
            )
        };
        assert!(errs(&lib("linux = \"server/x.dll\"\n")).contains("must be a .so file"));
        assert!(errs(&lib("windows = \"server/libx.so\"\n")).contains("must be a .dll file"));
        assert!(errs(&lib("macos = \"server/x.dylib\"\n")).contains("unknown platform"));
        assert!(errs(&lib("linux = \"../libx.so\"\n")).contains("relative path"));
        assert!(errs(&lib("linux = 5\n")).contains("server.library.linux must be a string"));
        // Upper-case extensions are fine on Windows files.
        assert!(parse_manifest(&lib("windows = \"server/X.DLL\"\n")).is_ok());
    }

    #[test]
    fn unknown_server_keys_are_errors() {
        let e = errs(&v2(
            "server",
            "[server]\nserver_api = 1\nlibary = \"x\"\n[[commands]]\nname = \"hi\"\nreply = \"x\"\n",
        ));
        assert!(e.contains("server.libary is not a known key"), "{e}");
        let e = errs(&v2(
            "server",
            "[[commands]]\nname = \"hi\"\nreply = \"x\"\ncolour = 1\n",
        ));
        assert!(
            e.contains("commands \"hi\": colour is not a known key"),
            "{e}"
        );
    }

    #[test]
    fn commands_are_validated() {
        let cmd = |body: &str| v2("server", &format!("[[commands]]\n{body}"));
        assert!(errs(&cmd("reply = \"x\"\n")).contains("commands[0]: name is required"));
        assert!(errs(&cmd("name = \"Hi\"\nreply = \"x\"\n")).contains("name \"Hi\""));
        assert!(errs(&cmd("name = \"hi\"\n")).contains("exactly one of reply and alias"));
        assert!(
            errs(&cmd("name = \"hi\"\nreply = \"x\"\nalias = \"y\"\n"))
                .contains("exactly one of reply and alias")
        );
        assert!(errs(&cmd("name = \"hi\"\nalias = \"!kick\"\n")).contains("without the leading !"));
        assert!(
            errs(&cmd("name = \"hi\"\nreply = \"x\"\nrole = \"god\"\n")).contains("role must be")
        );
        assert!(errs(&cmd("name = \"hi\"\nreply = \"  \"\n")).contains("reply is empty"));
        let long = "x".repeat(COMMAND_TEXT_MAX + 1);
        assert!(
            errs(&cmd(&format!("name = \"hi\"\nreply = \"{long}\"\n"))).contains("longer than")
        );
        let dup = v2(
            "server",
            "[[commands]]\nname = \"hi\"\nreply = \"a\"\n[[commands]]\nname = \"hi\"\nreply = \"b\"\n",
        );
        assert!(errs(&dup).contains("defined twice"));
        assert!(errs("manifest_version = 2\nid = \"ab\"\nname = \"x\"\nversion = \"1.0.0\"\nside = \"server\"\ncommands = 3\n")
            .contains("array of tables"));
        for ok in ["a", "motd", "roll-info", "a_b9"] {
            assert!(valid_command_name(ok), "{ok}");
        }
        for bad in ["", "9a", "-a", "A", "a b", "!a", &"a".repeat(33)] {
            assert!(!valid_command_name(bad), "{bad}");
        }
    }

    #[test]
    fn v2_reports_all_problems_at_once() {
        let e = errs(&v2(
            "both",
            "[client]\ndll = \"../a.dll\"\n[server]\nserver_api = -1\n[server.library]\nlinux = \"libx.dll\"\n[[commands]]\nname = \"Bad\"\n",
        ));
        for needle in [
            "client.dll",
            "server.server_api must be a non-negative integer",
            "must be a .so file",
            "name \"Bad\"",
        ] {
            assert!(e.contains(needle), "{needle} missing in {e}");
        }
    }

    #[test]
    fn dependencies_and_conflicts_are_the_same_in_v2() {
        let m = parse_manifest(V2_BOTH).unwrap().manifest;
        assert_eq!(m.dependencies["core-lib"], "^1");
        assert_eq!(m.conflicts, ["slow-rolls"]);
        let e = errs(&v2(
            "client",
            "[client]\ndll = \"a.dll\"\nhook_api = 1\n[dependencies]\nab = \"1\"\nbad = \"x.y\"\n[load]\nafter = [\"ab\"]\n",
        ));
        assert!(e.contains("cannot depend on itself"), "{e}");
        assert!(e.contains("dependencies.bad"), "{e}");
        assert!(
            e.contains("load.after: a mod cannot refer to itself"),
            "{e}"
        );
    }
}
