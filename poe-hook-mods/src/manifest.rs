//! `mod.toml` (spec: `docs/mod-manifest.md`). Same rules as the launcher's parser: every problem
//! is reported, unknown keys are collected (and logged by the loader), never fatal.

use std::{
    collections::BTreeMap,
    path::{Component, Path},
};

use semver::{Version, VersionReq};

use crate::MANIFEST_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub authors: Vec<String>,
    pub license: String,
    pub homepage: String,
    /// `[game] versions`; empty = not stated.
    pub game_versions: Vec<String>,
    /// `[game] hook_api`: the mod ABI the mod was built against.
    pub hook_api: Option<u32>,
    pub after: Vec<String>,
    pub before: Vec<String>,
    pub conflicts: Vec<String>,
    /// id -> semver requirement text.
    pub dependencies: BTreeMap<String, String>,
    /// `[entry] dll`, relative to the mod folder.
    pub entry_dll: Option<String>,
    pub data_tables: Vec<String>,
    pub data_opcodes: Vec<String>,
    pub config_defaults: Option<String>,
}

/// A parsed manifest plus its non-fatal findings.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub manifest: Manifest,
    pub unknown_keys: Vec<String>,
}

const KNOWN_TOP: &[&str] = &[
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
const KNOWN_SECTIONS: &[(&str, &[&str])] = &[
    ("game", &["versions", "hook_api"]),
    ("load", &["after", "before", "conflicts"]),
    ("entry", &["dll"]),
    ("data", &["tables", "opcodes", "config_defaults"]),
];

/// `[a-z0-9][a-z0-9_-]{1,63}`
pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    (2..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Parses and validates `mod.toml` text; the error lists every problem found.
pub fn parse_manifest(text: &str) -> Result<Parsed, Vec<String>> {
    let table: toml::Table = text
        .parse()
        .map_err(|e| vec![format!("mod.toml is not valid TOML: {e}")])?;
    let mut errors: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = table
        .keys()
        .filter(|k| !KNOWN_TOP.contains(&k.as_str()))
        .cloned()
        .collect();
    for (sec, keys) in KNOWN_SECTIONS {
        if let Some(t) = table.get(*sec).and_then(toml::Value::as_table) {
            for k in t.keys().filter(|k| !keys.contains(&k.as_str())) {
                unknown.push(format!("{sec}.{k}"));
            }
        }
    }

    match table.get("manifest_version") {
        None => errors.push("manifest_version is required".into()),
        Some(v) => match v.as_integer() {
            Some(n) if n == i64::from(MANIFEST_VERSION) => {}
            Some(n) => errors.push(format!(
                "manifest_version {n} is not supported (this loader reads {MANIFEST_VERSION})"
            )),
            None => errors.push("manifest_version must be an integer".into()),
        },
    }
    let mut m = Manifest::default();
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

    if let Some(g) = sub(&table, "game", &mut errors) {
        m.game_versions = string_list(g, Some("game"), "versions", &mut errors);
        if let Some(v) = g.get("hook_api") {
            match v.as_integer().and_then(|n| u32::try_from(n).ok()) {
                Some(n) => m.hook_api = Some(n),
                None => errors.push("game.hook_api must be a non-negative integer".into()),
            }
        }
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
    if let Some(e) = sub(&table, "entry", &mut errors) {
        match e.get("dll") {
            None => {}
            Some(toml::Value::String(s)) => {
                check_rel_path("entry.dll", s, &mut errors);
                m.entry_dll = Some(s.clone());
            }
            Some(_) => errors.push("entry.dll must be a string".into()),
        }
    }
    if let Some(d) = sub(&table, "data", &mut errors) {
        m.data_tables = string_list(d, Some("data"), "tables", &mut errors);
        m.data_opcodes = string_list(d, Some("data"), "opcodes", &mut errors);
        match d.get("config_defaults") {
            None => {}
            Some(toml::Value::String(s)) => {
                check_rel_path("data.config_defaults", s, &mut errors);
                m.config_defaults = Some(s.clone());
            }
            Some(_) => errors.push("data.config_defaults must be a string".into()),
        }
        for p in m.data_tables.iter().chain(&m.data_opcodes) {
            check_rel_path("data path", p, &mut errors);
        }
    }
    if m.entry_dll.is_none()
        && m.data_tables.is_empty()
        && m.data_opcodes.is_empty()
        && m.config_defaults.is_none()
    {
        errors.push("a mod needs at least one of [entry] dll or [data] entries".into());
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
fn check_rel_path(what: &str, p: &str, errors: &mut Vec<String>) {
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

    #[test]
    fn manifest_parses_every_field() {
        let p = parse_manifest(GOOD).unwrap();
        let m = p.manifest;
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
        let bad = "manifest_version = 2\nid = \"Bad Id\"\nversion = \"1.x\"\n[entry]\ndll = \"../evil.dll\"\n";
        let e = parse_manifest(bad).unwrap_err();
        let all = e.join("\n");
        for needle in [
            "manifest_version 2",
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
}
