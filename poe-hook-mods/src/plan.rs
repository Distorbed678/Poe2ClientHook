//! Which enabled mods may load, in what order, and why the others do not.
//!
//! [`plan`] makes every decision that needs only files: official mode, `state.toml`, the
//! manifest, the folder name, the ABI version, the entry DLL's presence. [`LoadSet`] makes the
//! two that depend on what really loaded before (dependencies, conflicts): a mod whose
//! dependency failed to load must not load either. A mod that is skipped never has any of its
//! code mapped.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use semver::{Version, VersionReq};

use crate::{
    HOOK_API, MANIFEST_FILE, Manifest, STATE_FILE, Side, parse_manifest, parse_state, valid_id,
};

/// A mod that passed the file-level checks.
#[derive(Debug, Clone)]
pub struct PlannedMod {
    pub id: String,
    /// `<mods dir>/<id>`.
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The entry DLL's full path; `None` for a data-only mod.
    pub dll: Option<PathBuf>,
    /// Non-fatal findings to log (unknown keys, a client version the mod was not made for).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Plan {
    /// Set when no mod may load at all ([`refusal`]); `mods` is empty then.
    pub refused: Option<String>,
    /// In load order (the order of `state.toml`).
    pub mods: Vec<PlannedMod>,
    pub skipped: Vec<Skipped>,
    /// Enabled mods that have no client half (`side = "server"`). They are skipped, never
    /// loaded; they only count for the dependency and conflict checks of the mods that are
    /// ([`LoadSet::add_foreign`]).
    pub other_side: Vec<Manifest>,
    /// Problems with the mod directory itself (an unreadable `state.toml`).
    pub notes: Vec<String>,
}

/// Why no mod may load: official mode (read-only: nothing is injected into the client) and a
/// latch that is already on (the client talks to an untrusted server). `None`: mods may load.
pub fn refusal(official: bool, read_only: bool) -> Option<&'static str> {
    if official {
        Some("official mode is read-only: no mod is loaded")
    } else if read_only {
        Some("the read-only latch is on (untrusted server): no mod is loaded")
    } else {
        None
    }
}

/// The ABI check on the manifest. The loader offers exactly [`HOOK_API`]: a mod built for a
/// newer major needs functions this loader lacks, and an older major's layout is not kept.
/// A mod with an entry DLL must state which ABI it was built against.
pub fn check_abi(m: &Manifest) -> Result<(), String> {
    match m.hook_api {
        Some(v) if v == HOOK_API => Ok(()),
        Some(v) if v > HOOK_API => Err(format!(
            "built for mod ABI {v}, this loader offers {HOOK_API} (update poe-hook)"
        )),
        Some(v) => Err(format!(
            "built for mod ABI {v}, this loader offers {HOOK_API} (rebuild the mod)"
        )),
        None if m.entry_dll.is_some() => Err(format!(
            "no game.hook_api: a mod with an entry DLL must state the mod ABI it was built against (this loader offers {HOOK_API})"
        )),
        None => Ok(()),
    }
}

/// The server-API check on the manifest, for a server that offers `offered`. A mod with a
/// native server library must state which API it was built against; a mod without one
/// (commands and data only) needs no number.
pub fn check_server_api(m: &Manifest, offered: u32) -> Result<(), String> {
    if !m.has_server_library() {
        return Ok(());
    }
    match m.server_api {
        Some(v) if v == offered => Ok(()),
        Some(v) if v > offered => Err(format!(
            "built for server API {v}, this server offers {offered} (update the server)"
        )),
        Some(v) => Err(format!(
            "built for server API {v}, this server offers {offered} (rebuild the mod)"
        )),
        None => Err(format!(
            "no server.server_api: a mod with a server library must state the server API it was built against (this server offers {offered})"
        )),
    }
}

/// Reads `<mods_dir>/state.toml` and the enabled mods' manifests. Does no file access at all
/// when [`refusal`] applies. `game_version` is the client version of the matching signature
/// table, when known (a mod made for other versions only gets a warning).
pub fn plan(mods_dir: &Path, official: bool, read_only: bool, game_version: Option<&str>) -> Plan {
    let mut plan = Plan::default();
    if let Some(why) = refusal(official, read_only) {
        plan.refused = Some(why.to_owned());
        return plan;
    }
    let enabled = match std::fs::read_to_string(mods_dir.join(STATE_FILE)) {
        Ok(text) => match parse_state(&text) {
            Ok(s) => s.enabled,
            Err(e) => {
                plan.notes.push(format!("{e}: no mod is loaded"));
                return plan;
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return plan,
        Err(e) => {
            plan.notes
                .push(format!("cannot read {STATE_FILE}: {e}: no mod is loaded"));
            return plan;
        }
    };
    let mut seen: Vec<&str> = Vec::new();
    for id in &enabled {
        let mut skip = |reason: String| {
            plan.skipped.push(Skipped {
                id: id.clone(),
                reason,
            })
        };
        if seen.contains(&id.as_str()) {
            skip("listed twice in state.toml".into());
            continue;
        }
        seen.push(id);
        if !valid_id(id) {
            skip("not a valid mod id".into());
            continue;
        }
        let dir = mods_dir.join(id);
        let text = match std::fs::read_to_string(dir.join(MANIFEST_FILE)) {
            Ok(t) => t,
            Err(e) => {
                skip(format!("enabled but {MANIFEST_FILE} cannot be read ({e})"));
                continue;
            }
        };
        let parsed = match parse_manifest(&text) {
            Ok(p) => p,
            Err(errors) => {
                skip(format!("invalid {MANIFEST_FILE}: {}", errors.join("; ")));
                continue;
            }
        };
        let m = parsed.manifest;
        if m.id != *id {
            skip(format!(
                "the folder is named {id:?} but the manifest id is {:?}",
                m.id
            ));
            continue;
        }
        if !m.side.includes_client() {
            skip(format!(
                "server-only mod (side = \"{}\"): it has no client half, install it into the server's mods folder",
                m.side.as_str()
            ));
            plan.other_side.push(m);
            continue;
        }
        if let Err(why) = check_abi(&m) {
            skip(why);
            continue;
        }
        let dll = match &m.entry_dll {
            Some(rel) => {
                let p = dir.join(rel);
                if !p.is_file() {
                    skip(format!("entry DLL {rel:?} is missing"));
                    continue;
                }
                Some(p)
            }
            None => None,
        };
        let mut warnings: Vec<String> = parsed
            .unknown_keys
            .iter()
            .map(|k| format!("unknown key {k} in {MANIFEST_FILE} ignored"))
            .collect();
        if let Some(v) = game_version
            && !m.game_versions.is_empty()
            && !m.game_versions.iter().any(|g| g == v)
        {
            warnings.push(format!(
                "made for client {}, this client is {v}",
                m.game_versions.join(", ")
            ));
        }
        plan.mods.push(PlannedMod {
            id: id.clone(),
            dir,
            manifest: m,
            dll,
            warnings,
        });
    }
    plan
}

/// The mods that loaded so far, for the checks that depend on them.
#[derive(Debug, Default)]
pub struct LoadSet {
    loaded: BTreeMap<String, (Version, Vec<String>)>,
    /// Mods that are enabled but have no half for this program (server-only mods, seen from
    /// the client). They satisfy dependencies of mods that also have another half and count
    /// for conflicts, but are never loaded here.
    foreign: BTreeMap<String, (Version, Vec<String>)>,
}

impl LoadSet {
    /// `Ok` when `m` may load now: every dependency has loaded (earlier) in a version that
    /// satisfies the requirement, and no loaded mod conflicts with it or it with them.
    ///
    /// Dependencies and conflicts are about the mod, not a half: a mod that has a client and a
    /// server half may depend on a server-only mod (the dependency matters on the server, so the
    /// client skips it); a mod with only this program's half may not.
    pub fn check(&self, m: &Manifest) -> Result<(), String> {
        for (dep, req) in &m.dependencies {
            let Some((have, _)) = self.loaded.get(dep).or_else(|| self.foreign.get(dep)) else {
                return Err(format!(
                    "needs {dep} {req}, which is not loaded (missing, disabled, failed, or ordered after this mod)"
                ));
            };
            if self.foreign.contains_key(dep) && m.side != Side::Both {
                return Err(format!(
                    "needs {dep} {req}, which is a mod for the other side, and this mod (side = \"{}\") has no other half",
                    m.side.as_str()
                ));
            }
            // Both parsed by the manifest check; a failure here means a hand-built Manifest.
            let ok = VersionReq::parse(req).is_ok_and(|r| r.matches(have));
            if !ok {
                return Err(format!("needs {dep} {req}, but {dep} {have} is loaded"));
            }
        }
        for c in &m.conflicts {
            if self.loaded.contains_key(c) || self.foreign.contains_key(c) {
                return Err(format!("conflicts with {c}, which is loaded"));
            }
        }
        for (other, (_, conflicts)) in self.loaded.iter().chain(&self.foreign) {
            if conflicts.contains(&m.id) {
                return Err(format!("{other} conflicts with it and is loaded"));
            }
        }
        Ok(())
    }

    /// Records that `m` loaded.
    pub fn add(&mut self, m: &Manifest) {
        let v = Version::parse(&m.version).unwrap_or(Version::new(0, 0, 0));
        self.loaded.insert(m.id.clone(), (v, m.conflicts.clone()));
    }

    /// Records an enabled mod that has no half for this program ([`Plan::other_side`]).
    pub fn add_foreign(&mut self, m: &Manifest) {
        let v = Version::parse(&m.version).unwrap_or(Version::new(0, 0, 0));
        self.foreign.insert(m.id.clone(), (v, m.conflicts.clone()));
    }

    pub fn contains(&self, id: &str) -> bool {
        self.loaded.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_mod(dir: &Path, id: &str, extra: &str, dll: Option<&str>) {
        let d = dir.join(id);
        fs::create_dir_all(&d).unwrap();
        let entry = dll.map_or(String::new(), |f| {
            fs::write(d.join(f), b"MZ").unwrap();
            format!("[entry]\ndll = \"{f}\"\n")
        });
        fs::write(
            d.join("mod.toml"),
            format!(
                "manifest_version = 1\nid = \"{id}\"\nname = \"{id}\"\nversion = \"1.0.0\"\n{extra}\n{entry}"
            ),
        )
        .unwrap();
    }

    fn enable(dir: &Path, ids: &[&str]) {
        let list: Vec<String> = ids.iter().map(|s| (*s).to_owned()).collect();
        fs::write(dir.join("state.toml"), crate::state_text(&list)).unwrap();
    }

    fn ids(p: &Plan) -> Vec<&str> {
        p.mods.iter().map(|m| m.id.as_str()).collect()
    }

    const API: &str = "[game]\nhook_api = 1\n";

    #[test]
    fn plan_loads_enabled_mods_in_state_order_and_ignores_disabled_ones() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "zeta", API, Some("z.dll"));
        write_mod(t.path(), "alpha", API, Some("a.dll"));
        write_mod(t.path(), "off-mod", API, Some("o.dll"));
        enable(t.path(), &["zeta", "alpha"]);
        let p = plan(t.path(), false, false, Some("0.5.5e"));
        // The state file is the order, not the id.
        assert_eq!(ids(&p), ["zeta", "alpha"]);
        assert!(p.skipped.is_empty() && p.refused.is_none());
        assert_eq!(
            p.mods[0].dll.as_deref(),
            Some(t.path().join("zeta/z.dll").as_path())
        );
    }

    #[test]
    fn plan_without_state_file_or_with_empty_state_loads_nothing() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "alpha", API, Some("a.dll"));
        assert!(plan(t.path(), false, false, None).mods.is_empty());
        enable(t.path(), &[]);
        assert!(plan(t.path(), false, false, None).mods.is_empty());
        // A missing directory is the same as no mods.
        let p = plan(&t.path().join("nowhere"), false, false, None);
        assert!(p.mods.is_empty() && p.notes.is_empty());
    }

    #[test]
    fn plan_with_a_broken_state_file_fails_closed() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "alpha", API, Some("a.dll"));
        fs::write(t.path().join("state.toml"), "enabled = \"alpha\"").unwrap();
        let p = plan(t.path(), false, false, None);
        assert!(p.mods.is_empty());
        assert!(p.notes[0].contains("no mod is loaded"), "{:?}", p.notes);
    }

    #[test]
    fn official_mode_loads_no_mod_and_does_not_even_read_the_directory() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "alpha", API, Some("a.dll"));
        enable(t.path(), &["alpha"]);
        let p = plan(t.path(), true, false, Some("0.5.5e"));
        assert!(p.mods.is_empty() && p.skipped.is_empty());
        assert!(p.refused.as_deref().unwrap().contains("official"));
        // Same answer when the directory does not exist (nothing was read to decide).
        let p = plan(&t.path().join("nowhere"), true, false, None);
        assert!(p.refused.is_some());
    }

    #[test]
    fn an_already_set_read_only_latch_refuses_too() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "alpha", API, Some("a.dll"));
        enable(t.path(), &["alpha"]);
        let p = plan(t.path(), false, true, None);
        assert!(p.mods.is_empty());
        assert!(p.refused.as_deref().unwrap().contains("latch"));
        assert!(refusal(false, false).is_none());
        assert!(refusal(true, true).unwrap().contains("official"));
    }

    #[test]
    fn abi_check_accepts_only_the_loaders_version() {
        let mut m = Manifest {
            id: "ab".into(),
            entry_dll: Some("a.dll".into()),
            hook_api: Some(HOOK_API),
            ..Default::default()
        };
        assert!(check_abi(&m).is_ok());
        m.hook_api = Some(HOOK_API + 1);
        let e = check_abi(&m).unwrap_err();
        assert!(e.contains("update poe-hook"), "{e}");
        m.hook_api = Some(HOOK_API - 1);
        assert!(check_abi(&m).unwrap_err().contains("rebuild the mod"));
        // A DLL mod must say; a data-only mod need not.
        m.hook_api = None;
        assert!(check_abi(&m).unwrap_err().contains("game.hook_api"));
        m.entry_dll = None;
        assert!(check_abi(&m).is_ok());
    }

    #[test]
    fn plan_skips_a_mod_with_the_wrong_abi_and_never_maps_its_dll() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "newer", "[game]\nhook_api = 99\n", Some("n.dll"));
        write_mod(t.path(), "nostate", "", Some("s.dll"));
        write_mod(t.path(), "fine", API, Some("f.dll"));
        enable(t.path(), &["newer", "nostate", "fine"]);
        let p = plan(t.path(), false, false, None);
        assert_eq!(ids(&p), ["fine"]);
        assert_eq!(p.skipped.len(), 2);
        assert_eq!(p.skipped[0].id, "newer");
        assert!(
            p.skipped[0].reason.contains("mod ABI 99"),
            "{:?}",
            p.skipped
        );
        assert!(
            p.skipped[1].reason.contains("game.hook_api"),
            "{:?}",
            p.skipped
        );
    }

    #[test]
    fn plan_skips_broken_mods_with_a_reason_and_goes_on() {
        let t = tempfile::tempdir().unwrap();
        write_mod(t.path(), "nodll", API, None);
        fs::write(
            t.path().join("nodll/mod.toml"),
            "manifest_version = 1\nid = \"nodll\"\nname = \"n\"\nversion = \"1.0.0\"\n[game]\nhook_api = 1\n[entry]\ndll = \"gone.dll\"\n",
        )
        .unwrap();
        write_mod(t.path(), "badtoml", API, Some("b.dll"));
        fs::write(t.path().join("badtoml/mod.toml"), "id = [").unwrap();
        write_mod(t.path(), "renamed", API, Some("r.dll"));
        fs::rename(t.path().join("renamed"), t.path().join("folder")).unwrap();
        write_mod(t.path(), "ok-mod", API, Some("o.dll"));
        enable(
            t.path(),
            &[
                "nodll", "badtoml", "folder", "missing", "Bad Id", "ok-mod", "ok-mod",
            ],
        );
        let p = plan(t.path(), false, false, None);
        assert_eq!(ids(&p), ["ok-mod"]);
        let why: Vec<(&str, &str)> = p
            .skipped
            .iter()
            .map(|s| (s.id.as_str(), s.reason.as_str()))
            .collect();
        assert!(why[0].1.contains("entry DLL"), "{why:?}");
        assert!(why[1].1.contains("not valid TOML"), "{why:?}");
        assert!(why[2].1.contains("manifest id"), "{why:?}");
        assert!(why[3].1.contains("cannot be read"), "{why:?}");
        assert!(why[4].1.contains("not a valid mod id"), "{why:?}");
        assert!(why[5].1.contains("twice"), "{why:?}");
    }

    #[test]
    fn plan_warns_about_other_client_versions_and_unknown_keys_but_loads() {
        let t = tempfile::tempdir().unwrap();
        write_mod(
            t.path(),
            "old-mod",
            "mystery = 1\n[game]\nhook_api = 1\nversions = [\"0.4.0\"]\n",
            Some("o.dll"),
        );
        enable(t.path(), &["old-mod"]);
        let p = plan(t.path(), false, false, Some("0.5.5e"));
        assert_eq!(ids(&p), ["old-mod"]);
        let w = p.mods[0].warnings.join("\n");
        assert!(w.contains("made for client 0.4.0"), "{w}");
        assert!(w.contains("unknown key mystery"), "{w}");
        // Unknown client: nothing to compare.
        let p = plan(t.path(), false, false, None);
        assert!(!p.mods[0].warnings.join("\n").contains("made for client"));
    }

    #[test]
    fn data_only_mods_are_planned_without_a_dll() {
        let t = tempfile::tempdir().unwrap();
        write_mod(
            t.path(),
            "data-mod",
            "[data]\ntables = [\"data/t\"]\n",
            None,
        );
        enable(t.path(), &["data-mod"]);
        let p = plan(t.path(), false, false, None);
        assert_eq!(ids(&p), ["data-mod"]);
        assert!(p.mods[0].dll.is_none());
    }

    fn manifest(id: &str, version: &str, deps: &[(&str, &str)], conflicts: &[&str]) -> Manifest {
        Manifest {
            id: id.into(),
            version: version.into(),
            dependencies: deps
                .iter()
                .map(|(a, b)| ((*a).into(), (*b).into()))
                .collect(),
            conflicts: conflicts.iter().map(|s| (*s).into()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn load_set_checks_dependencies_versions_and_conflicts() {
        let mut set = LoadSet::default();
        let lib = manifest("core-lib", "1.4.0", &[], &["evil"]);
        let user = manifest("user", "1.0.0", &[("core-lib", ">=1.0, <2")], &[]);
        // The dependency has not loaded yet (or failed): the dependent must not load.
        assert!(set.check(&user).unwrap_err().contains("not loaded"));
        assert!(set.check(&lib).is_ok());
        set.add(&lib);
        assert!(set.contains("core-lib"));
        assert!(set.check(&user).is_ok());
        let strict = manifest("strict", "1.0.0", &[("core-lib", ">=2")], &[]);
        assert!(set.check(&strict).unwrap_err().contains("1.4.0 is loaded"));
        // Conflicts both ways.
        let evil = manifest("evil", "1.0.0", &[], &[]);
        assert!(set.check(&evil).unwrap_err().contains("conflicts with it"));
        let hates = manifest("hates", "1.0.0", &[], &["core-lib"]);
        assert!(
            set.check(&hates)
                .unwrap_err()
                .contains("conflicts with core-lib")
        );
    }

    fn write_v2(dir: &Path, id: &str, side: &str, body: &str) {
        let d = dir.join(id);
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("mod.toml"),
            format!(
                "manifest_version = 2\nid = \"{id}\"\nname = \"{id}\"\nversion = \"1.0.0\"\nside = \"{side}\"\n{body}"
            ),
        )
        .unwrap();
    }

    const CLIENT_HALF: &str = "[client]\ndll = \"client/c.dll\"\nhook_api = 1\n";
    const SERVER_HALF: &str = "[[commands]]\nname = \"hi\"\nreply = \"x\"\n";

    #[test]
    fn a_server_only_mod_is_refused_cleanly_and_never_gets_a_dll() {
        let t = tempfile::tempdir().unwrap();
        write_v2(t.path(), "srv", "server", SERVER_HALF);
        write_mod(t.path(), "cli", API, Some("c.dll"));
        enable(t.path(), &["srv", "cli"]);
        let p = plan(t.path(), false, false, None);
        assert_eq!(ids(&p), ["cli"]);
        assert_eq!(p.skipped.len(), 1);
        assert_eq!(p.skipped[0].id, "srv");
        assert!(
            p.skipped[0].reason.contains("server-only mod"),
            "{:?}",
            p.skipped
        );
        assert_eq!(p.other_side.len(), 1);
    }

    #[test]
    fn a_both_mod_loads_its_client_half_and_ignores_the_server_half() {
        let t = tempfile::tempdir().unwrap();
        let both = format!(
            "{CLIENT_HALF}{SERVER_HALF}[server]\nserver_api = 7\n[server.library]\nlinux = \"server/libx.so\"\n"
        );
        write_v2(t.path(), "both-mod", "both", &both);
        fs::create_dir_all(t.path().join("both-mod/client")).unwrap();
        fs::write(t.path().join("both-mod/client/c.dll"), b"MZ").unwrap();
        enable(t.path(), &["both-mod"]);
        let p = plan(t.path(), false, false, None);
        // The server library is missing and built for another API: irrelevant to the client.
        assert_eq!(ids(&p), ["both-mod"], "{:?}", p.skipped);
        assert_eq!(
            p.mods[0].dll.as_deref(),
            Some(t.path().join("both-mod/client/c.dll").as_path())
        );
        // A client DLL that is missing still skips it.
        fs::remove_file(t.path().join("both-mod/client/c.dll")).unwrap();
        let p = plan(t.path(), false, false, None);
        assert!(p.mods.is_empty());
        assert!(p.skipped[0].reason.contains("entry DLL"), "{:?}", p.skipped);
    }

    #[test]
    fn a_v2_client_mod_with_the_wrong_hook_api_is_still_refused() {
        let t = tempfile::tempdir().unwrap();
        write_v2(
            t.path(),
            "newer",
            "client",
            "[client]\ndll = \"c.dll\"\nhook_api = 99\n",
        );
        enable(t.path(), &["newer"]);
        let p = plan(t.path(), false, false, None);
        assert!(
            p.skipped[0].reason.contains("mod ABI 99"),
            "{:?}",
            p.skipped
        );
    }

    #[test]
    fn server_api_check_mirrors_the_hook_api_check() {
        let mut m = Manifest {
            id: "ab".into(),
            server_linux: Some("server/libx.so".into()),
            server_api: Some(2),
            ..Default::default()
        };
        assert!(check_server_api(&m, 2).is_ok());
        assert!(
            check_server_api(&m, 1)
                .unwrap_err()
                .contains("update the server")
        );
        assert!(
            check_server_api(&m, 3)
                .unwrap_err()
                .contains("rebuild the mod")
        );
        m.server_api = None;
        assert!(
            check_server_api(&m, 2)
                .unwrap_err()
                .contains("server.server_api")
        );
        // Commands and data need no library, so no number.
        m.server_linux = None;
        assert!(check_server_api(&m, 2).is_ok());
    }

    fn sided(id: &str, side: Side, deps: &[(&str, &str)], conflicts: &[&str]) -> Manifest {
        Manifest {
            side,
            ..manifest(id, "1.0.0", deps, conflicts)
        }
    }

    #[test]
    fn dependencies_and_conflicts_cross_sides() {
        let mut set = LoadSet::default();
        set.add_foreign(&sided("srv-lib", Side::Server, &[], &["clash"]));
        // A both mod may depend on a server-only mod (the dependency matters on the server).
        let both = sided("user", Side::Both, &[("srv-lib", "^1")], &[]);
        assert!(set.check(&both).is_ok());
        // A client-only mod cannot: it has no half the dependency could serve.
        let client = sided("user", Side::Client, &[("srv-lib", "^1")], &[]);
        let e = set.check(&client).unwrap_err();
        assert!(e.contains("other side"), "{e}");
        // The version still has to fit.
        let strict = sided("user", Side::Both, &[("srv-lib", ">=2")], &[]);
        assert!(set.check(&strict).unwrap_err().contains("1.0.0 is loaded"));
        // Conflicts hold across sides, in both directions.
        let hates = sided("hates", Side::Client, &[], &["srv-lib"]);
        assert!(
            set.check(&hates)
                .unwrap_err()
                .contains("conflicts with srv-lib")
        );
        let clash = sided("clash", Side::Client, &[], &[]);
        assert!(
            set.check(&clash)
                .unwrap_err()
                .contains("srv-lib conflicts with it")
        );
    }
}
