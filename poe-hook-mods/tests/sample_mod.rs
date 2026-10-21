//! The shipped sample mod must stay loadable by this loader: its manifest parses, states the
//! ABI the loader offers, and a state.toml that enables it yields a plan with its DLL.

use std::fs;

use poe_hook_mods::{HOOK_API, check_abi, parse_manifest, plan, state_text};

const SAMPLE: &str = include_str!("../../examples/sample-mod/mod.toml");

#[test]
fn sample_mod_manifest_is_valid_and_matches_the_abi() {
    let p = parse_manifest(SAMPLE).unwrap();
    assert!(p.unknown_keys.is_empty(), "{:?}", p.unknown_keys);
    let m = p.manifest;
    assert_eq!(m.id, "sample-mod");
    assert_eq!(m.hook_api, Some(HOOK_API));
    assert_eq!(m.entry_dll.as_deref(), Some("sample_mod.dll"));
    assert!(check_abi(&m).is_ok());
}

#[test]
fn sample_mod_is_planned_when_enabled_and_not_in_official_mode() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("sample-mod");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("mod.toml"), SAMPLE).unwrap();
    fs::write(dir.join("sample_mod.dll"), b"MZ").unwrap();
    fs::write(
        t.path().join("state.toml"),
        state_text(&["sample-mod".to_owned()]),
    )
    .unwrap();

    let p = plan(t.path(), false, false, Some("0.5.5e"));
    assert_eq!(p.mods.len(), 1, "{:?}", p.skipped);
    assert_eq!(
        p.mods[0].dll.as_deref(),
        Some(dir.join("sample_mod.dll").as_path())
    );
    assert!(p.mods[0].warnings.is_empty());

    let official = plan(t.path(), true, false, Some("0.5.5e"));
    assert!(official.mods.is_empty() && official.refused.is_some());
}
