//! The embedded signature table against the real game executable (client 0.5.5e).
//!
//! The exe is not in the repository: the tests look for `$POE_EXE`, else
//! `<repo>/GameFiles/PathOfExileSteam.exe` (this crate is `modules/client-hook/poe-hook-sig`
//! inside the Poe2ModdingProject checkout), and skip with a message when there is none.
//! The file is only read.

use poe_hook_sig::{Failure, Image, embedded, map_file, resolve};

fn exe() -> Option<Vec<u8>> {
    let path = std::env::var_os("POE_EXE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../GameFiles/PathOfExileSteam.exe")
        });
    match std::fs::read(&path) {
        Ok(f) => Some(f),
        Err(_) => {
            eprintln!("skipped: no game executable at {}", path.display());
            None
        }
    }
}

#[test]
fn the_table_resolves_to_the_0_5_5e_addresses_and_offsets() {
    let Some(file) = exe() else { return };
    let mapped = map_file(&file).unwrap();
    let image = Image::from_mapped(&mapped).unwrap();
    let tables = embedded::tables().unwrap();
    let (i, exact) = embedded::select(&tables, &image.info).unwrap();
    assert!(exact, "the exe is not the build of the embedded table");
    let table = &tables[i];
    let r = resolve(table, &image, None);
    assert!(r.build.verified(), "{}", r.build.describe());
    let mut bad = Vec::new();
    for s in &table.sig {
        match &r.sigs[&s.name] {
            Ok(res) => {
                let va = r.image_base + res.rva;
                match s.ghidra {
                    Some(g) if g == va => {}
                    other => bad.push(format!("{}: {va:#x} vs table {other:x?}", s.name)),
                }
            }
            Err(e) => bad.push(format!("{}: {e}", s.name)),
        }
    }
    for f in &table.field {
        match &r.fields[&f.name] {
            Ok(res) if res.changed_from.is_none() && Some(res.value) == f.value => {}
            other => bad.push(format!("field {}: {other:?}", f.name)),
        }
    }
    assert!(
        bad.is_empty(),
        "{} problems:\n{}",
        bad.len(),
        bad.join("\n")
    );
    for f in table.features() {
        assert!(
            r.feature_ok(&f),
            "feature {f} is off: {}",
            r.feature_problem(&f)
        );
    }
    // The count the docs quote.
    assert!(table.sig.len() >= 80 && table.field.len() >= 45);
}

#[test]
fn a_mutated_executable_makes_the_affected_entries_fail() {
    let Some(file) = exe() else { return };
    let mut mapped = map_file(&file).unwrap();
    let tables = embedded::tables().unwrap();
    let table = &tables[0];
    let base = 0x1_4000_0000u64;
    // 1. The first byte of a function (client_platform_detect) and of a site.
    for (name, features_off) in [
        ("client_platform_detect", vec!["login_patch"]),
        ("verify_and_derive", vec!["crypto_bypass"]),
        ("instance_ciphers", vec!["side_channel"]),
        ("read_message", vec!["packets"]),
    ] {
        let rva = (table.sig(name).unwrap().ghidra.unwrap() - base) as usize;
        let before = mapped[rva];
        mapped[rva] ^= 0xff;
        let image = Image::from_mapped(&mapped).unwrap();
        let r = resolve(table, &image, None);
        assert_eq!(r.sigs[name], Err(Failure::Missing), "{name}");
        for f in &features_off {
            assert!(!r.feature_ok(f), "{f} must be off when {name} is missing");
        }
        // Everything that does not need it still resolves.
        assert!(
            r.feature_ok("area_export"),
            "{}",
            r.feature_problem("area_export")
        );
        mapped[rva] = before;
    }
    // 2. Breaking an anchor takes its fields and refs down with it.
    let anchor = (table.sig("read_initial_state").unwrap().ghidra.unwrap() - base) as usize;
    let before = mapped[anchor];
    mapped[anchor] ^= 0xff;
    let image = Image::from_mapped(&mapped).unwrap();
    let r = resolve(table, &image, None);
    assert_eq!(r.sigs["read_initial_state"], Err(Failure::Missing));
    assert_eq!(
        r.fields["entity.type"],
        Err(Failure::AnchorFailed("read_initial_state".into()))
    );
    assert!(!r.feature_ok("dump_object_types"));
    assert!(r.feature_ok("packets"));
    mapped[anchor] = before;
    // 3. The unmodified copy is fine again.
    let image = Image::from_mapped(&mapped).unwrap();
    assert!(resolve(table, &image, None).features.values().all(|f| f.ok));
}
