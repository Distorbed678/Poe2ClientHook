//! Resolves the signature table against a PE file on disk and compares the result with the
//! table's fallback values (the 0.5.5e Ghidra addresses and struct offsets).
//!
//! ```text
//! cargo run --release -p poe-hook-sig --example resolve -- GameFiles/PathOfExileSteam.exe [table.toml] [--quiet]
//! ```
//! Without a table path the embedded tables are used (selected by the exe's timestamp and
//! size). Exit code: 0 everything resolved and equals the fallback values; 1 some entry did
//! not resolve or differs from its fallback; 2 usage or file error.

use std::process::ExitCode;

use poe_hook_sig::{Image, PeInfo, Table, embedded, map_file, resolve};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quiet = args.iter().any(|a| a == "--quiet");
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let Some(exe) = paths.first() else {
        eprintln!("usage: resolve <exe> [table.toml] [--quiet]");
        return ExitCode::from(2);
    };
    let file = match std::fs::read(exe) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{exe}: {e}");
            return ExitCode::from(2);
        }
    };
    let mapped = match map_file(&file) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{exe}: {e}");
            return ExitCode::from(2);
        }
    };
    let image = Image::from_mapped(&mapped).expect("mapped image parses");
    let table = match paths.get(1) {
        Some(p) => match std::fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|t| Table::parse(&t))
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => {
            let tables = embedded::tables().expect("embedded tables parse");
            let info: &PeInfo = &image.info;
            let (i, exact) = embedded::select(&tables, info).expect("a table");
            println!(
                "table {} ({})",
                tables[i].build.version,
                if exact {
                    "exact match"
                } else {
                    "candidate only"
                }
            );
            tables[i].clone()
        }
    };
    let start = std::time::Instant::now();
    let res = resolve(&table, &image, None);
    println!(
        "resolved in {:.0} ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
    println!("{}", res.build.describe());
    let mut bad = 0;
    for s in &table.sig {
        match &res.sigs[&s.name] {
            Ok(r) => {
                let va = res.image_base + r.rva;
                let same = s.ghidra.map(|g| g == va);
                if !quiet || same == Some(false) {
                    println!(
                        "sig   {:<32} {va:#x} {}",
                        s.name,
                        match same {
                            Some(true) => "= ghidra".to_string(),
                            Some(false) => format!("!= ghidra {:#x}", s.ghidra.unwrap()),
                            None => "(no ghidra address)".to_string(),
                        }
                    );
                }
                if same == Some(false) {
                    bad += 1;
                }
            }
            Err(e) => {
                println!("sig   {:<32} FAILED: {e}", s.name);
                bad += 1;
            }
        }
    }
    for f in &table.field {
        match &res.fields[&f.name] {
            Ok(r) => {
                let same = r.changed_from.is_none();
                if !quiet || !same {
                    println!(
                        "field {:<32} {:#x} {}",
                        f.name,
                        r.value,
                        if same {
                            "= table value".to_string()
                        } else {
                            format!("!= table value {:#x}", r.changed_from.unwrap())
                        }
                    );
                }
                if !same {
                    bad += 1;
                }
            }
            Err(e) => {
                println!("field {:<32} FAILED: {e}", f.name);
                bad += 1;
            }
        }
    }
    for line in res.summary() {
        if !quiet || line.contains("OFF") || line.contains("NOT") {
            println!("{line}");
        }
    }
    println!(
        "{} signatures, {} fields, {bad} problems",
        table.sig.len(),
        table.field.len()
    );
    if bad == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
