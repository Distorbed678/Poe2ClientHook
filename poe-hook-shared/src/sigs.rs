//! The signature table in a running process: resolves it once against the loaded game image
//! and answers "where is X" / "does feature Y have everything it needs". The matcher,
//! the table format and the rules live in `poe-hook-sig` (pure Rust, also used by the host
//! tools); this module only feeds it the loaded module and logs the result.
//!
//! The tables are embedded in the DLLs at build time (`signatures/<version>.toml`,
//! `include_str!`), not read from disk: a table that does not match the DLL's code would be
//! a way to get a hook installed on the wrong bytes, and the DLL is rebuilt with the table
//! anyway. The build is chosen by the image's PE timestamp and size; an unknown build is tried
//! with the newest table and reported as unverified.
//!
//! Resolved once per DLL load (the loader resolves only the login entries, before it patches
//! them; the core resolves the rest). A signature that matches zero or several times, or
//! whose address holds other bytes than the table expects, disables the features that list
//! it, with a log line naming the entry. Nothing is hooked or patched on a guess.

use std::ops::Range;

use crate::module::Module;
use poe_hook_sig::{Image, Resolved, resolve_embedded};

/// Features the loader (`version.dll`) resolves and applies itself, before the core exists.
/// The core must not resolve them: by then the loader has patched their first bytes.
pub const LOADER_FEATURES: &[&str] = &["login_patch", "login_cache", "patcher_skip"];

/// Features that only read memory with guarded reads and observe: the only ones that start
/// on an official server when the build is not the one the table was made for.
pub const OBSERVE_ONLY: &[&str] = &["packets", "crash_log", "exit_trace"];

pub struct Loaded {
    resolved: Resolved,
    base: usize,
    size: usize,
}

impl Loaded {
    /// Resolves the embedded table against `main`'s loaded image (`features`: only those
    /// entries; `None`: everything).
    pub fn resolve(main: &Module, features: Option<&[&str]>) -> Result<Self, String> {
        // The mapped image of the game executable: committed for its whole size.
        let image = unsafe { std::slice::from_raw_parts(main.base as *const u8, main.size) };
        let resolved = resolve_embedded(image, features)?;
        Ok(Self {
            resolved,
            base: main.base,
            size: main.size,
        })
    }

    /// Features of the table other than the loader's.
    pub fn core_features() -> Result<Vec<String>, String> {
        Ok(poe_hook_sig::embedded::tables()?
            .iter()
            .flat_map(|t| t.features())
            .filter(|f| !LOADER_FEATURES.contains(&f.as_str()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    pub fn table(&self) -> &poe_hook_sig::Table {
        &self.resolved.table
    }

    pub fn resolution(&self) -> &poe_hook_sig::Resolution {
        &self.resolved.resolution
    }

    /// The build is the table's (timestamp, size and revision string all agree).
    pub fn verified(&self) -> bool {
        self.resolved.exact && self.resolved.resolution.build.verified()
    }

    /// Every entry the feature needs resolved (a feature the table does not list is fine).
    pub fn feature_ok(&self, feature: &str) -> bool {
        self.resolved.resolution.feature_ok(feature)
    }

    /// Why a feature is off (empty when it is on).
    pub fn feature_problem(&self, feature: &str) -> String {
        self.resolved.resolution.feature_problem(feature)
    }

    /// Runtime address of a resolved signature.
    pub fn addr(&self, name: &str) -> Result<usize, String> {
        match self.resolved.resolution.sigs.get(name) {
            Some(Ok(r)) => Ok(self.base + r.rva as usize),
            Some(Err(e)) => Err(format!("signature {name}: {e}")),
            None => Err(format!("signature {name} was not resolved")),
        }
    }

    /// The resolved value of a struct offset.
    pub fn field(&self, name: &str) -> Option<usize> {
        self.resolved.resolution.field(name).map(|v| v as usize)
    }

    /// The `.pdata` range (runtime addresses) of the function a resolved signature points at.
    pub fn function_range(&self, name: &str) -> Option<Range<usize>> {
        let rva = self.resolved.resolution.rva(name)?;
        let data = unsafe { std::slice::from_raw_parts(self.base as *const u8, self.size) };
        let image = Image::from_mapped(data).ok()?;
        let (b, e) = image.function_range(rva)?;
        Some(self.base + b as usize..self.base + e as usize)
    }

    /// The expected and the replacement bytes of a patch entry.
    pub fn patch_bytes(&self, name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        self.resolved.table.patch_bytes(name)
    }

    /// Ghidra address (image base 0x140000000) of a runtime address, for logs.
    pub fn ghidra(&self, addr: usize) -> usize {
        addr - self.base + self.resolved.resolution.image_base as usize
    }

    /// One log record per line of the resolution summary (errors for features that are off).
    pub fn log_summary(&self) {
        for line in self.resolved.resolution.summary() {
            if line.contains("OFF") {
                log::error!("{line}");
            } else if line.contains("NOT verified") {
                log::warn!("{line}");
            } else {
                log::info!("{line}");
            }
        }
        if !self.resolved.exact {
            log::warn!(
                "signatures: this executable is not a build the DLL knows (timestamp/size differ); \
                 table {} used as a candidate",
                self.resolved.table.build.version
            );
        }
    }
}
