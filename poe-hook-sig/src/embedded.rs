//! The tables compiled into the DLLs, and picking one for an image.

use crate::{pe::PeInfo, table::Table};

/// `(version, table text)` of every supported build, oldest first.
pub const TABLES: &[(&str, &str)] = &[("0.5.5e", include_str!("../../signatures/0.5.5e.toml"))];

/// All embedded tables, parsed. A table that does not parse is a build error of the DLL
/// (the unit tests parse every one).
pub fn tables() -> Result<Vec<Table>, String> {
    TABLES
        .iter()
        .map(|(v, text)| Table::parse(text).map_err(|e| format!("{v}: {e}")))
        .collect()
}

/// The table for an image: the one whose timestamp and size match, else the newest one.
/// The flag is `true` for an exact (timestamp and size) match.
pub fn select(tables: &[Table], info: &PeInfo) -> Option<(usize, bool)> {
    tables
        .iter()
        .position(|t| {
            t.build.pe_timestamp == info.timestamp && t.build.image_size == info.size_of_image
        })
        .map(|i| (i, true))
        .or_else(|| tables.len().checked_sub(1).map(|i| (i, false)))
}

/// The table chosen for an image and what resolving it gave.
pub struct Resolved {
    pub table: Table,
    pub resolution: crate::resolve::Resolution,
    /// The image's timestamp and size are the table's (a known build). Otherwise the newest
    /// table was tried as a candidate.
    pub exact: bool,
}

/// Picks the embedded table for the mapped image `mapped` and resolves it (only the entries of
/// `features`, or everything with `None`).
pub fn resolve_embedded(mapped: &[u8], features: Option<&[&str]>) -> Result<Resolved, String> {
    let image = crate::pe::Image::from_mapped(mapped)?;
    let mut all = tables()?;
    let (i, exact) = select(&all, &image.info).ok_or("no signature table is embedded")?;
    let table = all.swap_remove(i);
    let resolution = crate::resolve::resolve(&table, &image, features);
    Ok(Resolved {
        table,
        resolution,
        exact,
    })
}
