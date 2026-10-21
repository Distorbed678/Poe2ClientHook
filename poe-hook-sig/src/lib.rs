//! The client DLL's signature table: finding functions, mid-function sites, globals and struct
//! offsets in the game executable by byte patterns instead of fixed addresses.
//!
//! Pure Rust without Windows dependencies, so the DLLs (on the loaded image) and the host
//! tools (`cargo xtask check-build`, on the exe file) use the same code:
//!
//! - [`pattern`]: patterns with wildcards and captures;
//! - [`pe`]: PE headers, `.pdata`, mapping a file into memory layout;
//! - [`scan`]: single and multi-pattern search;
//! - [`table`]: the `signatures/<version>.toml` format and its validation;
//! - [`resolve`]: resolving a table against an image, per-feature status;
//! - [`embedded`]: the tables compiled into the DLLs.

pub mod embedded;
pub mod pattern;
pub mod pe;
pub mod resolve;
pub mod scan;
pub mod table;

pub use embedded::{Resolved, resolve_embedded};
pub use pattern::Pattern;
pub use pe::{Image, PeInfo, map_file};
pub use resolve::{BuildCheck, Failure, FeatureStatus, Resolution, resolve};
pub use table::Table;
