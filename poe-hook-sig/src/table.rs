//! The signature table (`signatures/<version>.toml`): the format, parsing and validation.
//!
//! ```toml
//! [build]
//! version = "0.5.5e"
//! build_revision = "323943"
//! revision_pattern = "20 <rev:bytes6> 00 25 53 2e 70 6f 65 63 61 70"
//! pe_timestamp = 0x6ac302e0
//! image_size = 0x04ca0000
//!
//! [[sig]]                      # a function: unique match of the pattern in the code sections
//! name = "client_platform_detect"
//! features = ["login_patch"]   # the features that are off when this one does not resolve
//! pattern = "40 55 53 56 57 ..."
//! ghidra = 0x142196ec0         # the 0.5.5e address: logged and sanity-checked, never used
//! expect = "40 55 53"          # bytes required at the resolved address (patches: exact)
//! patch = "31 c0 c3"
//! pdata = true                 # the address must start a .pdata function
//!
//! [[field]]                    # a struct offset read from an instruction operand
//! name = "positioned.facing"
//! features = ["dump_object_types"]
//! anchor = "positioned_set_orientation"   # searched inside that function only
//! pattern = "c7 81 <v:4> 00 00 00 00"
//! capture = "v"
//! value = 0x44c                # the 0.5.5e value (a different one is logged as a change)
//! ```

use serde::Deserialize;

use crate::pattern::{CaptureKind, Pattern, parse_exact_bytes};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Table {
    pub build: Build,
    #[serde(default)]
    pub sig: Vec<Sig>,
    #[serde(default)]
    pub field: Vec<Field>,
}

/// Identity of the build the table is for.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    pub version: String,
    /// The ASCII build revision (`Build Revision:` in `Client.txt`).
    pub build_revision: String,
    /// Finds the revision string in the data sections: a pattern with a `<rev:bytesN>` capture.
    pub revision_pattern: Option<String>,
    /// `IMAGE_FILE_HEADER.TimeDateStamp`.
    pub pe_timestamp: u32,
    /// `IMAGE_OPTIONAL_HEADER.SizeOfImage`.
    pub image_size: u32,
    /// Only the host tool (`check-build`) can afford to hash 78 MB.
    pub exe_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A function: the pattern (unique in the code sections) matches at its start.
    #[default]
    Function,
    /// An address inside a function, found from an anchor function. Instruction boundary
    /// checked.
    Site,
    /// The address a RIP-relative operand of the pattern refers to (a call target, a global, a
    /// vtable).
    Ref,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sig {
    pub name: String,
    /// Features that need this entry; when it does not resolve they are off.
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub kind: Kind,
    pub pattern: Option<String>,
    /// Bytes from the match start to the address (`function`, `site` with a pattern).
    #[serde(default)]
    pub offset: i64,
    /// A function entry the search is limited to (`site`, `ref`, or any entry that cannot be
    /// unique in the whole image).
    pub anchor: Option<String>,
    /// `site` without a pattern: bytes from the anchor's start to the site.
    pub anchor_offset: Option<u64>,
    /// `ref`: the RIP-relative capture whose target is the address.
    pub capture: Option<String>,
    /// The 0.5.5e address (Ghidra, image base 0x140000000). Logging and sanity only.
    pub ghidra: Option<u64>,
    /// Pattern (wildcards allowed; exact bytes when `patch` is set) that must match at the
    /// resolved address.
    pub expect: Option<String>,
    /// Bytes a patch writes at the address (only after `expect` matched).
    pub patch: Option<String>,
    /// The resolved address must be the start of a `.pdata` function.
    #[serde(default)]
    pub pdata: bool,
    /// Free text for people.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    #[serde(default)]
    pub features: Vec<String>,
    pub anchor: Option<String>,
    pub pattern: String,
    pub capture: String,
    /// The 0.5.5e value.
    pub value: Option<u64>,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub align: Option<u64>,
    /// Another field that must have the same value (both read the same member).
    pub agrees_with: Option<String>,
    pub note: Option<String>,
}

impl Sig {
    pub fn parsed_pattern(&self) -> Option<Pattern> {
        self.pattern.as_deref().and_then(|p| Pattern::parse(p).ok())
    }
}

impl Table {
    /// Parses and validates a table.
    pub fn parse(text: &str) -> Result<Self, String> {
        let table: Table = toml::from_str(text).map_err(|e| format!("signature table: {e}"))?;
        let errors = table.validate();
        if errors.is_empty() {
            Ok(table)
        } else {
            Err(format!("signature table: {}", errors.join("; ")))
        }
    }

    pub fn sig(&self, name: &str) -> Option<&Sig> {
        self.sig.iter().find(|s| s.name == name)
    }

    pub fn field(&self, name: &str) -> Option<&Field> {
        self.field.iter().find(|f| f.name == name)
    }

    /// Every feature name any entry lists.
    pub fn features(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .sig
            .iter()
            .flat_map(|s| s.features.iter())
            .chain(self.field.iter().flat_map(|f| f.features.iter()))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Everything that is wrong with the table itself (not with a build).
    pub fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        let mut names = std::collections::HashSet::new();
        if let Some(p) = &self.build.revision_pattern {
            match Pattern::parse(p) {
                Ok(p)
                    if p.capture("rev")
                        .is_some_and(|c| c.kind == CaptureKind::Bytes) => {}
                Ok(_) => e.push("build.revision_pattern needs a <rev:bytesN> capture".into()),
                Err(x) => e.push(format!("build.revision_pattern: {x}")),
            }
        }
        for s in &self.sig {
            let n = &s.name;
            if !names.insert(format!("sig:{n}")) {
                e.push(format!("sig `{n}` is defined twice"));
            }
            let pattern = match s.pattern.as_deref().map(Pattern::parse) {
                Some(Ok(p)) => Some(p),
                Some(Err(x)) => {
                    e.push(format!("sig `{n}`: pattern: {x}"));
                    None
                }
                None => None,
            };
            if let Some(a) = &s.anchor {
                match self.sig(a) {
                    None => e.push(format!("sig `{n}`: unknown anchor `{a}`")),
                    Some(_) if a == n => e.push(format!("sig `{n}` is its own anchor")),
                    Some(_) => {}
                }
            }
            match s.kind {
                Kind::Function => {
                    if pattern.is_none() {
                        e.push(format!("sig `{n}`: a function needs a pattern"));
                    }
                    if s.anchor.is_some() {
                        e.push(format!("sig `{n}`: a function has no anchor"));
                    }
                    if pattern.as_ref().is_some_and(|p| p.key().is_none()) {
                        e.push(format!(
                            "sig `{n}`: pattern has no two fixed bytes in a row"
                        ));
                    }
                }
                Kind::Site => {
                    if s.anchor.is_none() {
                        e.push(format!("sig `{n}`: a site needs an anchor"));
                    }
                    if pattern.is_none() == s.anchor_offset.is_none() {
                        e.push(format!(
                            "sig `{n}`: a site needs either a pattern or an anchor_offset"
                        ));
                    }
                    if s.expect.is_none() {
                        e.push(format!("sig `{n}`: a site needs the expected bytes"));
                    }
                }
                Kind::Ref => {
                    let Some(p) = &pattern else {
                        e.push(format!("sig `{n}`: a ref needs a pattern"));
                        continue;
                    };
                    match s.capture.as_deref().and_then(|c| p.capture(c)) {
                        Some(c) if matches!(c.kind, CaptureKind::Rip { .. }) => {}
                        _ => e.push(format!(
                            "sig `{n}`: a ref needs a rip4 capture named in `capture`"
                        )),
                    }
                    if s.anchor.is_none() && p.key().is_none() {
                        e.push(format!(
                            "sig `{n}`: pattern has no two fixed bytes in a row"
                        ));
                    }
                }
            }
            if let Some(x) = &s.expect
                && let Err(x) = Pattern::parse(x)
            {
                e.push(format!("sig `{n}`: expect: {x}"));
            }
            if let Some(p) = &s.patch {
                match (
                    parse_exact_bytes(p),
                    s.expect.as_deref().map(parse_exact_bytes),
                ) {
                    (Ok(patch), Some(Ok(expect))) if patch.len() == expect.len() => {}
                    (Ok(_), Some(Ok(_))) => {
                        e.push(format!("sig `{n}`: patch and expect differ in length"))
                    }
                    (Err(x), _) => e.push(format!("sig `{n}`: patch: {x}")),
                    _ => e.push(format!("sig `{n}`: a patch needs exact `expect` bytes")),
                }
            }
        }
        for f in &self.field {
            let n = &f.name;
            if !names.insert(format!("field:{n}")) {
                e.push(format!("field `{n}` is defined twice"));
            }
            match Pattern::parse(&f.pattern) {
                Ok(p) => match p.capture(&f.capture) {
                    Some(c) if c.kind == CaptureKind::Le => {}
                    _ => e.push(format!(
                        "field `{n}`: capture `{}` is not an integer capture",
                        f.capture
                    )),
                },
                Err(x) => e.push(format!("field `{n}`: pattern: {x}")),
            }
            if let Some(a) = &f.anchor
                && self.sig(a).is_none()
            {
                e.push(format!("field `{n}`: unknown anchor `{a}`"));
            }
            if let Some(p) = &f.agrees_with
                && (self.field(p).is_none() || p == n)
            {
                e.push(format!(
                    "field `{n}`: agrees_with `{p}` is not another field"
                ));
            }
            if f.align == Some(0) {
                e.push(format!("field `{n}`: align 0"));
            }
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: &str =
        "[build]\nversion=\"t\"\nbuild_revision=\"1\"\npe_timestamp=1\nimage_size=2\n";

    fn parse(body: &str) -> Result<Table, String> {
        Table::parse(&format!("{BUILD}{body}"))
    }

    #[test]
    fn accepts_a_small_table() {
        let t = parse(
            r#"
[[sig]]
name = "a"
features = ["f"]
pattern = "40 55 53 ?? ??"
ghidra = 0x142196ec0
expect = "40 55 53"
patch = "31 c0 c3"
[[sig]]
name = "b"
kind = "site"
anchor = "a"
anchor_offset = 4
expect = "90"
[[sig]]
name = "c"
kind = "ref"
anchor = "a"
pattern = "8b 05 <g:rip4>"
capture = "g"
[[field]]
name = "x.y"
features = ["f", "g"]
anchor = "a"
pattern = "c7 81 <v:4>"
capture = "v"
value = 0x44c
"#,
        )
        .unwrap();
        assert_eq!(t.features(), ["f", "g"]);
        assert_eq!(t.sig("a").unwrap().ghidra, Some(0x1_4219_6ec0));
        assert_eq!(t.field("x.y").unwrap().value, Some(0x44c));
    }

    #[test]
    fn rejects_inconsistent_entries() {
        for (body, needle) in [
            ("[[sig]]\nname=\"a\"\n", "needs a pattern"),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 8b\"\n[[sig]]\nname=\"a\"\npattern=\"48 8b\"\n",
                "twice",
            ),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 8b\"\nanchor=\"zz\"\n",
                "unknown anchor",
            ),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 ?? 8b\"\n",
                "two fixed bytes",
            ),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 8b\"\npatch=\"90\"\n",
                "exact",
            ),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 8b\"\npatch=\"90\"\nexpect=\"90 90\"\n",
                "differ",
            ),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 8b\"\n[[sig]]\nname=\"s\"\nkind=\"site\"\nanchor=\"a\"\n",
                "pattern or an anchor_offset",
            ),
            (
                "[[sig]]\nname=\"a\"\npattern=\"48 8b\"\n[[sig]]\nname=\"r\"\nkind=\"ref\"\npattern=\"8b 05 <g:4>\"\ncapture=\"g\"\n",
                "rip4",
            ),
            (
                "[[field]]\nname=\"f\"\npattern=\"c7 81 <v:4>\"\ncapture=\"w\"\n",
                "not an integer",
            ),
            (
                "[[field]]\nname=\"f\"\npattern=\"c7 81 <v:4>\"\ncapture=\"v\"\nagrees_with=\"g\"\n",
                "agrees_with",
            ),
        ] {
            let err = parse(body).expect_err(body);
            assert!(err.contains(needle), "{body:?}: {err}");
        }
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(parse("[[sig]]\nname=\"a\"\npattern=\"48 8b\"\nbogus=1\n").is_err());
    }
}
