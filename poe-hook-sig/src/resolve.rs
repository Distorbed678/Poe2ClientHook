//! Resolving a [`Table`] against an image: addresses and struct offsets, per-feature status.
//!
//! Rules (see docs/architecture/client-dll.md):
//! - a `function` entry must match exactly once in the code sections; `site`, `ref` and field
//!   entries with an `anchor` must match exactly once inside the anchor function;
//! - zero or several matches, a failed anchor, wrong bytes at the address, a site that is not
//!   an instruction boundary, a value outside its limits: the entry has failed and every
//!   feature that lists it is off;
//! - nothing is patched or hooked here: this only reads.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use iced_x86::{Decoder, DecoderOptions};

use crate::{
    pattern::{Pattern, parse_exact_bytes},
    pe::Image,
    scan::{Hits, find_all, scan_code},
    table::{Field, Kind, Sig, Table},
};

/// Whether the image is the build the table was made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildCheck {
    pub table_version: String,
    pub timestamp_ok: bool,
    pub size_ok: bool,
    /// The revision string found in the image, if the table can find it.
    pub revision_found: Option<String>,
    pub revision_expected: String,
    /// The table has a `revision_pattern`.
    pub revision_checked: bool,
}

impl BuildCheck {
    /// Timestamp, size and revision all agree with the table.
    pub fn verified(&self) -> bool {
        self.timestamp_ok
            && self.size_ok
            && (!self.revision_checked
                || self.revision_found.as_deref() == Some(self.revision_expected.as_str()))
    }

    pub fn describe(&self) -> String {
        let rev = match (&self.revision_found, self.revision_checked) {
            (Some(r), _) => format!("revision {r}"),
            (None, true) => "revision not found".into(),
            (None, false) => "revision not checked".into(),
        };
        format!(
            "table {}: timestamp {}, size {}, {rev} (expected {})",
            self.table_version,
            if self.timestamp_ok { "ok" } else { "DIFFERENT" },
            if self.size_ok { "ok" } else { "DIFFERENT" },
            self.revision_expected
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The pattern matched nowhere.
    Missing,
    /// The pattern matched more than once (the count).
    Ambiguous(usize),
    /// The anchor entry did not resolve.
    AnchorFailed(String),
    /// The anchor has no `.pdata` function.
    NoFunctionRange,
    /// The bytes at the resolved address are not the expected ones.
    ExpectMismatch { found: Vec<u8> },
    /// The address is not the start of a `.pdata` function.
    NotFunctionStart,
    /// The site is not the start of an instruction (or the decode ran into data).
    NotBoundary,
    /// The address or value is outside what is plausible.
    OutOfRange(u64),
    /// The captured value broke a limit of the entry.
    Limit(String),
    /// A field that must equal another field does not.
    Disagrees {
        other: String,
        mine: u64,
        theirs: u64,
    },
    /// The table entry is unusable (should have been caught by validation).
    Invalid(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Missing => write!(f, "matched 0 times"),
            Failure::Ambiguous(n) => write!(f, "ambiguous: matched {n} times"),
            Failure::AnchorFailed(a) => write!(f, "anchor `{a}` did not resolve"),
            Failure::NoFunctionRange => write!(f, "anchor is not in .pdata"),
            Failure::ExpectMismatch { found } => {
                write!(
                    f,
                    "bytes at the address are {found:02x?}, not the expected ones"
                )
            }
            Failure::NotFunctionStart => write!(f, "address does not start a .pdata function"),
            Failure::NotBoundary => write!(f, "site is not an instruction boundary"),
            Failure::OutOfRange(v) => write!(f, "value {v:#x} out of range"),
            Failure::Limit(s) => write!(f, "{s}"),
            Failure::Disagrees {
                other,
                mine,
                theirs,
            } => {
                write!(f, "value {mine:#x} disagrees with {other} ({theirs:#x})")
            }
            Failure::Invalid(s) => write!(f, "invalid entry: {s}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigResolved {
    /// RVA of the resolved address.
    pub rva: u64,
    /// Differs from the table's `ghidra` address by this many bytes (a rebuilt exe), if set.
    pub moved: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldResolved {
    pub value: u64,
    /// The table's value, when it differs from this build's.
    pub changed_from: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureStatus {
    pub name: String,
    pub ok: bool,
    /// Entries (signatures and fields) the feature needs.
    pub entries: usize,
    /// What failed, as `sig NAME: reason` lines.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Resolution {
    pub build: BuildCheck,
    pub image_base: u64,
    pub sigs: BTreeMap<String, Result<SigResolved, Failure>>,
    pub fields: BTreeMap<String, Result<FieldResolved, Failure>>,
    pub features: BTreeMap<String, FeatureStatus>,
}

impl Resolution {
    /// RVA of a resolved signature.
    pub fn rva(&self, name: &str) -> Option<u64> {
        self.sigs.get(name)?.as_ref().ok().map(|r| r.rva)
    }

    /// The resolved value of a field.
    pub fn field(&self, name: &str) -> Option<u64> {
        self.fields.get(name)?.as_ref().ok().map(|r| r.value)
    }

    /// Whether every entry of `feature` resolved. A feature no entry lists is fine.
    pub fn feature_ok(&self, feature: &str) -> bool {
        self.features.get(feature).is_none_or(|f| f.ok)
    }

    /// Why `feature` is off, as one line (empty when it is on).
    pub fn feature_problem(&self, feature: &str) -> String {
        self.features
            .get(feature)
            .map(|f| f.problems.join("; "))
            .unwrap_or_default()
    }

    /// Log lines: the build check, one line per feature, one per moved or changed entry.
    pub fn summary(&self) -> Vec<String> {
        let mut out = vec![self.build.describe()];
        if !self.build.verified() {
            out.push(
                "build NOT verified against the table: results are unverified; research hooks \
                 stay off in official mode"
                    .into(),
            );
        }
        for f in self.features.values() {
            out.push(if f.ok {
                format!("signatures: feature {}: ok ({} entries)", f.name, f.entries)
            } else {
                format!(
                    "signatures: feature {}: OFF ({})",
                    f.name,
                    f.problems.join("; ")
                )
            });
        }
        for (n, r) in &self.sigs {
            if let Ok(SigResolved {
                moved: Some(d),
                rva,
            }) = r
                && *d != 0
            {
                out.push(format!(
                    "signatures: {n} moved by {d:+#x} (now {:#x})",
                    self.image_base + rva
                ));
            }
        }
        for (n, r) in &self.fields {
            if let Ok(FieldResolved {
                value,
                changed_from: Some(old),
            }) = r
            {
                out.push(format!(
                    "signatures: field {n} changed: {old:#x} -> {value:#x}"
                ));
            }
        }
        out
    }
}

/// Resolves `table` against `image`. With `features`, only the entries those features need
/// (and their anchors) are resolved; with `None`, everything.
pub fn resolve(table: &Table, image: &Image, features: Option<&[&str]>) -> Resolution {
    let wanted = |list: &[String]| match features {
        None => true,
        Some(fs) => list.iter().any(|f| fs.contains(&f.as_str())),
    };
    let mut r = Resolver {
        table,
        image,
        sigs: HashMap::new(),
        busy: HashSet::new(),
        scan: HashMap::new(),
    };
    // One pass over the code for every pattern that is searched image-wide.
    let mut global: Vec<(&str, Pattern)> = Vec::new();
    let mut need: HashSet<String> = HashSet::new();
    let sigs: Vec<&Sig> = table.sig.iter().filter(|s| wanted(&s.features)).collect();
    for s in &sigs {
        need.insert(s.name.clone());
    }
    // Anchors of wanted entries are needed too.
    let mut stack: Vec<String> = need.iter().cloned().collect();
    stack.extend(
        table
            .field
            .iter()
            .filter(|f| wanted(&f.features))
            .filter_map(|f| f.anchor.clone()),
    );
    while let Some(n) = stack.pop() {
        if let Some(s) = table.sig(&n) {
            need.insert(n.clone());
            if let Some(a) = &s.anchor
                && !need.contains(a)
            {
                stack.push(a.clone());
            }
        }
    }
    for s in table.sig.iter().filter(|s| need.contains(&s.name)) {
        let global_search = match s.kind {
            Kind::Function => true,
            Kind::Ref => s.anchor.is_none(),
            Kind::Site => false,
        };
        if global_search && let Some(p) = s.parsed_pattern() {
            global.push((s.pattern.as_deref().unwrap(), p));
        }
    }
    for f in table.field.iter().filter(|f| wanted(&f.features)) {
        if f.anchor.is_none()
            && let Ok(p) = Pattern::parse(&f.pattern)
        {
            global.push((&f.pattern, p));
        }
    }
    global.sort_by(|a, b| a.0.cmp(b.0));
    global.dedup_by(|a, b| a.0 == b.0);
    let patterns: Vec<&Pattern> = global.iter().map(|(_, p)| p).collect();
    // Patterns without two fixed bytes in a row cannot go through the bucket scan.
    let (indexed, loose): (Vec<usize>, Vec<usize>) =
        (0..patterns.len()).partition(|i| patterns[*i].key().is_some());
    let hits = scan_code(
        image,
        &indexed.iter().map(|i| patterns[*i]).collect::<Vec<_>>(),
    );
    for (slot, i) in indexed.iter().enumerate() {
        r.scan.insert(global[*i].0.to_owned(), hits[slot].clone());
    }
    for i in loose {
        let mut h = Hits::default();
        for s in image.code_sections() {
            for pos in find_all(image.section_bytes(s), patterns[i]) {
                h.count += 1;
                if h.first.len() < Hits::KEPT {
                    h.first.push(s.rva as u64 + pos as u64);
                }
            }
        }
        r.scan.insert(global[i].0.to_owned(), h);
    }
    let mut out_sigs = BTreeMap::new();
    for s in table.sig.iter().filter(|s| need.contains(&s.name)) {
        out_sigs.insert(s.name.clone(), r.sig(&s.name));
    }
    let mut out_fields: BTreeMap<String, Result<FieldResolved, Failure>> = BTreeMap::new();
    for f in table.field.iter().filter(|f| wanted(&f.features)) {
        out_fields.insert(f.name.clone(), r.field(f));
    }
    // Fields that must agree.
    for f in table.field.iter().filter(|f| wanted(&f.features)) {
        let Some(other) = &f.agrees_with else {
            continue;
        };
        if let (Some(Ok(a)), Some(Ok(b))) = (out_fields.get(&f.name), out_fields.get(other))
            && a.value != b.value
        {
            let (mine, theirs) = (a.value, b.value);
            out_fields.insert(
                f.name.clone(),
                Err(Failure::Disagrees {
                    other: other.clone(),
                    mine,
                    theirs,
                }),
            );
            out_fields.insert(
                other.clone(),
                Err(Failure::Disagrees {
                    other: f.name.clone(),
                    mine: theirs,
                    theirs: mine,
                }),
            );
        }
    }
    let mut features_out: BTreeMap<String, FeatureStatus> = BTreeMap::new();
    for name in table.features() {
        if features.is_some_and(|fs| !fs.contains(&name.as_str())) {
            continue;
        }
        let mut st = FeatureStatus {
            name: name.clone(),
            ok: true,
            entries: 0,
            problems: Vec::new(),
        };
        // Entries that failed only because their anchor did are summed up per anchor.
        let mut lost: BTreeMap<String, usize> = BTreeMap::new();
        let mut note = |st: &mut FeatureStatus, kind: &str, n: &str, e: &Failure| {
            st.ok = false;
            match e {
                Failure::AnchorFailed(a) => *lost.entry(a.clone()).or_default() += 1,
                _ => st.problems.push(format!("{kind} {n}: {e}")),
            }
        };
        for s in table.sig.iter().filter(|s| s.features.contains(&name)) {
            st.entries += 1;
            if let Some(Err(e)) = out_sigs.get(&s.name) {
                note(&mut st, "sig", &s.name, e);
            }
        }
        for f in table.field.iter().filter(|f| f.features.contains(&name)) {
            st.entries += 1;
            if let Some(Err(e)) = out_fields.get(&f.name) {
                note(&mut st, "field", &f.name, e);
            }
        }
        for (a, n) in lost {
            st.problems
                .push(format!("{n} entries need the failed anchor `{a}`"));
        }
        features_out.insert(name, st);
    }
    Resolution {
        build: check_build(table, image),
        image_base: image.info.image_base,
        sigs: out_sigs,
        fields: out_fields,
        features: features_out,
    }
}

struct Resolver<'a> {
    table: &'a Table,
    image: &'a Image<'a>,
    sigs: HashMap<String, Result<SigResolved, Failure>>,
    busy: HashSet<String>,
    /// Image-wide scan results by pattern text.
    scan: HashMap<String, Hits>,
}

impl Resolver<'_> {
    fn sig(&mut self, name: &str) -> Result<SigResolved, Failure> {
        if let Some(r) = self.sigs.get(name) {
            return r.clone();
        }
        if !self.busy.insert(name.to_owned()) {
            return Err(Failure::Invalid(format!("anchor cycle at `{name}`")));
        }
        let table = self.table;
        let r = match table.sig(name) {
            Some(s) => self.sig_uncached(s),
            None => Err(Failure::Invalid(format!("unknown entry `{name}`"))),
        };
        self.busy.remove(name);
        self.sigs.insert(name.to_owned(), r.clone());
        r
    }

    /// The function range of an anchor entry.
    fn anchor_range(&mut self, anchor: &str) -> Result<(u64, u64), Failure> {
        let a = self
            .sig(anchor)
            .map_err(|_| Failure::AnchorFailed(anchor.to_owned()))?;
        self.image
            .function_range(a.rva)
            .ok_or(Failure::NoFunctionRange)
    }

    fn sig_uncached(&mut self, s: &Sig) -> Result<SigResolved, Failure> {
        let rva = match s.kind {
            Kind::Function => {
                let hit = self.global_hit(s.pattern.as_deref().unwrap_or(""))?;
                hit.checked_add_signed(s.offset)
                    .ok_or(Failure::OutOfRange(hit))?
            }
            Kind::Site => {
                let (begin, end) = self.anchor_range(s.anchor.as_deref().unwrap_or(""))?;
                let rva = match &s.pattern {
                    Some(text) => {
                        let p = parse(text)?;
                        let hit = self.local_hit(&p, begin, end)?;
                        hit.checked_add_signed(s.offset)
                            .ok_or(Failure::OutOfRange(hit))?
                    }
                    None => begin + s.anchor_offset.unwrap_or(0),
                };
                if rva >= end {
                    return Err(Failure::OutOfRange(rva));
                }
                if !self.is_boundary(begin, end, rva) {
                    return Err(Failure::NotBoundary);
                }
                rva
            }
            Kind::Ref => {
                let text = s.pattern.as_deref().unwrap_or("");
                let p = parse(text)?;
                let (hit, pos_data): (u64, &[u8]) = match &s.anchor {
                    Some(a) => {
                        let (begin, end) = self.anchor_range(a)?;
                        (self.local_hit(&p, begin, end)?, self.image.data)
                    }
                    None => (self.global_hit(text)?, self.image.data),
                };
                let cap = s
                    .capture
                    .as_deref()
                    .and_then(|c| p.capture(c))
                    .ok_or_else(|| Failure::Invalid("ref needs a capture".into()))?;
                let target = p
                    .capture_value(pos_data, hit as usize, hit, cap)
                    .ok_or(Failure::OutOfRange(hit))?;
                if target >= self.image.info.size_of_image as u64 {
                    return Err(Failure::OutOfRange(target));
                }
                target
            }
        };
        if let Some(text) = &s.expect {
            let p = parse(text)?;
            let found = self.image.read(rva, p.len());
            match found {
                Some(b) if p.matches_at(b, 0) => {}
                Some(b) => return Err(Failure::ExpectMismatch { found: b.to_vec() }),
                None => return Err(Failure::OutOfRange(rva)),
            }
        }
        if s.pdata && !self.image.is_function_start(rva) {
            return Err(Failure::NotFunctionStart);
        }
        let moved = s
            .ghidra
            .map(|g| (self.image.info.image_base + rva) as i64 - g as i64);
        Ok(SigResolved { rva, moved })
    }

    /// The single image-wide match of a pattern (RVA).
    fn global_hit(&self, text: &str) -> Result<u64, Failure> {
        match self.scan.get(text) {
            None => Err(Failure::Invalid("pattern was not scanned".into())),
            Some(h) if h.count == 0 => Err(Failure::Missing),
            Some(h) if h.count > 1 => Err(Failure::Ambiguous(h.count)),
            Some(h) => Ok(h.first[0]),
        }
    }

    /// The single match of `p` inside `begin..end` (RVA).
    fn local_hit(&self, p: &Pattern, begin: u64, end: u64) -> Result<u64, Failure> {
        let Some(data) = self.image.read(begin, (end - begin) as usize) else {
            return Err(Failure::OutOfRange(begin));
        };
        let hits = find_all(data, p);
        match hits.len() {
            0 => Err(Failure::Missing),
            1 => Ok(begin + hits[0] as u64),
            n => Err(Failure::Ambiguous(n)),
        }
    }

    /// Linear decode from `begin`: is `site` the start of an instruction?
    fn is_boundary(&self, begin: u64, end: u64, site: u64) -> bool {
        let Some(code) = self.image.read(begin, (end - begin) as usize) else {
            return false;
        };
        let mut d = Decoder::with_ip(64, code, begin, DecoderOptions::NONE);
        while d.can_decode() && d.ip() < site {
            let ins = d.decode();
            if ins.is_invalid() {
                return false;
            }
        }
        d.ip() == site
    }

    fn field(&mut self, f: &Field) -> Result<FieldResolved, Failure> {
        let p = parse(&f.pattern)?;
        let hit = match &f.anchor {
            Some(a) => {
                let (begin, end) = self.anchor_range(a)?;
                self.local_hit(&p, begin, end)?
            }
            None => self.global_hit(&f.pattern)?,
        };
        let cap = p
            .capture(&f.capture)
            .ok_or_else(|| Failure::Invalid("unknown capture".into()))?;
        let value = p
            .capture_value(self.image.data, hit as usize, hit, cap)
            .ok_or(Failure::OutOfRange(hit))?;
        if let Some(min) = f.min
            && value < min
        {
            return Err(Failure::Limit(format!("value {value:#x} below {min:#x}")));
        }
        if let Some(max) = f.max
            && value > max
        {
            return Err(Failure::Limit(format!("value {value:#x} above {max:#x}")));
        }
        if let Some(align) = f.align
            && value % align != 0
        {
            return Err(Failure::Limit(format!(
                "value {value:#x} not aligned to {align}"
            )));
        }
        Ok(FieldResolved {
            value,
            changed_from: f.value.filter(|v| *v != value),
        })
    }
}

fn parse(text: &str) -> Result<Pattern, Failure> {
    Pattern::parse(text).map_err(Failure::Invalid)
}

/// Compares the image with the table's build and finds the revision string.
pub fn check_build(table: &Table, image: &Image) -> BuildCheck {
    let b = &table.build;
    let mut found = None;
    let mut checked = false;
    if let Some(text) = &b.revision_pattern
        && let Ok(p) = Pattern::parse(text)
        && let Some(cap) = p.capture("rev")
    {
        checked = true;
        let mut all = Vec::new();
        for s in image.data_sections() {
            let data = image.section_bytes(s);
            for pos in find_all(data, &p) {
                if let Some(bytes) = p.capture_bytes(data, pos, cap)
                    && bytes.iter().all(u8::is_ascii_digit)
                {
                    all.push(String::from_utf8_lossy(bytes).into_owned());
                }
            }
        }
        all.sort();
        all.dedup();
        // Several different revisions would be a wrong pattern: not found.
        if all.len() == 1 {
            found = all.pop();
        }
    }
    BuildCheck {
        table_version: b.version.clone(),
        timestamp_ok: image.info.timestamp == b.pe_timestamp,
        size_ok: image.info.size_of_image == b.image_size,
        revision_found: found,
        revision_expected: b.build_revision.clone(),
        revision_checked: checked,
    }
}

impl Table {
    /// `(expected, patch)` bytes of a patch entry.
    pub fn patch_bytes(&self, name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let s = self.sig(name)?;
        Some((
            parse_exact_bytes(s.expect.as_deref()?).ok()?,
            parse_exact_bytes(s.patch.as_deref()?).ok()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{map_file, tests::synthetic};

    // Two functions in .text (RVA 0x1000, 0x1040), padded with int3:
    //   A: push rbx; mov rax,[rcx+0x44c]; mov edx,[rcx+0x1e5]; call rel32; mov rax,[rip+0x20]; nop; ret
    //   B: mov [rsp+8],rbx; sub rsp,0x20; xor eax,eax; nop; nop; ret
    const A: [u8; 29] = [
        0x53, 0x48, 0x8b, 0x81, 0x4c, 0x04, 0x00, 0x00, 0x8b, 0x91, 0xe5, 0x01, 0x00, 0x00, 0xe8,
        0x10, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x20, 0x00, 0x00, 0x00, 0x90, 0x90, 0xc3,
    ];
    const B: [u8; 15] = [
        0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x20, 0x31, 0xc0, 0x90, 0x90, 0xc3, 0xcc,
    ];

    fn code() -> Vec<u8> {
        let mut c = vec![0xccu8; 0x200];
        c[..A.len()].copy_from_slice(&A);
        c[0x40..0x40 + B.len()].copy_from_slice(&B);
        c
    }

    fn mapped(code: &[u8]) -> Vec<u8> {
        let mut file = synthetic(code, &[(0x1000, 0x101d), (0x1040, 0x104e)], 0x1234);
        // "<space>123456\0%S.poecap" in the data section (.pdata is readable data here)
        let rev = b" 123456\0%S.poecap";
        file[0x800 + 0x100..0x800 + 0x100 + rev.len()].copy_from_slice(rev);
        map_file(&file).unwrap()
    }

    const TABLE: &str = r#"
[build]
version = "t"
build_revision = "123456"
revision_pattern = "20 <rev:bytes6> 00 25 53 2e 70 6f 65 63 61 70"
pe_timestamp = 0x1234
image_size = 0x4000

[[sig]]
name = "a"
features = ["fa", "fb"]
pattern = "53 48 8b 81 ?? ?? ?? ?? 8b 91 ?? ?? ?? ?? e8"
pdata = true
ghidra = 0x140001000

[[sig]]
name = "b"
features = ["fb"]
pattern = "48 89 5c 24 08 48 83 ec ?? 31 c0"
expect = "48 89 5c 24"
patch = ""
ghidra = 0x140001040
[[sig]]
name = "site"
features = ["fa"]
kind = "site"
anchor = "a"
anchor_offset = 14
expect = "e8"
[[sig]]
name = "global"
features = ["fa"]
kind = "ref"
anchor = "a"
pattern = "48 8b 05 <t:rip4> 90"
capture = "t"
[[field]]
name = "facing"
features = ["fa"]
anchor = "a"
pattern = "48 8b 81 <v:4> 8b 91"
capture = "v"
value = 0x44c
min = 0x100
align = 4
[[field]]
name = "lock"
features = ["fa"]
anchor = "a"
pattern = "8b 91 <v:4> e8"
capture = "v"
value = 0x1e5
"#;

    fn table() -> Table {
        // The `patch = ""` line above is not valid; build the table without it.
        Table::parse(&TABLE.replace("patch = \"\"\n", "")).unwrap()
    }

    fn run(code: &[u8], features: Option<&[&str]>) -> Resolution {
        let m = mapped(code);
        let image = Image::from_mapped(&m).unwrap();
        resolve(&table(), &image, features)
    }

    #[test]
    fn everything_resolves_on_the_known_build() {
        let r = run(&code(), None);
        assert!(r.build.verified(), "{}", r.build.describe());
        assert_eq!(r.build.revision_found.as_deref(), Some("123456"));
        assert_eq!(r.rva("a"), Some(0x1000));
        assert_eq!(r.rva("b"), Some(0x1040));
        assert_eq!(r.rva("site"), Some(0x100e));
        // rip target: end of the disp field (0x1000 + 22 + 4 = 0x101a) + 0x20 (+ 0 extra) + 0
        assert_eq!(r.rva("global"), Some(0x1000 + 22 + 4 + 0x20));
        assert_eq!(r.field("facing"), Some(0x44c));
        assert_eq!(r.field("lock"), Some(0x1e5));
        assert!(r.feature_ok("fa") && r.feature_ok("fb"));
        // Unlisted features are fine.
        assert!(r.feature_ok("whatever"));
        assert_eq!(r.sigs["a"].as_ref().unwrap().moved, Some(0));
        assert!(r.fields["facing"].as_ref().unwrap().changed_from.is_none());
    }

    #[test]
    fn a_mutated_byte_disables_only_the_features_that_need_the_entry() {
        // Break B's pattern (the xor).
        let mut c = code();
        c[0x40 + 9] = 0x33;
        let r = run(&c, None);
        assert_eq!(r.sigs["b"], Err(Failure::Missing));
        assert!(!r.feature_ok("fb"));
        assert!(
            r.feature_ok("fa"),
            "fa does not need b: {}",
            r.feature_problem("fa")
        );
        assert!(r.feature_problem("fb").contains("sig b: matched 0 times"));
        assert!(r.summary().iter().any(|l| l.contains("feature fb: OFF")));
    }

    #[test]
    fn a_broken_anchor_takes_its_dependents_down() {
        let mut c = code();
        c[3] = 0x80; // A's pattern: 48 8b 81 -> 48 8b 80
        let r = run(&c, None);
        assert_eq!(r.sigs["a"], Err(Failure::Missing));
        assert_eq!(r.sigs["site"], Err(Failure::AnchorFailed("a".into())));
        assert_eq!(r.sigs["global"], Err(Failure::AnchorFailed("a".into())));
        assert!(r.fields["facing"].is_err());
        assert!(!r.feature_ok("fa") && !r.feature_ok("fb"));
    }

    #[test]
    fn a_duplicate_match_is_ambiguous_never_picked() {
        let mut c = code();
        // A second copy of function A.
        c[0x80..0x80 + A.len()].copy_from_slice(&A);
        let m = {
            let mut file = synthetic(
                &c,
                &[(0x1000, 0x101d), (0x1040, 0x104e), (0x1080, 0x109d)],
                0x1234,
            );
            let rev = b" 123456\0%S.poecap";
            file[0x800 + 0x100..0x800 + 0x100 + rev.len()].copy_from_slice(rev);
            map_file(&file).unwrap()
        };
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&table(), &image, None);
        assert_eq!(r.sigs["a"], Err(Failure::Ambiguous(2)));
        assert!(
            r.summary()
                .iter()
                .any(|l| l.contains("ambiguous: matched 2 times"))
        );
        assert!(!r.feature_ok("fa"));
    }

    #[test]
    fn expected_bytes_are_checked_at_the_address() {
        let t = Table::parse(
            &TABLE
                .replace("patch = \"\"\n", "")
                .replace("expect = \"48 89 5c 24\"", "expect = \"48 89 5c 25\""),
        )
        .unwrap();
        let m = mapped(&code());
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&t, &image, None);
        assert!(matches!(r.sigs["b"], Err(Failure::ExpectMismatch { .. })));
    }

    #[test]
    fn a_site_inside_an_instruction_is_refused() {
        // anchor_offset 15 is inside the `call rel32` (14..19).
        let t = Table::parse(
            &TABLE
                .replace("patch = \"\"\n", "")
                .replace("anchor_offset = 14", "anchor_offset = 15")
                .replace("expect = \"e8\"", "expect = \"10\""),
        )
        .unwrap();
        let m = mapped(&code());
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&t, &image, None);
        assert_eq!(r.sigs["site"], Err(Failure::NotBoundary));
        assert!(!r.feature_ok("fa"));
    }

    #[test]
    fn field_limits_and_agreement() {
        let t = Table::parse(
            &TABLE
                .replace("patch = \"\"\n", "")
                .replace("min = 0x100", "min = 0x500"),
        )
        .unwrap();
        let m = mapped(&code());
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&t, &image, None);
        assert!(matches!(r.fields["facing"], Err(Failure::Limit(_))));
        // Partners that read different values disable both.
        let t = Table::parse(&TABLE.replace("patch = \"\"\n", "").replace(
            "value = 0x1e5\n",
            "value = 0x1e5\nagrees_with = \"facing\"\n",
        ))
        .unwrap();
        let r = resolve(&t, &image, None);
        assert!(matches!(r.fields["lock"], Err(Failure::Disagrees { .. })));
        assert!(matches!(r.fields["facing"], Err(Failure::Disagrees { .. })));
        assert!(!r.feature_ok("fa"));
    }

    #[test]
    fn a_changed_value_is_reported_not_fatal() {
        let t = Table::parse(
            &TABLE
                .replace("patch = \"\"\n", "")
                .replace("value = 0x44c", "value = 0x440"),
        )
        .unwrap();
        let m = mapped(&code());
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&t, &image, None);
        assert_eq!(r.field("facing"), Some(0x44c));
        assert_eq!(
            r.fields["facing"].as_ref().unwrap().changed_from,
            Some(0x440)
        );
        assert!(r.feature_ok("fa"));
        assert!(
            r.summary()
                .iter()
                .any(|l| l.contains("field facing changed"))
        );
    }

    #[test]
    fn only_the_requested_features_are_resolved() {
        let r = run(&code(), Some(&["fb"]));
        // fb needs a and b; the site, global and fields only fa lists are not looked at.
        assert!(r.sigs.contains_key("a") && r.sigs.contains_key("b"));
        assert!(!r.sigs.contains_key("site") && !r.sigs.contains_key("global"));
        assert!(r.fields.is_empty());
        assert!(r.features.contains_key("fb") && !r.features.contains_key("fa"));
    }

    #[test]
    fn a_different_build_is_unverified() {
        let mut file = synthetic(&code(), &[(0x1000, 0x101d), (0x1040, 0x104e)], 0x9999);
        let rev = b" 654321\0%S.poecap";
        file[0x800 + 0x100..0x800 + 0x100 + rev.len()].copy_from_slice(rev);
        let m = map_file(&file).unwrap();
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&table(), &image, None);
        assert!(!r.build.timestamp_ok && r.build.size_ok);
        assert_eq!(r.build.revision_found.as_deref(), Some("654321"));
        assert!(!r.build.verified());
        assert!(r.summary().iter().any(|l| l.contains("NOT verified")));
        // The signatures still resolve (a rebuilt exe with the same code).
        assert!(r.feature_ok("fa"));
    }

    #[test]
    fn the_pdata_check_rejects_a_function_middle() {
        let t = Table::parse(
            &TABLE
                .replace("patch = \"\"\n", "")
                .replace("pdata = true", "pdata = true\noffset = 1"),
        )
        .unwrap();
        let m = mapped(&code());
        let image = Image::from_mapped(&m).unwrap();
        let r = resolve(&t, &image, None);
        assert_eq!(r.sigs["a"], Err(Failure::NotFunctionStart));
    }
}
