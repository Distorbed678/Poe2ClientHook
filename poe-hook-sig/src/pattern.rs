//! Byte patterns with wildcards and captures.
//!
//! Syntax (whitespace separated tokens):
//! - `48` a literal byte (hex);
//! - `??` any byte;
//! - `<name:N>` captures the next `N` bytes (`N` is 1, 2, 4 or 8) as a little-endian
//!   unsigned integer; the bytes match anything;
//! - `<name:rip4>` / `<name:rip4+K>` a RIP-relative 4-byte displacement. The captured value is
//!   the *address* it refers to: the end of the displacement field plus `K` (the bytes of the
//!   instruction after the displacement, for example 1 for `cmp dword ptr [rip+d], imm8`) plus
//!   the signed displacement. For a `call`/`jmp` use plain `rip4`.
//! - `<name:bytes6>`: captures 6 raw bytes (used for the build revision digits); any length.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    /// Little-endian unsigned integer of `len` bytes.
    Le,
    /// RIP-relative displacement (`len` is 4); `extra` bytes follow it in the instruction.
    Rip { extra: u8 },
    /// Raw bytes (`bytes<N>`).
    Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub name: String,
    /// Offset of the captured bytes inside the pattern.
    pub offset: usize,
    pub len: usize,
    pub kind: CaptureKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// Literal bytes (0 where the pattern has a wildcard).
    pub bytes: Vec<u8>,
    /// `true` where the byte must match.
    pub fixed: Vec<bool>,
    pub captures: Vec<Capture>,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut p = Pattern {
            bytes: Vec::new(),
            fixed: Vec::new(),
            captures: Vec::new(),
        };
        for tok in text.split_whitespace() {
            if tok == "??" || tok == "?" {
                p.bytes.push(0);
                p.fixed.push(false);
            } else if let Some(inner) = tok.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
                let (name, spec) = inner
                    .split_once(':')
                    .ok_or_else(|| format!("capture `{tok}` needs `<name:N>`"))?;
                if name.is_empty() || p.captures.iter().any(|c| c.name == name) {
                    return Err(format!("capture name `{name}` is empty or used twice"));
                }
                let (len, kind) = if let Some(rest) = spec.strip_prefix("rip4") {
                    let extra = match rest {
                        "" => 0,
                        r => r
                            .strip_prefix('+')
                            .and_then(|k| k.parse::<u8>().ok())
                            .ok_or_else(|| format!("bad rip capture `{tok}`"))?,
                    };
                    (4, CaptureKind::Rip { extra })
                } else if let Some(n) = spec.strip_prefix("bytes") {
                    let n: usize = n.parse().map_err(|_| format!("bad capture `{tok}`"))?;
                    (n, CaptureKind::Bytes)
                } else {
                    let n: usize = spec.parse().map_err(|_| format!("bad capture `{tok}`"))?;
                    if ![1, 2, 4, 8].contains(&n) {
                        return Err(format!("capture `{tok}`: length must be 1, 2, 4 or 8"));
                    }
                    (n, CaptureKind::Le)
                };
                if len == 0 {
                    return Err(format!("capture `{tok}` has no bytes"));
                }
                p.captures.push(Capture {
                    name: name.to_owned(),
                    offset: p.bytes.len(),
                    len,
                    kind,
                });
                for _ in 0..len {
                    p.bytes.push(0);
                    p.fixed.push(false);
                }
            } else {
                let b = u8::from_str_radix(tok, 16)
                    .ok()
                    .filter(|_| tok.len() == 2)
                    .ok_or_else(|| format!("bad byte `{tok}`"))?;
                p.bytes.push(b);
                p.fixed.push(true);
            }
        }
        if p.bytes.is_empty() {
            return Err("empty pattern".into());
        }
        Ok(p)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of bytes that must match.
    pub fn fixed_len(&self) -> usize {
        self.fixed.iter().filter(|f| **f).count()
    }

    /// Whether `data` at `pos` matches (false when it does not fit).
    pub fn matches_at(&self, data: &[u8], pos: usize) -> bool {
        let Some(window) = data.get(pos..pos + self.len()) else {
            return false;
        };
        window
            .iter()
            .zip(&self.bytes)
            .zip(&self.fixed)
            .all(|((d, b), fixed)| !fixed || d == b)
    }

    /// The first two consecutive fixed bytes as `(offset, [a, b])`, the key of the scanner's
    /// bucket table. `None` when the pattern has no such pair.
    pub fn key(&self) -> Option<(usize, [u8; 2])> {
        (0..self.len().saturating_sub(1))
            .find(|&i| self.fixed[i] && self.fixed[i + 1])
            .map(|i| (i, [self.bytes[i], self.bytes[i + 1]]))
    }

    pub fn capture(&self, name: &str) -> Option<&Capture> {
        self.captures.iter().find(|c| c.name == name)
    }

    /// The value of capture `c` for a match at `pos` (an offset into `data`) whose first byte
    /// has the address `rva_of_pos` (relative to the image base): the integer, or for RIP
    /// captures the referenced address (RVA). `None` for raw-byte captures or out of range.
    pub fn capture_value(
        &self,
        data: &[u8],
        pos: usize,
        rva_of_pos: u64,
        c: &Capture,
    ) -> Option<u64> {
        let at = pos + c.offset;
        let raw = data.get(at..at + c.len)?;
        match c.kind {
            CaptureKind::Le => {
                let mut v = [0u8; 8];
                v[..c.len].copy_from_slice(raw);
                Some(u64::from_le_bytes(v))
            }
            CaptureKind::Rip { extra } => {
                let disp = i32::from_le_bytes(raw.try_into().ok()?) as i64;
                let next = rva_of_pos as i64 + c.offset as i64 + 4 + extra as i64;
                u64::try_from(next + disp).ok()
            }
            CaptureKind::Bytes => None,
        }
    }

    /// Raw bytes of a capture for a match at `pos`.
    pub fn capture_bytes<'a>(&self, data: &'a [u8], pos: usize, c: &Capture) -> Option<&'a [u8]> {
        data.get(pos + c.offset..pos + c.offset + c.len)
    }
}

/// Parses a hex byte string without wildcards or captures (`"31 c0 c3"`).
pub fn parse_exact_bytes(text: &str) -> Result<Vec<u8>, String> {
    let p = Pattern::parse(text)?;
    if p.fixed.iter().any(|f| !f) {
        return Err(format!("`{text}` must be exact bytes (no wildcards)"));
    }
    Ok(p.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bytes_wildcards_and_captures() {
        let p = Pattern::parse("f6 81 <lock:4> 02 ?? <t:rip4+1> 90").unwrap();
        assert_eq!(p.len(), 2 + 4 + 1 + 1 + 4 + 1);
        assert_eq!(
            p.fixed,
            [
                true, true, false, false, false, false, true, false, false, false, false, false,
                true
            ]
        );
        assert_eq!(p.captures[0].offset, 2);
        assert_eq!(p.captures[1].kind, CaptureKind::Rip { extra: 1 });
        assert_eq!(p.fixed_len(), 4);
    }

    #[test]
    fn rejects_malformed_patterns() {
        for bad in [
            "",
            "4",
            "zz",
            "48 <a>",
            "<a:3>",
            "<a:4> <a:4>",
            "<:4>",
            "<a:rip4+x>",
            "<a:bytes0>",
        ] {
            assert!(Pattern::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn matches_with_wildcards_and_bounds() {
        let p = Pattern::parse("48 ?? c3").unwrap();
        assert!(p.matches_at(&[0, 0x48, 0x99, 0xc3], 1));
        assert!(!p.matches_at(&[0, 0x48, 0x99, 0xc2], 1));
        assert!(!p.matches_at(&[0x48, 0x99], 0));
    }

    #[test]
    fn key_is_the_first_fixed_pair() {
        assert_eq!(
            Pattern::parse("?? 48 8b ??").unwrap().key(),
            Some((1, [0x48, 0x8b]))
        );
        assert_eq!(Pattern::parse("48 ?? 8b ?? c3").unwrap().key(), None);
    }

    #[test]
    fn capture_values() {
        // mov eax, [rip + 0x10] : 8b 05 10 00 00 00 ; the instruction is 6 bytes at rva 0x1000
        let p = Pattern::parse("8b 05 <g:rip4>").unwrap();
        let data = [0x8b, 0x05, 0x10, 0, 0, 0];
        let c = p.capture("g").unwrap();
        assert_eq!(
            p.capture_value(&data, 0, 0x1000, c),
            Some(0x1000 + 6 + 0x10)
        );
        // negative displacement, with 1 trailing immediate byte (cmp dword [rip-8], 0)
        let p = Pattern::parse("83 3d <g:rip4+1> 00").unwrap();
        let data = [0x83, 0x3d, 0xf8, 0xff, 0xff, 0xff, 0x00];
        let c = p.capture("g").unwrap();
        assert_eq!(p.capture_value(&data, 0, 0x2000, c), Some(0x2000 + 7 - 8));
        // plain integers
        let p = Pattern::parse("c7 81 <f:4>").unwrap();
        let data = [0xc7, 0x81, 0x4c, 0x04, 0, 0];
        assert_eq!(
            p.capture_value(&data, 0, 0, p.capture("f").unwrap()),
            Some(0x44c)
        );
    }

    #[test]
    fn exact_bytes_reject_wildcards() {
        assert_eq!(parse_exact_bytes("31 c0 c3").unwrap(), [0x31, 0xc0, 0xc3]);
        assert!(parse_exact_bytes("31 ?? c3").is_err());
    }
}
