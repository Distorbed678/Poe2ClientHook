//! Searching: one pattern in a byte range, and many patterns in one pass over the code.

use crate::{pattern::Pattern, pe::Image};

/// All offsets in `data` where `p` matches.
pub fn find_all(data: &[u8], p: &Pattern) -> Vec<usize> {
    let mut out = Vec::new();
    let Some((koff, [k0, k1])) = p.key() else {
        // No two fixed bytes in a row: plain loop.
        for i in 0..data.len().saturating_sub(p.len() - 1) {
            if p.matches_at(data, i) {
                out.push(i);
            }
        }
        return out;
    };
    let mut i = koff;
    while i + 1 < data.len() {
        match data[i..].iter().position(|&b| b == k0) {
            None => break,
            Some(d) => i += d,
        }
        if i + 1 >= data.len() {
            break;
        }
        if data[i + 1] == k1 && p.matches_at(data, i - koff) {
            out.push(i - koff);
        }
        i += 1;
    }
    out
}

/// Result of a pattern in a whole-image scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hits {
    /// Number of matches.
    pub count: usize,
    /// The first matches (RVAs), at most [`Hits::KEPT`].
    pub first: Vec<u64>,
}

impl Hits {
    pub const KEPT: usize = 8;

    fn add(&mut self, rva: u64) {
        self.count += 1;
        if self.first.len() < Self::KEPT {
            self.first.push(rva);
        }
    }
}

/// Scans the executable sections of `image` once for all `patterns` (indexed by their first two
/// fixed bytes). Every pattern must have such a pair ([`Pattern::key`]).
pub fn scan_code(image: &Image, patterns: &[&Pattern]) -> Vec<Hits> {
    let mut hits = vec![Hits::default(); patterns.len()];
    // CSR table: for each 16-bit key the patterns (index, offset of the key in the pattern).
    let mut counts = vec![0u32; 65537];
    let keys: Vec<Option<(usize, usize)>> = patterns
        .iter()
        .map(|p| {
            p.key()
                .map(|(off, [a, b])| (off, a as usize | (b as usize) << 8))
        })
        .collect();
    for (_, k) in keys.iter().flatten() {
        counts[k + 1] += 1;
    }
    for i in 0..65536 {
        counts[i + 1] += counts[i];
    }
    let mut fill = counts.clone();
    let mut slots = vec![(0u32, 0u32); keys.iter().flatten().count()];
    for (idx, k) in keys.iter().enumerate() {
        if let Some((off, key)) = k {
            slots[fill[*key] as usize] = (idx as u32, *off as u32);
            fill[*key] += 1;
        }
    }
    for section in image.code_sections() {
        let data = image.section_bytes(section);
        let base = section.rva as u64;
        for i in 0..data.len().saturating_sub(1) {
            let key = data[i] as usize | (data[i + 1] as usize) << 8;
            let (lo, hi) = (counts[key] as usize, counts[key + 1] as usize);
            for &(idx, off) in &slots[lo..hi] {
                let Some(start) = i.checked_sub(off as usize) else {
                    continue;
                };
                if patterns[idx as usize].matches_at(data, start) {
                    hits[idx as usize].add(base + start as u64);
                }
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{map_file, tests::synthetic};

    #[test]
    fn find_all_reports_every_match() {
        let data = [1, 2, 3, 9, 1, 2, 3, 1, 2, 3, 3];
        let p = Pattern::parse("01 02 ??").unwrap();
        assert_eq!(find_all(&data, &p), [0, 4, 7]);
        let p = Pattern::parse("?? 02 03 09").unwrap();
        assert_eq!(find_all(&data, &p), [0]);
        assert!(find_all(&data, &Pattern::parse("03 04").unwrap()).is_empty());
        // a match at the very end
        assert_eq!(find_all(&data, &Pattern::parse("03 03").unwrap()), [9]);
    }

    #[test]
    fn scan_code_matches_find_all_and_counts_duplicates() {
        let mut code = vec![0x90u8; 0x200];
        code[0x10..0x16].copy_from_slice(&[0x48, 0x8b, 0x05, 1, 2, 3]);
        code[0x40..0x46].copy_from_slice(&[0x48, 0x8b, 0x05, 9, 9, 9]);
        code[0x80..0x84].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let file = synthetic(&code, &[], 1);
        let mapped = map_file(&file).unwrap();
        let image = Image::from_mapped(&mapped).unwrap();
        let a = Pattern::parse("48 8b 05 ?? ?? ??").unwrap();
        let b = Pattern::parse("?? ad be ef").unwrap();
        let c = Pattern::parse("48 8b 05 01 02 04").unwrap();
        let hits = scan_code(&image, &[&a, &b, &c]);
        assert_eq!(hits[0].count, 2);
        assert_eq!(hits[0].first, [0x1010, 0x1040]);
        assert_eq!(hits[1].first, [0x1080]);
        assert_eq!(hits[2].count, 0);
        let sec = image.section_bytes(&image.info.sections[0]);
        assert_eq!(find_all(sec, &a), [0x10, 0x40]);
    }
}
