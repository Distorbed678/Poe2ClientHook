//! Minimal PE64 reader: header fields, sections, `.pdata` function ranges, and mapping a file
//! into its in-memory layout. Works on the file bytes and on the loaded image alike (both
//! start with the same headers).

use std::ops::Range;

pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn executable(&self) -> bool {
        self.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0
    }

    /// Read-only data (`.rdata`, `.rsrc`, ...). Writable sections are skipped (nothing the
    /// table looks for is there) and so are discardable ones (`.reloc`): in a running process
    /// their pages need not be mapped.
    pub fn readable_data(&self) -> bool {
        !self.executable()
            && self.characteristics & SCN_MEM_READ != 0
            && self.characteristics & (SCN_MEM_WRITE | SCN_MEM_DISCARDABLE) == 0
    }

    /// The section's RVA range in the mapped image.
    pub fn range(&self) -> Range<usize> {
        let start = self.rva as usize;
        start..start + self.virtual_size as usize
    }
}

#[derive(Debug, Clone)]
pub struct PeInfo {
    pub image_base: u64,
    pub timestamp: u32,
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    /// Exception directory (`.pdata`): RVA and size.
    pub exception_dir: (u32, u32),
}

fn u16_at(d: &[u8], o: usize) -> Result<u16, String> {
    d.get(o..o + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "truncated PE".to_string())
}

fn u32_at(d: &[u8], o: usize) -> Result<u32, String> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "truncated PE".to_string())
}

fn u64_at(d: &[u8], o: usize) -> Result<u64, String> {
    d.get(o..o + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| "truncated PE".to_string())
}

impl PeInfo {
    /// Parses the headers at the start of `data` (a file or a mapped image).
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.get(..2) != Some(b"MZ") {
            return Err("not a PE file (no MZ)".into());
        }
        let nt = u32_at(data, 0x3c)? as usize;
        if data.get(nt..nt + 4) != Some(b"PE\0\0") {
            return Err("not a PE file (no PE signature)".into());
        }
        let file = nt + 4;
        if u16_at(data, file)? != 0x8664 {
            return Err("not an x86-64 PE".into());
        }
        let n_sections = u16_at(data, file + 2)? as usize;
        let timestamp = u32_at(data, file + 4)?;
        let opt_size = u16_at(data, file + 16)? as usize;
        let opt = file + 20;
        if u16_at(data, opt)? != 0x20b {
            return Err("not a PE32+ optional header".into());
        }
        let image_base = u64_at(data, opt + 24)?;
        let size_of_image = u32_at(data, opt + 56)?;
        // Data directories start at +112; entry 3 is the exception directory.
        let dirs = opt + 112;
        let exception_dir = (u32_at(data, dirs + 3 * 8)?, u32_at(data, dirs + 3 * 8 + 4)?);
        let table = opt + opt_size;
        let mut sections = Vec::with_capacity(n_sections);
        for i in 0..n_sections {
            let s = table + i * 40;
            let name_bytes = data.get(s..s + 8).ok_or("truncated section table")?;
            let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
                virtual_size: u32_at(data, s + 8)?,
                rva: u32_at(data, s + 12)?,
                raw_size: u32_at(data, s + 16)?,
                raw_offset: u32_at(data, s + 20)?,
                characteristics: u32_at(data, s + 36)?,
            });
        }
        Ok(Self {
            image_base,
            timestamp,
            size_of_image,
            sections,
            exception_dir,
        })
    }
}

/// A PE image in its mapped layout (byte index = RVA), borrowed.
pub struct Image<'a> {
    pub info: PeInfo,
    pub data: &'a [u8],
}

impl<'a> Image<'a> {
    /// `data` is the mapped image (`SizeOfImage` bytes at the module base in a process, or
    /// the result of [`map_file`]).
    pub fn from_mapped(data: &'a [u8]) -> Result<Self, String> {
        Ok(Self {
            info: PeInfo::parse(data)?,
            data,
        })
    }

    /// The bytes of a section as mapped (clamped to the buffer).
    pub fn section_bytes(&self, s: &Section) -> &'a [u8] {
        let start = (s.rva as usize).min(self.data.len());
        let end = (start + s.virtual_size as usize).min(self.data.len());
        &self.data[start..end]
    }

    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.info.sections.iter().filter(|s| s.executable())
    }

    pub fn data_sections(&self) -> impl Iterator<Item = &Section> {
        self.info.sections.iter().filter(|s| s.readable_data())
    }

    /// Bytes at an RVA.
    pub fn read(&self, rva: u64, len: usize) -> Option<&'a [u8]> {
        let start = usize::try_from(rva).ok()?;
        self.data.get(start..start.checked_add(len)?)
    }

    /// Whether `rva` lies in an executable section.
    pub fn is_code(&self, rva: u64) -> bool {
        self.code_sections()
            .any(|s| (s.rva as u64..s.rva as u64 + s.virtual_size as u64).contains(&rva))
    }

    fn pdata(&self) -> &'a [u8] {
        let (rva, size) = self.info.exception_dir;
        self.data
            .get(rva as usize..(rva as usize).saturating_add(size as usize))
            .unwrap_or(&[])
    }

    fn pdata_entry(&self, i: usize) -> (u32, u32) {
        let e = &self.pdata()[i * 12..i * 12 + 12];
        (
            u32::from_le_bytes(e[0..4].try_into().unwrap()),
            u32::from_le_bytes(e[4..8].try_into().unwrap()),
        )
    }

    /// The `.pdata` entry (begin, end RVAs) that contains `rva`.
    pub fn function_range(&self, rva: u64) -> Option<(u64, u64)> {
        let rva = u32::try_from(rva).ok()?;
        let n = self.pdata().len() / 12;
        // Entries are sorted by begin address.
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.pdata_entry(mid).0 <= rva {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let (begin, end) = self.pdata_entry(lo.checked_sub(1)?);
        (begin <= rva && rva < end).then_some((begin as u64, end as u64))
    }

    /// Whether `rva` is the start of a `.pdata` function.
    pub fn is_function_start(&self, rva: u64) -> bool {
        self.function_range(rva).is_some_and(|(b, _)| b == rva)
    }
}

/// Maps a PE file into its in-memory layout (sections at their RVAs; the gaps are zero).
pub fn map_file(file: &[u8]) -> Result<Vec<u8>, String> {
    let info = PeInfo::parse(file)?;
    let mut out = vec![0u8; info.size_of_image as usize];
    let headers = info
        .sections
        .iter()
        .map(|s| s.raw_offset as usize)
        .filter(|o| *o > 0)
        .min()
        .unwrap_or(0x400)
        .min(file.len())
        .min(out.len());
    out[..headers].copy_from_slice(&file[..headers]);
    for s in &info.sections {
        let raw = (s.raw_offset as usize).min(file.len());
        let copy = if s.virtual_size == 0 {
            s.raw_size
        } else {
            s.raw_size.min(s.virtual_size)
        };
        let n = (copy as usize)
            .min(file.len() - raw)
            .min(out.len().saturating_sub(s.rva as usize));
        out[s.rva as usize..s.rva as usize + n].copy_from_slice(&file[raw..raw + n]);
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A tiny synthetic PE64: one executable section `.text` at RVA 0x1000 (0x200 bytes of
    /// `code`) and `.pdata` with the given function entries.
    pub fn synthetic(code: &[u8], functions: &[(u32, u32)], timestamp: u32) -> Vec<u8> {
        let size_of_image = 0x4000u32;
        let mut f = vec![0u8; 0x400 + 0x400 + 0x200];
        f[0..2].copy_from_slice(b"MZ");
        f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let nt = 0x80;
        f[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let file = nt + 4;
        f[file..file + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[file + 2..file + 4].copy_from_slice(&2u16.to_le_bytes());
        f[file + 4..file + 8].copy_from_slice(&timestamp.to_le_bytes());
        f[file + 16..file + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = file + 20;
        f[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        f[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
        let dirs = opt + 112;
        f[dirs + 24..dirs + 28].copy_from_slice(&0x2000u32.to_le_bytes());
        f[dirs + 28..dirs + 32].copy_from_slice(&((functions.len() * 12) as u32).to_le_bytes());
        let table = opt + 240;
        let section = |f: &mut Vec<u8>, i: usize, name: &[u8], rva: u32, raw: u32, ch: u32| {
            let s = table + i * 40;
            f[s..s + name.len()].copy_from_slice(name);
            f[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes());
            f[s + 12..s + 16].copy_from_slice(&rva.to_le_bytes());
            f[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
            f[s + 20..s + 24].copy_from_slice(&raw.to_le_bytes());
            f[s + 36..s + 40].copy_from_slice(&ch.to_le_bytes());
        };
        section(&mut f, 0, b".text", 0x1000, 0x400, 0x6000_0020);
        section(&mut f, 1, b".pdata", 0x2000, 0x800, 0x4000_0040);
        f[0x400..0x400 + code.len()].copy_from_slice(code);
        for (i, (b, e)) in functions.iter().enumerate() {
            let o = 0x800 + i * 12;
            f[o..o + 4].copy_from_slice(&b.to_le_bytes());
            f[o + 4..o + 8].copy_from_slice(&e.to_le_bytes());
        }
        f
    }

    #[test]
    fn parses_and_maps_a_synthetic_image() {
        let file = synthetic(&[0x90, 0x90, 0xc3], &[(0x1000, 0x1003)], 0x1234);
        let info = PeInfo::parse(&file).unwrap();
        assert_eq!(info.timestamp, 0x1234);
        assert_eq!(info.size_of_image, 0x4000);
        assert_eq!(info.sections.len(), 2);
        assert!(info.sections[0].executable());
        assert!(!info.sections[1].executable());
        let mapped = map_file(&file).unwrap();
        assert_eq!(mapped.len(), 0x4000);
        assert_eq!(&mapped[0x1000..0x1003], [0x90, 0x90, 0xc3]);
        let image = Image::from_mapped(&mapped).unwrap();
        assert!(image.is_function_start(0x1000));
        assert!(!image.is_function_start(0x1001));
        assert_eq!(image.function_range(0x1002), Some((0x1000, 0x1003)));
        assert_eq!(image.function_range(0x1003), None);
        assert!(image.is_code(0x1000));
        assert!(!image.is_code(0x2000));
    }

    #[test]
    fn rejects_garbage() {
        assert!(PeInfo::parse(b"hello").is_err());
        assert!(PeInfo::parse(&[b'M', b'Z', 0, 0]).is_err());
    }
}
