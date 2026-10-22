//! The list of client mods the hook has loaded, as it tells a private server at login
//! (`Kind::ModReport` of the side channel, `docs/protocol/side-channel.md`). Pure code shared by
//! the DLL and the server, like the rest of [`crate::sidechannel`].
//!
//! The report is a consistency check, not anti-cheat: a modified client can say anything. It
//! carries, per loaded mod, the id and version and two SHA-256 values the server can compute
//! from the package it serves: the hash of the installed `mod.toml` (byte for byte) and the hash
//! of the entry DLL (absent for a data-only mod).
//!
//! Payload (little-endian): `u8 format (1)`, `u16 count`, then per mod `u8 id length`, id,
//! `u8 version length`, version, `[u8; 32]` manifest hash, `u8 has_dll`, and `[u8; 32]` DLL hash
//! when `has_dll` is 1. Lengths are bytes of UTF-8.

use sha2::{Digest, Sha256};

/// Format byte of the payload.
pub const FORMAT: u8 = 1;
/// Most mods a report may list.
pub const MAX_MODS: usize = 64;

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Lower-case hex of a hash.
pub fn hex(hash: &[u8; 32]) -> String {
    use std::fmt::Write;
    hash.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One loaded client mod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedMod {
    pub id: String,
    pub version: String,
    /// SHA-256 of the installed `mod.toml`.
    pub manifest_sha256: [u8; 32],
    /// SHA-256 of the entry DLL; `None` for a mod without one.
    pub dll_sha256: Option<[u8; 32]>,
}

/// All loaded client mods (possibly none).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModReport {
    pub mods: Vec<ReportedMod>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    Truncated,
    Format(u8),
    TooMany(usize),
    NotUtf8,
    Trailing,
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated mod report"),
            Self::Format(v) => write!(f, "unknown mod report format {v}"),
            Self::TooMany(n) => write!(f, "{n} mods in the report, at most {MAX_MODS}"),
            Self::NotUtf8 => write!(f, "mod report text is not UTF-8"),
            Self::Trailing => write!(f, "bytes after the mod report"),
        }
    }
}

impl ModReport {
    /// The payload. Mods past [`MAX_MODS`] and text past 255 bytes are cut (a mod id is at most
    /// 64 characters and a semver version is short, so neither happens for a valid mod).
    pub fn encode(&self) -> Vec<u8> {
        let mods = &self.mods[..self.mods.len().min(MAX_MODS)];
        let mut out = vec![FORMAT];
        out.extend_from_slice(&(mods.len() as u16).to_le_bytes());
        let put = |out: &mut Vec<u8>, s: &str| {
            let b = &s.as_bytes()[..s.len().min(255)];
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        };
        for m in mods {
            put(&mut out, &m.id);
            put(&mut out, &m.version);
            out.extend_from_slice(&m.manifest_sha256);
            match &m.dll_sha256 {
                Some(h) => {
                    out.push(1);
                    out.extend_from_slice(h);
                }
                None => out.push(0),
            }
        }
        out
    }

    pub fn decode(p: &[u8]) -> Result<Self, ReportError> {
        let mut r = Cursor { p, at: 0 };
        let format = r.take(1)?[0];
        if format != FORMAT {
            return Err(ReportError::Format(format));
        }
        let count = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if count > MAX_MODS {
            return Err(ReportError::TooMany(count));
        }
        let mut mods = Vec::with_capacity(count);
        for _ in 0..count {
            let id = r.text()?;
            let version = r.text()?;
            let manifest_sha256: [u8; 32] = r.take(32)?.try_into().unwrap();
            let dll_sha256 = match r.take(1)?[0] {
                0 => None,
                _ => Some(r.take(32)?.try_into().unwrap()),
            };
            mods.push(ReportedMod {
                id,
                version,
                manifest_sha256,
                dll_sha256,
            });
        }
        if r.at != p.len() {
            return Err(ReportError::Trailing);
        }
        Ok(Self { mods })
    }
}

struct Cursor<'a> {
    p: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReportError> {
        let s = self
            .p
            .get(self.at..self.at + n)
            .ok_or(ReportError::Truncated)?;
        self.at += n;
        Ok(s)
    }

    fn text(&mut self) -> Result<String, ReportError> {
        let n = self.take(1)?[0] as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| ReportError::NotUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ModReport {
        ModReport {
            mods: vec![
                ReportedMod {
                    id: "hello-both".into(),
                    version: "0.1.0".into(),
                    manifest_sha256: sha256(b"mod.toml"),
                    dll_sha256: Some(sha256(b"dll")),
                },
                ReportedMod {
                    id: "data-only".into(),
                    version: "1.2.3".into(),
                    manifest_sha256: sha256(b"other"),
                    dll_sha256: None,
                },
            ],
        }
    }

    #[test]
    fn a_report_round_trips() {
        let r = sample();
        assert_eq!(ModReport::decode(&r.encode()), Ok(r));
        let empty = ModReport::default();
        assert_eq!(empty.encode(), [FORMAT, 0, 0]);
        assert_eq!(ModReport::decode(&empty.encode()), Ok(empty));
    }

    #[test]
    fn the_wire_layout_is_stable() {
        let r = ModReport {
            mods: vec![ReportedMod {
                id: "ab".into(),
                version: "1".into(),
                manifest_sha256: [7; 32],
                dll_sha256: None,
            }],
        };
        let mut want = vec![1, 1, 0, 2, b'a', b'b', 1, b'1'];
        want.extend([7u8; 32]);
        want.push(0);
        assert_eq!(r.encode(), want);
    }

    #[test]
    fn bad_payloads_are_refused() {
        let good = sample().encode();
        for cut in [0, 1, 2, 5, good.len() - 1] {
            assert!(ModReport::decode(&good[..cut]).is_err(), "cut {cut}");
        }
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(ModReport::decode(&extra), Err(ReportError::Trailing));
        let mut format = good.clone();
        format[0] = 9;
        assert_eq!(ModReport::decode(&format), Err(ReportError::Format(9)));
        let mut many = vec![FORMAT];
        many.extend((MAX_MODS as u16 + 1).to_le_bytes());
        assert_eq!(
            ModReport::decode(&many),
            Err(ReportError::TooMany(MAX_MODS + 1))
        );
        let mut utf = good;
        utf[4] = 0xff;
        assert_eq!(ModReport::decode(&utf), Err(ReportError::NotUtf8));
    }

    #[test]
    fn hashes_are_sha256() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_report_travels_as_a_sealed_frame() {
        use crate::sidechannel::{Dir, Kind, SessionKeys, open, seal};
        let keys = SessionKeys::derive(&[3; 64]);
        let frame = seal(&keys, Kind::ModReport, 1, &sample().encode());
        let f = open(&keys, Dir::ClientToServer, &frame).unwrap();
        assert_eq!(f.kind, Kind::ModReport);
        assert_eq!(ModReport::decode(f.payload), Ok(sample()));
        // It is a client frame: the server's key does not open it as one.
        assert!(open(&keys, Dir::ServerToClient, &frame).is_err());
    }
}
