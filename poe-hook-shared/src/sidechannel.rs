//! Authenticated side channel between the client DLL and our instance server: position
//! reports, the debug link (overlay commands and state) and the terrain upload.
//!
//! Everything here is pure (no Windows calls), so the DLL and the server share one
//! implementation and test it on the host. Wire format: `docs/protocol/side-channel.md`.
//!
//! # Keys
//!
//! Both sides know the 64-byte key material of the instance session: the server issued it in
//! the ticket and sent it in `InstanceDetails`, the client reads it when `EnableEncryption`
//! builds its Salsa20 pair. [`SessionKeys::derive`] turns it into a session id and one HMAC-SHA256
//! key per direction (labels differ from every other use of the material). The material is
//! secret on the wire (the login stream is encrypted), the session id is not.
//!
//! # Frames
//!
//! `b"PSS"`, `u8 version`, `u8 kind`, `u8 flags (0)`, `u64 session id`, `u64 counter`, payload,
//! `tag`: the first [`TAG_LEN`] bytes of HMAC-SHA256 over everything before it, keyed by the
//! direction's key (client-to-server kinds and server-to-client kinds use different keys, and
//! the kind is inside the MAC). Counters start at 1 and rise per sender and stream; the
//! receiver keeps a [`ReplayWindow`] and only advances it for frames whose tag is valid.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// First bytes of every frame.
pub const MAGIC: [u8; 3] = *b"PSS";
/// Wire version (the byte after the magic). Other versions are rejected.
pub const VERSION: u8 = 1;
/// Bytes before the payload.
pub const HEADER_LEN: usize = 22;
/// Truncated HMAC length.
pub const TAG_LEN: usize = 16;
/// First four bytes of a terrain upload on the instance TCP port (never a valid game opcode).
pub const UPLOAD_MAGIC: [u8; 4] = *b"PSUP";
/// First four bytes of the server's answer to an upload.
pub const UPLOAD_REPLY_MAGIC: [u8; 4] = *b"PSUR";
/// Reply status: the offer is wanted (send the upload) / the upload is stored.
pub const REPLY_OK: u8 = 0;
/// Same value, read as the answer to an offer.
pub const REPLY_SEND: u8 = 0;
/// The server already has this terrain.
pub const REPLY_HAVE: u8 = 1;
/// Refused: invalid, too large or inconsistent.
pub const REPLY_REJECTED: u8 = 2;
/// Refused: unknown session, bad tag or replayed counter.
pub const REPLY_AUTH: u8 = 3;

/// The server's answer on the upload connection: `b"PSUR"`, `u8 status`, `u16 length`, text.
/// It is not authenticated (it only tells the client what to do next).
pub fn encode_reply(status: u8, text: &str) -> Vec<u8> {
    let text = &text.as_bytes()[..text.len().min(512)];
    let mut out = Vec::with_capacity(7 + text.len());
    out.extend_from_slice(&UPLOAD_REPLY_MAGIC);
    out.push(status);
    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
    out.extend_from_slice(text);
    out
}

/// What a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Client to server, UDP: the player's position and action for one frame.
    Report = 1,
    /// Client to server, UDP: a server command line typed in the overlay.
    Command = 2,
    /// Server to client, UDP: `key\tvalue` debug state, registry and instance lists.
    Debug = 3,
    /// Client to server, TCP: the terrain layout and grid of an area ([`Upload`]).
    Upload = 4,
    /// Client to server, TCP: `u32 tile hash`, asks whether the server wants that terrain.
    UploadOffer = 5,
}

/// Which way a frame travels (picks the key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    ClientToServer,
    ServerToClient,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Report,
            2 => Self::Command,
            3 => Self::Debug,
            4 => Self::Upload,
            5 => Self::UploadOffer,
            _ => return None,
        })
    }

    pub fn dir(self) -> Dir {
        match self {
            Self::Debug => Dir::ServerToClient,
            _ => Dir::ClientToServer,
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// The keys of one session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Names the session in every frame (not secret).
    pub id: u64,
    c2s: [u8; 32],
    s2c: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKeys({:016x}, ..)", self.id)
    }
}

impl SessionKeys {
    /// Derives the keys from the instance session's 64-byte key material.
    pub fn derive(material: &[u8; 64]) -> Self {
        let id = hmac(material, &[b"poe2-side/v1/session"]);
        Self {
            id: u64::from_le_bytes(id[..8].try_into().unwrap()),
            c2s: hmac(material, &[b"poe2-side/v1/c2s"]),
            s2c: hmac(material, &[b"poe2-side/v1/s2c"]),
        }
    }

    fn key(&self, dir: Dir) -> &[u8; 32] {
        match dir {
            Dir::ClientToServer => &self.c2s,
            Dir::ServerToClient => &self.s2c,
        }
    }
}

/// Builds a frame.
pub fn seal(keys: &SessionKeys, kind: Kind, counter: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind as u8);
    out.push(0);
    out.extend_from_slice(&keys.id.to_le_bytes());
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(payload);
    let tag = hmac(keys.key(kind.dir()), &[&out]);
    out.extend_from_slice(&tag[..TAG_LEN]);
    out
}

/// Why a frame was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Too short, or not our magic (a stray datagram).
    Malformed,
    /// A version this build does not speak.
    Version(u8),
    UnknownKind(u8),
    /// A frame that travels the other way (a reflected server frame).
    WrongDirection,
    /// Names another session.
    WrongSession,
    /// The tag does not match.
    BadTag,
    /// The counter was already seen or is too old.
    Replay,
}

/// A frame whose tag is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub session: u64,
    pub counter: u64,
    pub payload: &'a [u8],
}

/// The session a frame names (before it is authenticated), to find the keys.
pub fn peek_session(frame: &[u8]) -> Option<u64> {
    if frame.len() < HEADER_LEN + TAG_LEN {
        return None;
    }
    peek_session_header(frame)
}

/// The session in the first [`HEADER_LEN`] bytes of a frame (a stream reader that has not read
/// the whole frame yet).
pub fn peek_session_header(header: &[u8]) -> Option<u64> {
    if header.len() < HEADER_LEN || header[..3] != MAGIC {
        return None;
    }
    Some(u64::from_le_bytes(header[6..14].try_into().unwrap()))
}

/// Checks a frame against the session's keys. `dir` is the direction the receiver expects.
/// The replay counter is not checked here (see [`ReplayWindow`]).
pub fn open<'a>(keys: &SessionKeys, dir: Dir, frame: &'a [u8]) -> Result<Frame<'a>, Reject> {
    if frame.len() < HEADER_LEN + TAG_LEN || frame[..3] != MAGIC {
        return Err(Reject::Malformed);
    }
    if frame[3] != VERSION {
        return Err(Reject::Version(frame[3]));
    }
    let kind = Kind::from_u8(frame[4]).ok_or(Reject::UnknownKind(frame[4]))?;
    if kind.dir() != dir {
        return Err(Reject::WrongDirection);
    }
    let session = u64::from_le_bytes(frame[6..14].try_into().unwrap());
    if session != keys.id {
        return Err(Reject::WrongSession);
    }
    let (body, tag) = frame.split_at(frame.len() - TAG_LEN);
    let expect = hmac(keys.key(dir), &[body]);
    if !bool::from(expect[..TAG_LEN].ct_eq(tag)) {
        return Err(Reject::BadTag);
    }
    Ok(Frame {
        kind,
        session,
        counter: u64::from_le_bytes(frame[14..22].try_into().unwrap()),
        payload: &body[HEADER_LEN..],
    })
}

/// Sliding replay window over the last 64 counters (UDP may reorder; nothing is accepted twice).
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplayWindow {
    top: u64,
    seen: u64,
}

impl ReplayWindow {
    /// Accepts `counter` once: it must be above the highest seen, or inside the window and not
    /// seen yet. Counter 0 is never valid. Call it only for frames whose tag was valid.
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if counter > self.top {
            let shift = counter - self.top;
            self.seen = if shift >= 64 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.top = counter;
            return true;
        }
        let back = self.top - counter;
        if back >= 64 || self.seen >> back & 1 == 1 {
            return false;
        }
        self.seen |= 1 << back;
        true
    }
}

/// Position report payload (`Kind::Report`, little-endian, 26 bytes): `u16 flags`, `u32 frame`,
/// `f32 x`, `f32 y` (grid cells), `u16 action`, `u16 action2`, `i16 cursor x`, `i16 cursor y`,
/// `u16 window width`, `u16 window height`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReportPayload {
    pub flags: u16,
    pub frame: u32,
    pub x: f32,
    pub y: f32,
    pub action: u16,
    pub action2: u16,
    pub cursor: (i16, i16),
    pub window: (u16, u16),
}

impl ReportPayload {
    pub const LEN: usize = 26;

    pub fn encode(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(Self::LEN);
        m.extend_from_slice(&self.flags.to_le_bytes());
        m.extend_from_slice(&self.frame.to_le_bytes());
        m.extend_from_slice(&self.x.to_le_bytes());
        m.extend_from_slice(&self.y.to_le_bytes());
        m.extend_from_slice(&self.action.to_le_bytes());
        m.extend_from_slice(&self.action2.to_le_bytes());
        m.extend_from_slice(&self.cursor.0.to_le_bytes());
        m.extend_from_slice(&self.cursor.1.to_le_bytes());
        m.extend_from_slice(&self.window.0.to_le_bytes());
        m.extend_from_slice(&self.window.1.to_le_bytes());
        m
    }

    pub fn decode(p: &[u8]) -> Option<Self> {
        if p.len() < Self::LEN {
            return None;
        }
        let u16_at = |i: usize| u16::from_le_bytes([p[i], p[i + 1]]);
        let u32_at = |i: usize| u32::from_le_bytes(p[i..i + 4].try_into().unwrap());
        Some(Self {
            flags: u16_at(0),
            frame: u32_at(2),
            x: f32::from_bits(u32_at(6)),
            y: f32::from_bits(u32_at(10)),
            action: u16_at(14),
            action2: u16_at(16),
            cursor: (u16_at(18) as i16, u16_at(20) as i16),
            window: (u16_at(22), u16_at(24)),
        })
    }
}

/// Size limits of a terrain upload (the server's config).
#[derive(Debug, Clone, Copy)]
pub struct UploadLimits {
    /// Largest layout after decompression.
    pub layout: usize,
    /// Largest grid after decompression.
    pub grid: usize,
}

/// A terrain upload: the layout TSV and the cell grid (`PWG1`) of one tile hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    pub tile_hash: u32,
    pub layout: Vec<u8>,
    pub grid: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    Truncated,
    /// Unknown compression byte.
    Encoding(u8),
    /// The data does not decompress, or exceeds the limit.
    Inflate(&'static str),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated upload"),
            Self::Encoding(e) => write!(f, "unknown encoding {e}"),
            Self::Inflate(what) => write!(f, "{what} does not inflate within its limit"),
        }
    }
}

impl Upload {
    /// Payload (`Kind::Upload`): `u32 tile hash`, `u8 encoding (1: zlib)`, `u32 layout bytes`,
    /// `u32 grid bytes` (both as sent), the layout, the grid.
    pub fn encode(&self) -> Vec<u8> {
        let layout = miniz_oxide::deflate::compress_to_vec_zlib(&self.layout, 6);
        let grid = miniz_oxide::deflate::compress_to_vec_zlib(&self.grid, 6);
        let mut out = Vec::with_capacity(13 + layout.len() + grid.len());
        out.extend_from_slice(&self.tile_hash.to_le_bytes());
        out.push(1);
        out.extend_from_slice(&(layout.len() as u32).to_le_bytes());
        out.extend_from_slice(&(grid.len() as u32).to_le_bytes());
        out.extend_from_slice(&layout);
        out.extend_from_slice(&grid);
        out
    }

    pub fn decode(p: &[u8], limits: UploadLimits) -> Result<Self, UploadError> {
        let head = p.get(..13).ok_or(UploadError::Truncated)?;
        let tile_hash = u32::from_le_bytes(head[..4].try_into().unwrap());
        if head[4] != 1 {
            return Err(UploadError::Encoding(head[4]));
        }
        let layout_len = u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize;
        let grid_len = u32::from_le_bytes(head[9..13].try_into().unwrap()) as usize;
        let layout = p
            .get(13..)
            .and_then(|r| r.get(..layout_len))
            .ok_or(UploadError::Truncated)?;
        let grid = p
            .get(13 + layout_len..)
            .and_then(|r| r.get(..grid_len))
            .ok_or(UploadError::Truncated)?;
        if 13 + layout_len + grid_len != p.len() {
            return Err(UploadError::Truncated);
        }
        let inflate = |data, limit, what| {
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, limit)
                .map_err(|_| UploadError::Inflate(what))
        };
        Ok(Self {
            tile_hash,
            layout: inflate(layout, limits.layout, "layout")?,
            grid: inflate(grid, limits.grid, "grid")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(seed: u8) -> SessionKeys {
        SessionKeys::derive(&[seed; 64])
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        // Key "Jefe", data "what do ya want for nothing?".
        let tag = hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(tag[..8], [0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e]);
    }

    #[test]
    fn keys_are_per_session_and_per_direction() {
        let (a, b) = (keys(1), keys(2));
        assert_ne!(a.id, b.id);
        assert_ne!(a.c2s, a.s2c);
        assert_eq!(a, keys(1));
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = keys(7);
        let f = seal(&k, Kind::Command, 5, b"area G1_1");
        assert_eq!(peek_session(&f), Some(k.id));
        let o = open(&k, Dir::ClientToServer, &f).unwrap();
        assert_eq!(
            (o.kind, o.session, o.counter, o.payload),
            (Kind::Command, k.id, 5, &b"area G1_1"[..])
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let k = keys(7);
        let f = seal(&k, Kind::Report, 1, &[1, 2, 3]);
        // Every single byte flip fails (header, payload and tag alike).
        for i in 0..f.len() {
            let mut g = f.clone();
            g[i] ^= 0x40;
            assert!(open(&k, Dir::ClientToServer, &g).is_err(), "byte {i}");
        }
        // Truncated, empty and foreign datagrams.
        assert_eq!(
            open(&k, Dir::ClientToServer, &f[..HEADER_LEN]),
            Err(Reject::Malformed)
        );
        assert_eq!(open(&k, Dir::ClientToServer, b""), Err(Reject::Malformed));
        assert_eq!(peek_session(b"PSY2\0\0"), None);
    }

    #[test]
    fn another_sessions_key_does_not_verify() {
        let (a, b) = (keys(1), keys(2));
        let f = seal(&a, Kind::Report, 1, &[0; 26]);
        assert_eq!(open(&b, Dir::ClientToServer, &f), Err(Reject::WrongSession));
        // Same id but a forged key: a tag made with the wrong key fails.
        let mut forged = b.clone();
        forged.id = a.id;
        assert_eq!(open(&forged, Dir::ClientToServer, &f), Err(Reject::BadTag));
    }

    #[test]
    fn directions_do_not_mix() {
        let k = keys(3);
        let debug = seal(&k, Kind::Debug, 1, b"server_pos\t1 2");
        assert!(open(&k, Dir::ServerToClient, &debug).is_ok());
        // The server never accepts a (reflected) server frame.
        assert_eq!(
            open(&k, Dir::ClientToServer, &debug),
            Err(Reject::WrongDirection)
        );
        // Re-labelling a client frame as a server frame breaks the tag.
        let mut report = seal(&k, Kind::Report, 1, &[0; 26]);
        report[4] = Kind::Debug as u8;
        assert_eq!(open(&k, Dir::ServerToClient, &report), Err(Reject::BadTag));
    }

    #[test]
    fn other_versions_are_rejected() {
        let k = keys(3);
        let mut f = seal(&k, Kind::Report, 1, &[0; 26]);
        f[3] = 2;
        assert_eq!(open(&k, Dir::ClientToServer, &f), Err(Reject::Version(2)));
        // The old unauthenticated datagrams are not frames.
        assert_eq!(
            open(
                &k,
                Dir::ClientToServer,
                &[b'P', b'S', b'Y', b'2'].repeat(10)
            ),
            Err(Reject::Malformed)
        );
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(!w.accept(0));
        assert!(w.accept(1));
        assert!(!w.accept(1), "replay");
        assert!(w.accept(3));
        assert!(w.accept(2), "reordered, first time");
        assert!(!w.accept(2));
        assert!(w.accept(100));
        assert!(!w.accept(3), "fell out of the window");
        assert!(w.accept(60), "inside the window, unseen");
        assert!(!w.accept(60));
        assert!(w.accept(1_000_000));
        assert!(!w.accept(100));
    }

    #[test]
    fn report_payload_roundtrip() {
        let r = ReportPayload {
            flags: 0x20,
            frame: 7,
            x: 12.5,
            y: 300.25,
            action: 0xed4c,
            action2: 0,
            cursor: (-5, 300),
            window: (2560, 1440),
        };
        let bytes = r.encode();
        assert_eq!(bytes.len(), ReportPayload::LEN);
        assert_eq!(ReportPayload::decode(&bytes), Some(r));
        assert_eq!(ReportPayload::decode(&bytes[..25]), None);
    }

    const LIMITS: UploadLimits = UploadLimits {
        layout: 1 << 20,
        grid: 1 << 22,
    };

    #[test]
    fn upload_offer_is_a_client_frame_and_replies_encode() {
        let k = keys(4);
        let f = seal(&k, Kind::UploadOffer, 1, &7u32.to_le_bytes());
        assert_eq!(
            open(&k, Dir::ClientToServer, &f).unwrap().kind,
            Kind::UploadOffer
        );
        let r = encode_reply(REPLY_HAVE, "cached");
        assert_eq!(&r[..4], b"PSUR");
        assert_eq!((r[4], u16::from_le_bytes([r[5], r[6]])), (1, 6));
        assert_eq!(&r[7..], b"cached");
    }

    #[test]
    fn upload_roundtrip_and_limits() {
        let up = Upload {
            tile_hash: 3958003549,
            layout: b"size\t2\t2\n0\t0\ta.tdt\t0\n".repeat(50),
            grid: vec![0x55; 100_000],
        };
        let bytes = up.encode();
        assert!(bytes.len() < up.layout.len() + up.grid.len(), "compressed");
        assert_eq!(Upload::decode(&bytes, LIMITS), Ok(up.clone()));
        // A decompression bomb stays inside the limit.
        let bomb = Upload {
            tile_hash: 1,
            layout: vec![0; 10],
            grid: vec![0; 5 << 20],
        };
        assert_eq!(
            Upload::decode(&bomb.encode(), LIMITS),
            Err(UploadError::Inflate("grid"))
        );
        // Truncated and trailing bytes.
        assert_eq!(
            Upload::decode(&bytes[..bytes.len() - 1], LIMITS),
            Err(UploadError::Truncated)
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(Upload::decode(&long, LIMITS), Err(UploadError::Truncated));
        assert_eq!(
            Upload::decode(&bytes[..5], LIMITS),
            Err(UploadError::Truncated)
        );
        let mut bad = bytes;
        bad[4] = 9;
        assert_eq!(Upload::decode(&bad, LIMITS), Err(UploadError::Encoding(9)));
    }
}
