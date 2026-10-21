//! Pure decision logic of the network guard (`poe-hook/src/guard.rs`), kept here so it is
//! unit-tested on the host: what to do with a connection attempt, how a host name or list
//! the Winsock helper APIs (`WSAConnectByName`, `WSAConnectByList`) take is judged, and how
//! the `ConnectEx` function pointer is recognised in a `WSAIoctl` call.
//!
//! Rule for every connect API alike: the destination is *trusted* (loopback or an entry of
//! `trusted_servers`, [`crate::trust`]) or *external*. External plus `block_external` is
//! refused; external otherwise switches the read-only latch on. A destination the guard
//! cannot judge without resolving a name (a host name, a non-numeric service) is external.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::trust;

/// `WSAIoctl` control code `SIO_GET_EXTENSION_FUNCTION_POINTER` (`_WSAIORW(IOC_WS2, 6)`).
pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;

/// `WSAID_CONNECTEX` {25a207b9-ddf3-4660-8ee9-76e58c74063e} in memory layout (little-endian
/// `Data1..Data3`).
pub const WSAID_CONNECTEX: [u8; 16] = [
    0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e,
];

/// What the guard does with one connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Refuse (private mode, `block_external`, external destination).
    Block,
    /// Let it through; `latch` is true when this attempt must switch the read-only latch on
    /// (the caller still checks whether it is already on, to log only the first time).
    Allow { latch: bool },
}

/// The decision shared by every hooked connect API.
pub fn decide(external: bool, block_external: bool) -> Verdict {
    if external && block_external {
        Verdict::Block
    } else {
        Verdict::Allow { latch: external }
    }
}

/// Whether a `WSAIoctl` call asks for the `ConnectEx` function pointer (the only way to get
/// the function; `mswsock` does not export it by name).
pub fn is_connect_ex_request(code: u32, input: Option<&[u8]>) -> bool {
    code == SIO_GET_EXTENSION_FUNCTION_POINTER && input == Some(&WSAID_CONNECTEX[..])
}

/// The numeric IPv4 target of a `WSAConnectByName` call: a dotted-quad `node` and a decimal
/// `service`. Anything else (a host name, a service name such as `http`, port 0) is `None`:
/// the guard does not resolve names, so such a target is external.
pub fn parse_v4_target(node: &str, service: &str) -> Option<([u8; 4], u16)> {
    let ip: Ipv4Addr = node.trim().parse().ok()?;
    let port: u16 = service.trim().parse().ok().filter(|p| *p != 0)?;
    Some((ip.octets(), port))
}

/// Trust decision for a `WSAConnectByName` target: only a numeric target that is trusted.
pub fn name_target_external(node: &str, service: &str) -> bool {
    match parse_v4_target(node, service) {
        Some((ip, port)) => !trust::is_trusted_v4(ip, port),
        None => true,
    }
}

/// Trust decision for a `WSAConnectByList` call: external as soon as one entry is (the API
/// may connect to any of them). `None` entries are non-IPv4 or unreadable, so external. An
/// empty list is external too (nothing to judge).
pub fn list_external(entries: &[Option<([u8; 4], u16)>]) -> bool {
    entries.is_empty()
        || entries
            .iter()
            .any(|e| e.is_none_or(|(ip, port)| !trust::is_trusted_v4(ip, port)))
}

/// Same as [`list_external`] for an explicit trust list (tests).
pub fn list_external_in(list: &[trust::TrustedServer], entries: &[Option<([u8; 4], u16)>]) -> bool {
    entries.is_empty()
        || entries.iter().any(|e| match e {
            Some((ip, port)) => !trust::is_trusted_in(
                list,
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port),
            ),
            None => true,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> Vec<trust::TrustedServer> {
        let owned: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        trust::parse_list(&owned).0
    }

    #[test]
    fn decide_blocks_external_in_private_mode_only() {
        assert_eq!(decide(true, true), Verdict::Block);
        assert_eq!(decide(true, false), Verdict::Allow { latch: true });
        assert_eq!(decide(false, true), Verdict::Allow { latch: false });
        assert_eq!(decide(false, false), Verdict::Allow { latch: false });
    }

    #[test]
    fn connect_ex_guid_layout() {
        // {25a207b9-ddf3-4660-8ee9-76e58c74063e}
        let mut g = Vec::new();
        g.extend_from_slice(&0x25a2_07b9u32.to_le_bytes());
        g.extend_from_slice(&0xddf3u16.to_le_bytes());
        g.extend_from_slice(&0x4660u16.to_le_bytes());
        g.extend_from_slice(&[0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e]);
        assert_eq!(g, WSAID_CONNECTEX);
    }

    #[test]
    fn only_the_connect_ex_pointer_request_is_recognised() {
        let guid = &WSAID_CONNECTEX[..];
        assert!(is_connect_ex_request(
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(guid)
        ));
        // another ioctl, another GUID (AcceptEx), a short buffer, no input
        assert!(!is_connect_ex_request(0x9800_0004, Some(guid)));
        let mut other = WSAID_CONNECTEX;
        other[0] ^= 1;
        assert!(!is_connect_ex_request(
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&other)
        ));
        assert!(!is_connect_ex_request(
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&guid[..8])
        ));
        assert!(!is_connect_ex_request(
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            None
        ));
    }

    #[test]
    fn name_targets_need_a_numeric_address_and_port() {
        assert_eq!(
            parse_v4_target("127.0.0.1", "20481"),
            Some(([127, 0, 0, 1], 20481))
        );
        assert_eq!(
            parse_v4_target(" 10.0.0.5 ", " 6112 "),
            Some(([10, 0, 0, 5], 6112))
        );
        for (n, s) in [
            ("example.com", "443"),
            ("127.0.0.1", "http"),
            ("127.0.0.1", "0"),
            ("127.0.0.1", "99999"),
            ("localhost", "80"),
            ("::1", "80"),
            ("", ""),
        ] {
            assert_eq!(parse_v4_target(n, s), None, "{n}:{s}");
        }
    }

    #[test]
    fn names_are_external_unless_a_trusted_literal() {
        // Loopback literal is trusted without any list (the global list is empty here).
        assert!(!name_target_external("127.0.0.1", "20481"));
        assert!(name_target_external("localhost", "20481"));
        assert!(name_target_external("pathofexile.com", "443"));
        assert!(name_target_external("203.0.113.9", "6112"));
        assert!(name_target_external("127.0.0.1", "http"));
    }

    #[test]
    fn a_list_is_external_when_any_entry_is() {
        let l = list(&["192.168.1.20:20481"]);
        let ours = Some(([192, 168, 1, 20], 20481));
        let loopback = Some(([127, 0, 0, 1], 1));
        let official = Some(([203, 0, 113, 9], 6112));
        assert!(!list_external_in(&l, &[ours, loopback]));
        assert!(list_external_in(&l, &[ours, official]));
        assert!(list_external_in(&l, &[official]));
        assert!(list_external_in(&l, &[ours, None]), "non-IPv4 entry");
        assert!(list_external_in(&l, &[]), "empty list");
        assert!(list_external_in(&[], &[ours]), "no trusted_servers entry");
    }
}
