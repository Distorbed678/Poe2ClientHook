//! Which servers the client may treat like our own: loopback always, plus the
//! `trusted_servers` list of `poe-hook.toml`.
//!
//! One helper, [`is_trusted`], decides for the whole hook:
//!
//! - the network guard (`poe-hook`): a connection that is not trusted is *external*. In private
//!   mode with `block_external` it is refused; otherwise it switches the read-only latch on;
//! - [`crate::abi::Connection::external`] is exactly `!is_trusted(addr)`;
//! - the core's crypto bypass and `custom_server()` (overlay features that talk to our server)
//!   require the connections to be trusted.
//!
//! Entries are `ip:port`, `ip:*` or a bare `ip` (any port). Only IPv4 literals are accepted
//! here: the loader decides under the loader lock and must not resolve names. Names are
//! resolved when the list is written (`poe-hook-deploy`). IPv6 is never trusted, except the
//! loopback address `::1`, as before every non-IPv4 family counts as external.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::RwLock,
};

/// One parsed `trusted_servers` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedServer {
    pub ip: Ipv4Addr,
    /// `None`: any port.
    pub port: Option<u16>,
}

impl TrustedServer {
    /// Parses `ip:port`, `ip:*` or `ip`.
    pub fn parse(entry: &str) -> Result<Self, String> {
        let entry = entry.trim();
        let (host, port) = match entry.rsplit_once(':') {
            Some((host, "*")) => (host, None),
            Some((host, port)) => {
                let port: u16 = port
                    .parse()
                    .map_err(|_| format!("{entry:?}: bad port {port:?}"))?;
                if port == 0 {
                    return Err(format!("{entry:?}: port 0"));
                }
                (host, Some(port))
            }
            None => (entry, None),
        };
        let ip: Ipv4Addr = host.parse().map_err(|_| {
            format!("{entry:?}: not an IPv4 address (names are resolved at deploy)")
        })?;
        Ok(Self { ip, port })
    }

    pub fn matches(&self, addr: &SocketAddr) -> bool {
        match addr {
            SocketAddr::V4(a) => *a.ip() == self.ip && self.port.is_none_or(|p| p == a.port()),
            SocketAddr::V6(_) => false,
        }
    }
}

/// Parses a list; invalid entries are skipped and returned as messages (never trusted).
pub fn parse_list(entries: &[String]) -> (Vec<TrustedServer>, Vec<String>) {
    let (mut ok, mut errors) = (Vec::new(), Vec::new());
    for e in entries {
        match TrustedServer::parse(e) {
            Ok(t) => ok.push(t),
            Err(msg) => errors.push(msg),
        }
    }
    (ok, errors)
}

/// The trust decision for a list: loopback, or an entry of the list.
pub fn is_trusted_in(list: &[TrustedServer], addr: &SocketAddr) -> bool {
    addr.ip().is_loopback() || list.iter().any(|t| t.matches(addr))
}

/// This DLL's copy of the list (the loader and the core each hold their own; both call
/// [`set_trusted_servers`] with the config they loaded).
static TRUSTED: RwLock<Vec<TrustedServer>> = RwLock::new(Vec::new());

/// Installs the list; returns messages for the entries that were rejected.
pub fn set_trusted_servers(entries: &[String]) -> Vec<String> {
    let (list, errors) = parse_list(entries);
    *TRUSTED.write().unwrap_or_else(|e| e.into_inner()) = list;
    errors
}

/// The installed entries.
pub fn trusted_servers() -> Vec<TrustedServer> {
    TRUSTED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether the client may treat `addr` like our own server (see the module docs).
pub fn is_trusted(addr: &SocketAddr) -> bool {
    is_trusted_in(&TRUSTED.read().unwrap_or_else(|e| e.into_inner()), addr)
}

/// [`is_trusted`] for an IPv4 address and port as recorded by the connect hook.
pub fn is_trusted_v4(ip: [u8; 4], port: u16) -> bool {
    is_trusted(&SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
}

/// [`side_channel_allowed`] for an explicit list.
pub fn side_channel_allowed_in(list: &[TrustedServer], read_only: bool, addr: &SocketAddr) -> bool {
    !read_only && is_trusted_in(list, addr)
}

/// Whether the DLL may send anything to `addr` over the side channel (position reports, debug
/// link commands, terrain upload; `sidechannel.rs`): never while the read-only latch is on
/// (official servers) and only to loopback or a `trusted_servers` entry. Every outgoing
/// side-channel send passes this gate.
pub fn side_channel_allowed(read_only: bool, addr: &SocketAddr) -> bool {
    !read_only && is_trusted(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn list(entries: &[&str]) -> Vec<TrustedServer> {
        let owned: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        let (list, errors) = parse_list(&owned);
        assert!(errors.is_empty(), "{errors:?}");
        list
    }

    #[test]
    fn loopback_is_always_trusted() {
        for a in ["127.0.0.1:20481", "127.5.6.7:1", "[::1]:6112"] {
            assert!(is_trusted_in(&[], &sa(a)), "{a}");
        }
    }

    #[test]
    fn remote_is_untrusted_by_default() {
        for a in ["192.168.1.20:20481", "8.8.8.8:443", "[2001:db8::1]:6112"] {
            assert!(!is_trusted_in(&[], &sa(a)), "{a}");
        }
    }

    #[test]
    fn exact_ip_and_port_match() {
        let l = list(&["192.168.1.20:20481", "192.168.1.20:6112"]);
        assert!(is_trusted_in(&l, &sa("192.168.1.20:20481")));
        assert!(is_trusted_in(&l, &sa("192.168.1.20:6112")));
        assert!(!is_trusted_in(&l, &sa("192.168.1.20:443")));
        assert!(!is_trusted_in(&l, &sa("192.168.1.21:20481")));
    }

    #[test]
    fn wildcard_and_bare_ip_accept_any_port() {
        for entry in ["10.0.0.5:*", "10.0.0.5"] {
            let l = list(&[entry]);
            assert!(is_trusted_in(&l, &sa("10.0.0.5:1")), "{entry}");
            assert!(is_trusted_in(&l, &sa("10.0.0.5:65535")), "{entry}");
            assert!(!is_trusted_in(&l, &sa("10.0.0.6:1")), "{entry}");
        }
    }

    #[test]
    fn ipv6_is_never_trusted_by_the_list() {
        let l = list(&["10.0.0.5:*"]);
        assert!(!is_trusted_in(&l, &sa("[::ffff:10.0.0.5]:6112")));
    }

    #[test]
    fn bad_entries_are_rejected_and_never_trust_anything() {
        let entries: Vec<String> = ["example.com:80", "1.2.3.4:0", "1.2.3.4:99999", "", "::1:5"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (ok, errors) = parse_list(&entries);
        assert!(ok.is_empty(), "{ok:?}");
        assert_eq!(errors.len(), entries.len());
        assert!(!is_trusted_in(&ok, &sa("1.2.3.4:80")));
    }

    #[test]
    fn whitespace_is_trimmed() {
        let l = list(&["  192.168.0.2:5  "]);
        assert!(is_trusted_in(&l, &sa("192.168.0.2:5")));
    }

    #[test]
    fn installed_list_drives_is_trusted() {
        // The only test touching the global.
        assert!(!is_trusted_v4([192, 168, 1, 20], 20481));
        assert!(is_trusted_v4([127, 0, 0, 1], 20481));
        let errors = set_trusted_servers(&["192.168.1.20:20481".into(), "nope".into()]);
        assert_eq!(errors.len(), 1);
        assert!(is_trusted_v4([192, 168, 1, 20], 20481));
        assert!(!is_trusted_v4([192, 168, 1, 20], 20482));
        set_trusted_servers(&[]);
        assert!(!is_trusted_v4([192, 168, 1, 20], 20481));
    }

    #[test]
    fn side_channel_never_goes_to_official_or_read_only() {
        let l = list(&["192.168.1.20:6112"]);
        // An official server (untrusted address) gets nothing, latched or not.
        for ro in [false, true] {
            assert!(!side_channel_allowed_in(&l, ro, &sa("203.0.113.9:6112")));
            assert!(!side_channel_allowed_in(&[], ro, &sa("192.168.1.20:6112")));
        }
        // Read-only (the latch) blocks even a trusted or loopback address.
        assert!(!side_channel_allowed_in(&l, true, &sa("192.168.1.20:6112")));
        assert!(!side_channel_allowed_in(&l, true, &sa("127.0.0.1:6112")));
        // Trusted and loopback, latch off: allowed.
        assert!(side_channel_allowed_in(&l, false, &sa("192.168.1.20:6112")));
        assert!(side_channel_allowed_in(&l, false, &sa("127.0.0.1:6112")));
        assert!(!side_channel_allowed_in(&l, false, &sa("192.168.1.20:443")));
    }
}
