//! The `trusted_servers` list the deploy writes to `poe-hook.toml`.
//!
//! The DLL accepts IPv4 literals only (`ip:port`, `ip:*`, `ip`): it decides inside the
//! connect hook under the loader lock and must not resolve names. Names are resolved here, on
//! the host, when the list is written.

use std::net::{Ipv4Addr, ToSocketAddrs};

/// Domains of the official game services. A name under one of them is never accepted into
/// `trusted_servers`: a trusted address switches the read-only latch off for that connection,
/// and a typo or a pasted official gateway must not turn the client's official session into a
/// "private" one (docs/architecture/client-dll.md). A safety deny-list, not game data. IP
/// literals cannot be checked this way: only names are.
pub const OFFICIAL_DOMAINS: &[&str] = &["pathofexile.com", "pathofexile2.com", "grindinggear.com"];

/// Whether `host` is an official game domain or a subdomain of one.
pub fn is_official_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    OFFICIAL_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Resolves host names to IPv4 literals, validates entries and removes duplicates. Returns
/// the entries to write and a warning for each entry that was dropped.
pub fn resolve_trusted_servers(entries: &[String]) -> (Vec<String>, Vec<String>) {
    resolve_with(entries, |host| {
        (host, 0)
            .to_socket_addrs()
            .map(|it| {
                it.filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect()
            })
            .unwrap_or_default()
    })
}

pub(crate) fn resolve_with(
    entries: &[String],
    resolver: impl Fn(&str) -> Vec<Ipv4Addr>,
) -> (Vec<String>, Vec<String>) {
    let (mut out, mut warnings) = (Vec::<String>::new(), Vec::new());
    for entry in entries {
        let entry = entry.trim();
        let (host, port) = match entry.rsplit_once(':') {
            Some((h, p)) if p == "*" || p.parse::<u16>().is_ok_and(|p| p != 0) => (h, Some(p)),
            Some((_, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                warnings.push(format!("trusted server {entry:?}: bad port"));
                continue;
            }
            _ => (entry, None),
        };
        if is_official_host(host) {
            warnings.push(format!(
                "trusted server {entry:?}: an official game host can never be trusted, dropped"
            ));
            continue;
        }
        let ips = match host.parse::<Ipv4Addr>() {
            Ok(ip) => vec![ip],
            Err(_) if is_hostname(host) => resolver(host),
            Err(_) => Vec::new(),
        };
        if ips.is_empty() {
            warnings.push(format!(
                "trusted server {entry:?}: not an IPv4 address and could not be resolved, dropped"
            ));
            continue;
        }
        for ip in ips {
            let line = match port {
                Some(p) => format!("{ip}:{p}"),
                None => ip.to_string(),
            };
            if !out.contains(&line) {
                out.push(line);
            }
        }
    }
    (out, warnings)
}

fn is_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// TOML text of a string array: `["a", "b"]`. Entries come from [`resolve_trusted_servers`]
/// (digits, dots, colon, `*`), so no escaping is needed.
pub fn toml_array(entries: &[String]) -> String {
    let items: Vec<String> = entries.iter().map(|e| format!("\"{e}\"")).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn literals_pass_and_duplicates_go() {
        let (out, warn) = resolve_with(
            &s(&[
                "192.168.1.20:20481",
                "192.168.1.20:20481",
                "10.0.0.1",
                "10.0.0.2:*",
            ]),
            |_| panic!("no lookups for literals"),
        );
        assert_eq!(out, s(&["192.168.1.20:20481", "10.0.0.1", "10.0.0.2:*"]));
        assert!(warn.is_empty());
    }

    #[test]
    fn hostnames_are_resolved() {
        let (out, warn) = resolve_with(&s(&["play.example.org:20481"]), |h| {
            assert_eq!(h, "play.example.org");
            vec![Ipv4Addr::new(203, 0, 113, 7)]
        });
        assert_eq!(out, s(&["203.0.113.7:20481"]));
        assert!(warn.is_empty());
    }

    #[test]
    fn unresolvable_and_bad_entries_are_dropped_with_a_warning() {
        let (out, warn) = resolve_with(
            &s(&[
                "nowhere.invalid:1",
                "1.2.3.4:0",
                "1.2.3.4:70000",
                "\"x\":1",
                "",
            ]),
            |_| Vec::new(),
        );
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(warn.len(), 5);
    }

    #[test]
    fn array_text() {
        assert_eq!(toml_array(&[]), "[]");
        assert_eq!(
            toml_array(&s(&["1.2.3.4:5", "6.7.8.9"])),
            r#"["1.2.3.4:5", "6.7.8.9"]"#
        );
    }

    #[test]
    fn official_hosts_are_refused_without_a_lookup() {
        let (out, warn) = resolve_with(
            &s(&[
                "gateway.pathofexile.com:20481",
                "PATHOFEXILE2.com",
                "login.eu.grindinggear.com.",
                "notpathofexile.com",
                "192.168.1.20",
            ]),
            |host| {
                assert_eq!(host, "notpathofexile.com", "official names are never resolved");
                vec![Ipv4Addr::new(10, 0, 0, 9)]
            },
        );
        assert_eq!(out, s(&["10.0.0.9", "192.168.1.20"]));
        assert_eq!(warn.len(), 3, "{warn:?}");
        assert!(warn.iter().all(|w| w.contains("official game host")));
        assert!(is_official_host("a.b.pathofexile.com") && !is_official_host("example.org"));
    }
}
