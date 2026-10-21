//! Which captured messages carry secrets: the packet capture drops their bodies when
//! `[packets] redact` is on (the default). Pure logic, so it is unit-tested on the host.
//!
//! Secrets are the Steam ticket and machine hashes, the standalone login's account name and
//! password hash (`Credentials`, login `0x0003`), session tokens, instance tickets and key
//! material.
//!
//! The decision is by message name (from the protocol tables of the build the DLL was made
//! for) and, because the opcode tables are only valid for that build, also by fail-safe: when
//! the running executable is not a build the signature table knows, **every** login-channel
//! message is redacted, whatever its name, and the instance messages that carry the ticket.
//! So a renumbered opcode can never write a credential to `packets.jsonl`.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Channel {
    Login,
    Instance,
    Other,
}

/// `outgoing`: client to server.
pub fn is_secret(
    channel: Channel,
    outgoing: bool,
    opcode: u16,
    name: Option<&str>,
    build_verified: bool,
) -> bool {
    if !build_verified && channel == Channel::Login {
        return true;
    }
    // The instance ticket travels in client 0x000e, sent right after 0x000f Hello (not named
    // in the protocol table).
    if channel == Channel::Instance && outgoing && opcode == 0x000e {
        return true;
    }
    match (channel, outgoing, name) {
        (Channel::Login, true, Some("Credentials" | "Authenticate" | "ResumeSession")) => true,
        (Channel::Login, false, Some("AuthenticationResult" | "InstanceDetails")) => true,
        (Channel::Instance, true, Some("Hello")) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_secret_by_name_and_by_default() {
        assert!(is_secret(
            Channel::Login,
            true,
            0x0003,
            Some("Credentials"),
            true
        ));
        assert!(is_secret(
            Channel::Login,
            true,
            0x0005,
            Some("Authenticate"),
            true
        ));
        assert!(is_secret(
            Channel::Login,
            false,
            0x0014,
            Some("InstanceDetails"),
            true
        ));
        assert!(is_secret(Channel::Instance, true, 0x000e, None, true));
        assert!(is_secret(
            Channel::Instance,
            true,
            0x000f,
            Some("Hello"),
            true
        ));
    }

    #[test]
    fn harmless_messages_stay_readable_on_a_known_build() {
        assert!(!is_secret(
            Channel::Login,
            true,
            0x0001,
            Some("KeepAlive"),
            true
        ));
        assert!(!is_secret(
            Channel::Login,
            false,
            0x0015,
            Some("CharacterList"),
            true
        ));
        assert!(!is_secret(Channel::Instance, false, 0x000e, None, true));
        assert!(!is_secret(Channel::Other, true, 0x0003, None, true));
    }

    #[test]
    fn an_unknown_build_redacts_the_whole_login_channel() {
        // Renumbered: the old table names 0x0003 something else (or nothing) on a new build.
        assert!(is_secret(Channel::Login, true, 0x0003, None, false));
        assert!(is_secret(
            Channel::Login,
            true,
            0x0003,
            Some("KeepAlive"),
            false
        ));
        assert!(is_secret(Channel::Login, false, 0x0004, None, false));
        // The instance channel keeps its name-based rules (no credentials travel there).
        assert!(!is_secret(Channel::Instance, false, 0x0001, None, false));
        assert!(is_secret(Channel::Instance, true, 0x000e, None, false));
    }
}
