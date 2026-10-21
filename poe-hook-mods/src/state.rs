//! `poe-hook-mods/state.toml`: `enabled = ["id", ...]`, the enabled mods in load order. The
//! launcher writes it (it resolves dependencies and order); the loader only reads it. A mod
//! folder that is not listed is installed but disabled.

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    #[serde(default)]
    pub enabled: Vec<String>,
}

pub fn parse_state(text: &str) -> Result<State, String> {
    toml::from_str(text).map_err(|e| format!("state.toml is not valid: {e}"))
}

/// The file's text, in the shape the launcher writes.
pub fn state_text(enabled: &[String]) -> String {
    let body = toml::to_string(&State {
        enabled: enabled.to_vec(),
    })
    .unwrap_or_default();
    format!(
        "# `enabled` is the load order. Written by the Poe2 launcher or `cargo xtask deploy-mod`.\n{body}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_keeps_order_and_empty_is_fine() {
        let s = parse_state("enabled = [\"core-lib\", \"alpha\", \"beta\"]\n").unwrap();
        assert_eq!(s.enabled, ["core-lib", "alpha", "beta"]);
        assert!(parse_state("").unwrap().enabled.is_empty());
        assert!(
            parse_state("# only a comment\n")
                .unwrap()
                .enabled
                .is_empty()
        );
    }

    #[test]
    fn state_rejects_garbage() {
        assert!(parse_state("enabled = 3").is_err());
        assert!(parse_state("enabled = [1, 2]").is_err());
        assert!(parse_state("not toml [").is_err());
    }

    #[test]
    fn state_text_round_trips() {
        let ids = vec!["b-mod".to_owned(), "a-mod".to_owned()];
        let text = state_text(&ids);
        assert!(text.contains("enabled = [\"b-mod\", \"a-mod\"]"), "{text}");
        assert_eq!(parse_state(&text).unwrap().enabled, ids);
    }
}
