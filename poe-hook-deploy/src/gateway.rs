//! The client's `gateway_list.txt` (UTF-16LE with a BOM, one `;`-separated entry per line).

/// One realm entry. The client connects to `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayEntry {
    pub region: String,
    pub display_name: String,
    pub host: String,
    pub port: u16,
}

impl GatewayEntry {
    /// `region;name;host:port;host;false`
    pub fn line(&self) -> String {
        format!(
            "{};{};{}:{};{};false",
            self.region, self.display_name, self.host, self.port, self.host
        )
    }
}

pub fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// The client remembers the last gateway (`gateway_id` in its config, inside the Wine prefix);
/// after an official session it would stay on an official realm that our gateway list lacks.
/// Rewrites it to `name` in the prefix's `poe2_production_Config.ini` if that exists.
/// Returns whether a file was changed.
pub fn select_gateway_in_prefix(prefix_dir: &std::path::Path, name: &str) -> anyhow::Result<bool> {
    let ini = prefix_dir.join(
        "pfx/drive_c/users/steamuser/Documents/My Games/Path of Exile 2/poe2_production_Config.ini",
    );
    let Ok(text) = std::fs::read_to_string(&ini) else {
        return Ok(false);
    };
    let lines: Vec<String> = text
        .lines()
        .map(|l| {
            if l.starts_with("gateway_id=") {
                format!("gateway_id={name}")
            } else {
                l.to_owned()
            }
        })
        .collect();
    std::fs::write(&ini, lines.join("\n") + "\n")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_line() {
        let e = GatewayEntry {
            region: "Europe".into(),
            display_name: "Local".into(),
            host: "127.0.0.1".into(),
            port: 20481,
        };
        assert_eq!(e.line(), "Europe;Local;127.0.0.1:20481;127.0.0.1;false");
    }

    #[test]
    fn utf16_has_bom() {
        assert_eq!(utf16le_with_bom("ab"), [0xff, 0xfe, b'a', 0, b'b', 0]);
    }
}
