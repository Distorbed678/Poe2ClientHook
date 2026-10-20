//! Line-based edits of the installed `poe-hook.toml`, keeping the user's other settings and
//! comments.

use std::path::Path;

use anyhow::{Result, bail};

/// Sets `key = value` in `table` (`None`: the top level, before the first table) of the
/// installed `poe-hook.toml`. `value` is TOML text (strings quoted by the caller).
pub fn set_hook_key(path: &Path, table: Option<&str>, key: &str, value: &str) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    std::fs::write(path, set_key_in_text(&text, table, key, value))?;
    Ok(())
}

/// The string value of top-level `key` (before the first `[table]`) in `text`; `None` if the
/// key is missing or not a quoted string. Comments and other tables are ignored.
pub fn top_level_string(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() != key {
            continue;
        }
        let v = v.split('#').next().unwrap_or("").trim();
        let quote = v.chars().next().filter(|c| *c == '"' || *c == '\'')?;
        let rest = &v[1..];
        return rest.find(quote).map(|end| rest[..end].to_owned());
    }
    None
}

pub(crate) fn set_key_in_text(text: &str, table: Option<&str>, key: &str, value: &str) -> String {
    let line = format!("{key} = {value}");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let header = table.map(|t| format!("[{t}]"));
    // The section: from its header (or the file start) to the next header.
    let start = match &header {
        Some(h) => lines.iter().position(|l| l.trim() == h).map(|i| i + 1),
        None => Some(0),
    };
    let Some(start) = start else {
        lines.push(header.unwrap());
        lines.push(line);
        return lines.join("\n") + "\n";
    };
    let end = lines[start..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |i| start + i);
    let is_key = |l: &str| {
        !l.trim_start().starts_with('#')
            && l.split('=').next().is_some_and(|k| k.trim() == key)
            && l.contains('=')
    };
    match lines[start..end].iter().position(|l| is_key(l)) {
        Some(i) => lines[start + i] = line,
        None if table.is_none() => {
            // After the leading comment block.
            let at = lines[..end]
                .iter()
                .position(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .unwrap_or(end);
            lines.insert(at, line);
        }
        None => lines.insert(start, line),
    }
    lines.join("\n") + "\n"
}

/// The path under which the client sees a host path, for `poe-hook.toml` (`dump_dir`).
/// Under Wine/Proton (host is Unix) `Z:` is `/`, so `/home/u/x` becomes `Z:\home\u\x`; on
/// Windows it is the plain absolute path. The path must exist. Quotes are rejected because the
/// value is written as a TOML literal string.
pub fn hook_path(path: &Path) -> Result<String> {
    let abs = std::fs::canonicalize(path)?;
    let text = abs.to_string_lossy().into_owned();
    if text.contains('\'') {
        bail!("path with a quote cannot go into poe-hook.toml: {text}");
    }
    if cfg!(windows) {
        Ok(text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned())
    } else {
        Ok(format!("Z:{}", text.replace('/', "\\")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# comment\n\nmode = \"private\"\n\n[log]\nlevel = \"debug\"\n\n[features]\n# note\nauto_keys = [\"x\"]\n";

    #[test]
    fn reads_top_level_strings() {
        let t = "# c\nmode = \"private\"  # why\nlogin_mode = 'standalone'\n[log]\nlogin_mode = \"steam\"\n";
        assert_eq!(top_level_string(t, "mode").as_deref(), Some("private"));
        assert_eq!(
            top_level_string(t, "login_mode").as_deref(),
            Some("standalone")
        );
        assert_eq!(top_level_string(t, "missing"), None);
        assert_eq!(top_level_string("[log]\nmode = \"x\"\n", "mode"), None);
    }

    #[test]
    fn replaces_existing_top_level_key() {
        let out = set_key_in_text(SAMPLE, None, "mode", "\"official\"");
        assert!(out.contains("mode = \"official\"\n"));
        assert!(!out.contains("\"private\""));
        assert!(out.contains("# comment"));
    }

    #[test]
    fn inserts_missing_top_level_key_after_comments() {
        let out = set_key_in_text(SAMPLE, None, "dump_dir", "'Z:\\d'");
        let pos = out.find("dump_dir").unwrap();
        assert!(pos > out.find("# comment").unwrap());
        assert!(pos < out.find("[log]").unwrap());
    }

    #[test]
    fn sets_key_inside_table_and_creates_table() {
        let out = set_key_in_text(SAMPLE, Some("features"), "auto_keys", "[]");
        assert!(out.contains("auto_keys = []"));
        assert!(!out.contains("auto_keys = [\"x\"]"));
        let out = set_key_in_text(SAMPLE, Some("new"), "a", "1");
        assert!(out.ends_with("[new]\na = 1\n"));
    }

    #[test]
    fn ignores_commented_keys() {
        let text = "# mode = \"x\"\nmode = \"a\"\n";
        assert_eq!(
            set_key_in_text(text, None, "mode", "\"b\""),
            "# mode = \"x\"\nmode = \"b\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_path_becomes_z_drive() {
        let dir = tempfile::tempdir().unwrap();
        let p = hook_path(dir.path()).unwrap();
        assert!(p.starts_with("Z:\\"));
        assert!(!p.contains('/'));
    }
}
