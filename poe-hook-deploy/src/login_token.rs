//! Launcher-provided remember-me token for the standalone login.
//!
//! With `login_mode = "standalone"` the client keeps a "Remember Me" login as a 32-byte
//! server-issued token in `<Documents>\My Games\Path of Exile 2\<name>_login.credentials`
//! and the account name plus `save_login` in `<name>_Config.ini` (`[LOGIN]`). On the next
//! start, with an empty password box, it sends that token instead of a password hash
//! (`0x0003` with `token_login = 1`), so a launcher can sign a player in by writing those two
//! files before the client starts. The client reads them itself: the DLL needs no code for
//! this. Details: `docs/re/standalone-login.md` section 4 in Poe2ModdingProject.
//!
//! The file and key names are the best reading of the static RE and are parameters
//! ([`LoginTokenFiles`]) until a first remember-me login has been seen on disk: the credentials
//! name is `<config name>` (default `poe2_production`) + `_login.credentials` (string at
//! Ghidra `0x14316ab08`), and `config.json` can override it (`GGG_CREDENTIAL_FILE_NAME`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The client's configuration display name (default `poe2_production`).
pub const DEFAULT_CONFIG_NAME: &str = "poe2_production";
/// Appended to the config name for the token file.
pub const CREDENTIALS_SUFFIX: &str = "_login.credentials";
/// Appended to the config name for the ini file.
pub const INI_SUFFIX: &str = "_Config.ini";
/// The client's documents folder below the Windows `Documents` directory.
pub const GAME_DOCUMENTS: &str = "My Games/Path of Exile 2";
/// Where a Proton prefix keeps the Windows user's documents.
const PREFIX_DOCUMENTS: [&str; 2] = [
    "pfx/drive_c/users/steamuser/Documents",
    "drive_c/users/steamuser/Documents",
];

/// File and key names; the defaults are the client's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginTokenFiles {
    /// Name of the token file inside `Documents/My Games/Path of Exile 2/`.
    pub credentials_file: String,
    /// Name of the ini file in the same folder.
    pub ini_file: String,
    /// Ini section (`LOGIN`).
    pub section: String,
    /// Key holding the last account name (`username`).
    pub username_key: String,
    /// Key that enables remembering the login (`save_login`).
    pub save_login_key: String,
}

impl Default for LoginTokenFiles {
    fn default() -> Self {
        Self {
            credentials_file: format!("{DEFAULT_CONFIG_NAME}{CREDENTIALS_SUFFIX}"),
            ini_file: format!("{DEFAULT_CONFIG_NAME}{INI_SUFFIX}"),
            section: "LOGIN".into(),
            username_key: "username".into(),
            save_login_key: "save_login".into(),
        }
    }
}

/// What [`write_login_token`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginTokenReport {
    pub credentials: PathBuf,
    pub ini: PathBuf,
}

/// The Windows `Documents` directory for a Proton prefix directory (`<prefix>/pfx/drive_c/...`
/// or the `pfx` directory itself); any other path is taken to be the `Documents` directory.
pub fn documents_dir(prefix_or_documents_dir: &Path) -> PathBuf {
    PREFIX_DOCUMENTS
        .iter()
        .map(|rel| prefix_or_documents_dir.join(rel))
        .find(|p| p.is_dir())
        .unwrap_or_else(|| prefix_or_documents_dir.to_path_buf())
}

/// [`write_login_token_with`] with the client's default names.
pub fn write_login_token(
    prefix_or_documents_dir: &Path,
    account: &str,
    token: [u8; 32],
) -> Result<LoginTokenReport> {
    write_login_token_with(
        prefix_or_documents_dir,
        account,
        token,
        &LoginTokenFiles::default(),
    )
}

/// Writes the 32-byte token file and sets `[LOGIN] username=<account>` and
/// `save_login=true` in the ini, creating the folder and the files as needed and keeping the
/// rest of the ini. The token is a secret: the file is created readable by the owner only
/// (Unix) and it is never logged.
pub fn write_login_token_with(
    prefix_or_documents_dir: &Path,
    account: &str,
    token: [u8; 32],
    names: &LoginTokenFiles,
) -> Result<LoginTokenReport> {
    check_account(account)?;
    if token == [0u8; 32] {
        bail!("an all-zero token is ignored by the client");
    }
    let dir = documents_dir(prefix_or_documents_dir).join(GAME_DOCUMENTS);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let credentials = dir.join(&names.credentials_file);
    write_secret(&credentials, &token)?;

    let ini = dir.join(&names.ini_file);
    let text = std::fs::read_to_string(&ini).unwrap_or_default();
    let text = set_ini_value(&text, &names.section, &names.username_key, account);
    let text = set_ini_value(&text, &names.section, &names.save_login_key, "true");
    std::fs::write(&ini, text).with_context(|| format!("writing {}", ini.display()))?;
    Ok(LoginTokenReport { credentials, ini })
}

/// Parses 64 hex digits (case-insensitive, no separators) into a token.
pub fn parse_token_hex(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        bail!(
            "a token is 64 hex digits (32 bytes), got {} characters",
            hex.len()
        );
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .with_context(|| "token is not hexadecimal")?;
    }
    Ok(out)
}

fn check_account(account: &str) -> Result<()> {
    if account.trim().is_empty() || account.chars().any(char::is_control) {
        bail!("account name must be non-empty and free of control characters");
    }
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

/// Sets `key=value` in `[section]` of an ini text, keeping everything else: a UTF-8 BOM,
/// the line ending (LF or CRLF) and other keys. Creates the key or the section when missing.
pub fn set_ini_value(text: &str, section: &str, key: &str, value: &str) -> String {
    const BOM: char = '\u{feff}';
    let (bom, body) = match text.strip_prefix(BOM) {
        Some(rest) => (true, rest),
        None => (text.is_empty(), text),
    };
    let eol = if body.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
    let header = format!("[{section}]");
    let new_line = format!("{key}={value}");
    let is_header = |l: &str| l.trim().starts_with('[') && l.trim().ends_with(']');
    match lines.iter().position(|l| l.trim() == header) {
        Some(h) => {
            let end = lines[h + 1..]
                .iter()
                .position(|l| is_header(l))
                .map_or(lines.len(), |i| h + 1 + i);
            let existing = lines[h + 1..end].iter().position(|l| {
                l.split_once('=')
                    .is_some_and(|(k, _)| k.trim() == key && !k.trim_start().starts_with(';'))
            });
            match existing {
                Some(i) => lines[h + 1 + i] = new_line,
                None => lines.insert(h + 1, new_line),
            }
        }
        None => {
            lines.push(header);
            lines.push(new_line);
        }
    }
    let mut out = String::new();
    if bom {
        out.push(BOM);
    }
    out.push_str(&lines.join(eol));
    out.push_str(eol);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const INI: &str = "\u{feff}[LOGIN]\ngateway_auto_select=false\naccount_name=\ngateway_id=Canada\n[DISPLAY]\nvsync_mode=Locked\n";

    #[test]
    fn sets_new_key_in_existing_section() {
        let out = set_ini_value(INI, "LOGIN", "username", "alice");
        assert!(out.starts_with("\u{feff}[LOGIN]\nusername=alice\n"));
        assert!(out.contains("gateway_id=Canada\n[DISPLAY]"));
    }

    #[test]
    fn replaces_existing_key_only_in_its_section() {
        let text = "[A]\nusername=x\n[LOGIN]\nusername=old\nsave_login=false\n";
        let out = set_ini_value(text, "LOGIN", "username", "bob");
        assert_eq!(
            out,
            "[A]\nusername=x\n[LOGIN]\nusername=bob\nsave_login=false\n"
        );
        let out = set_ini_value(&out, "LOGIN", "save_login", "true");
        assert!(out.ends_with("username=bob\nsave_login=true\n"));
    }

    #[test]
    fn creates_missing_section_and_file() {
        let out = set_ini_value("[X]\na=1\n", "LOGIN", "username", "c");
        assert_eq!(out, "[X]\na=1\n[LOGIN]\nusername=c\n");
        let fresh = set_ini_value("", "LOGIN", "save_login", "true");
        assert_eq!(fresh, "\u{feff}[LOGIN]\nsave_login=true\n");
    }

    #[test]
    fn keeps_crlf() {
        let out = set_ini_value("[LOGIN]\r\na=1\r\n", "LOGIN", "username", "d");
        assert_eq!(out, "[LOGIN]\r\nusername=d\r\na=1\r\n");
    }

    #[test]
    fn token_hex() {
        let hex = "00".repeat(31) + "ff";
        let t = parse_token_hex(&hex).unwrap();
        assert_eq!(t[31], 0xff);
        assert!(parse_token_hex("abc").is_err());
        assert!(parse_token_hex(&"zz".repeat(32)).is_err());
        assert!(parse_token_hex(&"é".repeat(32)).is_err());
    }

    #[test]
    fn writes_token_and_ini_into_a_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let docs = tmp.path().join(PREFIX_DOCUMENTS[0]);
        let game = docs.join(GAME_DOCUMENTS);
        std::fs::create_dir_all(&game).unwrap();
        std::fs::write(game.join("poe2_production_Config.ini"), INI).unwrap();
        let token = [7u8; 32];
        let report = write_login_token(tmp.path(), "alice", token).unwrap();
        assert_eq!(
            report.credentials,
            game.join("poe2_production_login.credentials")
        );
        assert_eq!(std::fs::read(&report.credentials).unwrap(), token);
        let ini = std::fs::read_to_string(&report.ini).unwrap();
        assert!(ini.contains("username=alice\n"));
        assert!(ini.contains("save_login=true\n"));
        assert!(ini.contains("[DISPLAY]\nvsync_mode=Locked\n"));
        // A later token replaces the file (and does not grow it).
        write_login_token(tmp.path(), "bob", [9u8; 32]).unwrap();
        assert_eq!(std::fs::read(&report.credentials).unwrap(), [9u8; 32]);
        assert!(
            std::fs::read_to_string(&report.ini)
                .unwrap()
                .contains("username=bob\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let r = write_login_token(tmp.path(), "alice", [1u8; 32]).unwrap();
        let mode = std::fs::metadata(r.credentials)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn plain_documents_dir_and_custom_names() {
        let tmp = tempfile::tempdir().unwrap();
        let names = LoginTokenFiles {
            credentials_file: "custom.credentials".into(),
            ..Default::default()
        };
        let r = write_login_token_with(tmp.path(), "a", [1u8; 32], &names).unwrap();
        assert_eq!(
            r.credentials,
            tmp.path()
                .join("My Games/Path of Exile 2/custom.credentials")
        );
    }

    #[test]
    fn rejects_bad_input() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(write_login_token(tmp.path(), "", [1u8; 32]).is_err());
        assert!(write_login_token(tmp.path(), "a\nb=c", [1u8; 32]).is_err());
        assert!(write_login_token(tmp.path(), "a", [0u8; 32]).is_err());
    }
}
