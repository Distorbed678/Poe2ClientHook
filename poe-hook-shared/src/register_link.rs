//! The login screen's "Create account" button: the client opens the official site's account
//! page (`https://<host>/account/create?theme=poe2`, built from the path string in the exe's
//! `.rdata` and a host) with `ShellExecuteW`. With a private server the loader opens the
//! server's own register page instead (`register_url`, written by the launcher at Play). Pure
//! decision here, the hook in `poe-hook/src/register_link.rs`.

/// The path the client puts after the official host for the account page.
pub const ACCOUNT_CREATE_PATH: &str = "/account/create";

/// The URL to open instead of `target`, or `None` to leave the call alone: only for the
/// account page, only with a configured `http(s)://` register URL, and never while the
/// read-only latch is on (official play: nothing is altered).
pub fn redirect(target: &str, register_url: Option<&str>, read_only: bool) -> Option<String> {
    if read_only {
        return None;
    }
    let url = register_url?.trim();
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://"))
        || url.chars().any(char::is_control)
    {
        return None;
    }
    target.contains(ACCOUNT_CREATE_PATH).then(|| url.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICIAL: &str = "https://www.pathofexile.com/account/create?theme=poe2";
    const MINE: &str = "http://192.168.1.20:8080/#/register";

    #[test]
    fn only_the_account_page_goes_to_the_private_server() {
        assert_eq!(redirect(OFFICIAL, Some(MINE), false).as_deref(), Some(MINE));
        assert_eq!(
            redirect("https://www.pathofexile.com/forum", Some(MINE), false),
            None
        );
        assert_eq!(redirect(OFFICIAL, None, false), None, "not configured");
        assert_eq!(
            redirect(OFFICIAL, Some(MINE), true),
            None,
            "read-only: nothing is altered"
        );
        assert_eq!(
            redirect(OFFICIAL, Some("file:///etc/passwd"), false),
            None,
            "web pages only"
        );
        assert_eq!(
            redirect(OFFICIAL, Some("http://x/\n"), false).as_deref(),
            Some("http://x/"),
            "trimmed"
        );
        assert_eq!(redirect(OFFICIAL, Some("http://a\u{7}b"), false), None);
    }
}
