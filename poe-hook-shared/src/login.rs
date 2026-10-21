//! Standalone login: forcing the client's platform to 0 (see docs/re/standalone-login.md in
//! Poe2ModdingProject).
//!
//! The client picks its login screen and credentials flow from one cached value, computed by
//! `ClientPlatform_Detect` from the executable's file name (`PathOfExileSteam.exe` contains
//! `Steam`, so platform 1). Making that function return 0 selects `LoginScreen.ui` and the
//! email/password packet `0x0003`, and skips the Steam API. The loader (`poe-hook`) applies
//! the patch in `DllMain`; this module holds the addresses and the pure byte logic.
//!
//! Where the functions are, which bytes they must hold and what is written over them is in the
//! signature table (`signatures/<version>.toml`: `client_platform_detect`,
//! `standalone_patcher_run`, `platform_cache_guard`, `platform_cache_value`); see
//! [`crate::sigs`]. This module only holds the pure byte logic.
//!
//! - `ClientPlatform_Detect`: patched to `xor eax,eax; ret` (platform 0).
//! - `StandalonePatcher_Run` (called once from the start-up function; returns `true` to go
//!   on): patched to `mov al,1; ret`. It returns at once for Steam/Epic, skips the patcher
//!   when `--success-event <n>` is given (and no `--disable-client-switching`), and otherwise
//!   opens the patcher window and talks to GGG's patch servers.
//! - The cached platform (`i32`: 0 standalone, 1 Steam) has a thread-safe-static guard
//!   (non-zero once the value was computed).

/// The command-line option the patcher passes to the client it starts.
pub const SUCCESS_EVENT_OPTION: &str = "--success-event";
/// Makes the patcher run even with [`SUCCESS_EVENT_OPTION`].
pub const DISABLE_CLIENT_SWITCHING_OPTION: &str = "--disable-client-switching";

/// Outcome of [`patch_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOutcome {
    /// The original bytes were replaced.
    Patched,
    /// The patch was there already (a second call).
    AlreadyPatched,
    /// Neither the original nor the patch: another client build. Nothing was written.
    Mismatch(Vec<u8>),
}

/// Replaces `code` with `patch` if (and only if) it holds exactly the `original` bytes.
/// All three slices have the same length.
pub fn patch_bytes(code: &mut [u8], original: &[u8], patch: &[u8]) -> PatchOutcome {
    if code.len() != original.len() || original.len() != patch.len() {
        return PatchOutcome::Mismatch(code.to_vec());
    }
    if code == original {
        code.copy_from_slice(patch);
        PatchOutcome::Patched
    } else if code == patch {
        PatchOutcome::AlreadyPatched
    } else {
        PatchOutcome::Mismatch(code.to_vec())
    }
}

/// Whether `cmdline` (the process command line) has `option` as an argument, alone or as
/// `option=value`. Case-sensitive, like the client's parser.
pub fn has_option(cmdline: &str, option: &str) -> bool {
    cmdline.split_whitespace().any(|tok| {
        let tok = tok.trim_matches('"');
        tok == option || tok.strip_prefix(option).is_some_and(|r| r.starts_with('='))
    })
}

/// Whether the client's own start-up check would run the standalone patcher for `cmdline`:
/// unless `--success-event` is given without `--disable-client-switching`.
pub fn patcher_would_run(cmdline: &str) -> bool {
    !has_option(cmdline, SUCCESS_EVENT_OPTION)
        || has_option(cmdline, DISABLE_CLIENT_SWITCHING_OPTION)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DETECT: [u8; 3] = [0x40, 0x55, 0x53];
    const DETECT_PATCH: [u8; 3] = [0x31, 0xC0, 0xC3];

    #[test]
    fn patches_only_the_expected_bytes() {
        let mut code = DETECT;
        assert_eq!(
            patch_bytes(&mut code, &DETECT, &DETECT_PATCH),
            PatchOutcome::Patched
        );
        assert_eq!(code, DETECT_PATCH);
        assert_eq!(
            patch_bytes(&mut code, &DETECT, &DETECT_PATCH),
            PatchOutcome::AlreadyPatched
        );
    }

    #[test]
    fn leaves_other_builds_alone() {
        let mut code = [0x48, 0x89, 0x5c];
        assert_eq!(
            patch_bytes(&mut code, &DETECT, &DETECT_PATCH),
            PatchOutcome::Mismatch(vec![0x48, 0x89, 0x5c])
        );
        assert_eq!(code, [0x48, 0x89, 0x5c]);
    }

    #[test]
    fn lengths_must_agree() {
        let mut code = [0x40, 0x55, 0x53, 0x56];
        assert!(matches!(
            patch_bytes(&mut code, &DETECT, &DETECT_PATCH),
            PatchOutcome::Mismatch(_)
        ));
        assert_eq!(code, [0x40, 0x55, 0x53, 0x56]);
    }

    #[test]
    fn patcher_decision_follows_the_client() {
        let exe = r#""Z:\game\PathOfExileSteam.exe""#;
        assert!(patcher_would_run(exe));
        assert!(!patcher_would_run(&format!("{exe} --success-event 0")));
        assert!(!patcher_would_run(&format!(
            "{exe} --success-event=0 --nologo"
        )));
        assert!(patcher_would_run(&format!(
            "{exe} --success-event 0 --disable-client-switching"
        )));
        // Substring of another option is not the option.
        assert!(patcher_would_run(&format!("{exe} --success-events 1")));
    }
}
