//! Standalone login: forcing the client's platform to 0 (see docs/re/standalone-login.md in
//! Poe2ModdingProject).
//!
//! The client picks its login screen and credentials flow from one cached value, computed by
//! `ClientPlatform_Detect` from the executable's file name (`PathOfExileSteam.exe` contains
//! `Steam`, so platform 1). Making that function return 0 selects `LoginScreen.ui` and the
//! email/password packet `0x0003`, and skips the Steam API. The loader (`poe-hook`) applies
//! the patch in `DllMain`; this module holds the addresses and the pure byte logic.
//!
//! All addresses are Ghidra addresses (image base `0x140000000`) of client 0.5.5e.

/// `ClientPlatform_Detect`, the function to patch.
pub const CLIENT_PLATFORM_DETECT: usize = 0x1_4219_6ec0;
/// Guard of the cached platform (thread-safe static): non-zero once the value was computed.
pub const CLIENT_PLATFORM_CACHE_GUARD: usize = 0x1_4471_7114;
/// The cached platform value (`i32`): 0 standalone, 1 Steam.
pub const CLIENT_PLATFORM_CACHE_VALUE: usize = 0x1_4471_7118;

/// The function's first bytes in 0.5.5e (`push rbp; push rbx`), checked before patching.
pub const PLATFORM_DETECT_ORIGINAL: [u8; 3] = [0x40, 0x55, 0x53];
/// `xor eax,eax; ret`: platform 0.
pub const PLATFORM_DETECT_PATCH: [u8; 3] = [0x31, 0xC0, 0xC3];

/// `StandalonePatcher_Run` (Ghidra `FUN_1401162d0`): called once from the start-up function
/// (`FUN_14011b820`, call at `0x14011bf76`); returns `true` to go on. It returns at once for
/// Steam/Epic, skips the patcher when `--success-event <n>` is given (and no
/// `--disable-client-switching`), and otherwise opens the patcher window ("Language", news,
/// progress bar, LAUNCH) and talks to GGG's patch servers.
pub const STANDALONE_PATCHER_RUN: usize = 0x1_4011_62d0;
/// First bytes of `StandalonePatcher_Run` (`mov rax,rsp; ...`), checked before patching.
pub const PATCHER_RUN_ORIGINAL: [u8; 3] = [0x48, 0x8B, 0xC4];
/// `mov al,1; ret`: "go on" without running the patcher.
pub const PATCHER_RUN_PATCH: [u8; 3] = [0xB0, 0x01, 0xC3];

/// The command-line option the patcher passes to the client it starts.
pub const SUCCESS_EVENT_OPTION: &str = "--success-event";
/// Makes the patcher run even with [`SUCCESS_EVENT_OPTION`].
pub const DISABLE_CLIENT_SWITCHING_OPTION: &str = "--disable-client-switching";

/// Outcome of [`patch_prologue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOutcome {
    /// The original bytes were replaced.
    Patched,
    /// The patch was there already (a second call).
    AlreadyPatched,
    /// Neither the original nor the patch: another client build. Nothing was written.
    Mismatch([u8; 3]),
}

/// Replaces the first three bytes of `ClientPlatform_Detect` if (and only if) they are the
/// expected original bytes.
pub fn patch_prologue(code: &mut [u8; 3]) -> PatchOutcome {
    patch_bytes(code, PLATFORM_DETECT_ORIGINAL, PLATFORM_DETECT_PATCH)
}

/// Replaces the first three bytes of `StandalonePatcher_Run` if (and only if) they are the
/// expected original bytes.
pub fn patch_patcher_run(code: &mut [u8; 3]) -> PatchOutcome {
    patch_bytes(code, PATCHER_RUN_ORIGINAL, PATCHER_RUN_PATCH)
}

fn patch_bytes(code: &mut [u8; 3], original: [u8; 3], patch: [u8; 3]) -> PatchOutcome {
    if *code == original {
        *code = patch;
        PatchOutcome::Patched
    } else if *code == patch {
        PatchOutcome::AlreadyPatched
    } else {
        PatchOutcome::Mismatch(*code)
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

    #[test]
    fn patches_only_the_expected_bytes() {
        let mut code = PLATFORM_DETECT_ORIGINAL;
        assert_eq!(patch_prologue(&mut code), PatchOutcome::Patched);
        assert_eq!(code, [0x31, 0xC0, 0xC3]);
        assert_eq!(patch_prologue(&mut code), PatchOutcome::AlreadyPatched);
    }

    #[test]
    fn leaves_other_builds_alone() {
        let mut code = [0x48, 0x89, 0x5c];
        assert_eq!(
            patch_prologue(&mut code),
            PatchOutcome::Mismatch([0x48, 0x89, 0x5c])
        );
        assert_eq!(code, [0x48, 0x89, 0x5c]);
    }

    #[test]
    fn patcher_run_patch_is_checked_too() {
        let mut code = PATCHER_RUN_ORIGINAL;
        assert_eq!(patch_patcher_run(&mut code), PatchOutcome::Patched);
        assert_eq!(code, [0xB0, 0x01, 0xC3]);
        assert_eq!(patch_patcher_run(&mut code), PatchOutcome::AlreadyPatched);
        let mut other = [0x40, 0x55, 0x53];
        assert_eq!(
            patch_patcher_run(&mut other),
            PatchOutcome::Mismatch([0x40, 0x55, 0x53])
        );
        assert_eq!(other, [0x40, 0x55, 0x53]);
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

    #[test]
    fn cache_guard_precedes_value() {
        assert_eq!(CLIENT_PLATFORM_CACHE_VALUE - CLIENT_PLATFORM_CACHE_GUARD, 4);
    }
}
