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
    if *code == PLATFORM_DETECT_ORIGINAL {
        *code = PLATFORM_DETECT_PATCH;
        PatchOutcome::Patched
    } else if *code == PLATFORM_DETECT_PATCH {
        PatchOutcome::AlreadyPatched
    } else {
        PatchOutcome::Mismatch(*code)
    }
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
    fn cache_guard_precedes_value() {
        assert_eq!(CLIENT_PLATFORM_CACHE_VALUE - CLIENT_PLATFORM_CACHE_GUARD, 4);
    }
}
