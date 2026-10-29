//! Recognising the game's main window by class name (host-testable helpers).

/// Window class the game registers for its main window (`RegisterClassW` in
/// `FUN_141050c30`, string `POEWindowClass`). The standalone patcher uses `MainWindowClass`,
/// message boxes use the dialog class `#32770`.
pub const GAME_WINDOW_CLASS: &str = "POEWindowClass";

/// Longest class name examined (`GAME_WINDOW_CLASS` plus room to see a mismatch).
pub const MAX_CLASS_UNITS: usize = 64;

/// True if `name` (UTF-16, no terminator) is the game's main window class.
pub fn is_game_window_class(name: &[u16]) -> bool {
    name.len() == GAME_WINDOW_CLASS.len()
        && GAME_WINDOW_CLASS.encode_utf16().eq(name.iter().copied())
}

/// Reads the NUL-terminated UTF-16 class name at `ptr` (at most [`MAX_CLASS_UNITS`] units) and
/// tells whether it is the game's class. A null pointer or an atom (`MAKEINTATOM`, below
/// `0x10000`) is not.
///
/// # Safety
/// `ptr` must be null, an atom, or point to a NUL-terminated UTF-16 string.
pub unsafe fn is_game_window_class_ptr(ptr: *const u16) -> bool {
    if (ptr as usize) < 0x1_0000 {
        return false;
    }
    let mut buf = [0u16; MAX_CLASS_UNITS];
    let mut len = 0;
    while len < MAX_CLASS_UNITS {
        let unit = unsafe { ptr.add(len).read() };
        if unit == 0 {
            return is_game_window_class(&buf[..len]);
        }
        buf[len] = unit;
        len += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn matches_only_the_game_class() {
        assert!(is_game_window_class(&wide("POEWindowClass")[..14]));
        assert!(!is_game_window_class(&wide("MainWindowClass")[..15]));
        assert!(!is_game_window_class(&wide("#32770")[..6]));
        assert!(!is_game_window_class(&[]));
    }

    #[test]
    fn reads_pointers_safely() {
        unsafe {
            assert!(is_game_window_class_ptr(wide("POEWindowClass").as_ptr()));
            assert!(!is_game_window_class_ptr(wide("POEWindowClassX").as_ptr()));
            assert!(!is_game_window_class_ptr(wide("#32770").as_ptr()));
            assert!(!is_game_window_class_ptr(std::ptr::null()));
            assert!(!is_game_window_class_ptr(0x8002 as *const u16));
            let long = wide(&"A".repeat(200));
            assert!(!is_game_window_class_ptr(long.as_ptr()));
        }
    }
}
