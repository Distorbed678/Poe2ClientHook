//! The overlay's look: the "Ash & Blood" colours of the launcher and the web admin (their
//! `tokens.css`), as far as Dear ImGui goes. Text stays in the monospaced font; headings use
//! Cinzel (see [`heading`]).

use imgui::{FontId, StyleColor, Ui};

/// Converts `#rrggbb` and an alpha to ImGui's linear RGBA floats.
const fn rgb(hex: u32, a: f32) -> [f32; 4] {
    [
        ((hex >> 16) & 0xff) as f32 / 255.0,
        ((hex >> 8) & 0xff) as f32 / 255.0,
        (hex & 0xff) as f32 / 255.0,
        a,
    ]
}

// The tokens (tokens.css, dark theme).
pub const BG: [f32; 4] = rgb(0x0d0808, 0.96);
pub const SURFACE: [f32; 4] = rgb(0x170f0e, 1.0);
pub const SURFACE_2: [f32; 4] = rgb(0x221514, 1.0);
pub const SURFACE_3: [f32; 4] = rgb(0x2c1c1a, 1.0);
pub const LINE: [f32; 4] = rgb(0x3d2522, 1.0);
pub const TEXT: [f32; 4] = rgb(0xeedcd0, 1.0);
pub const MUTED: [f32; 4] = rgb(0xa88f85, 1.0);
pub const FAINT: [f32; 4] = rgb(0x6f5a54, 1.0);
pub const GOLD: [f32; 4] = rgb(0xd1a14e, 1.0);
pub const GOLD_2: [f32; 4] = rgb(0xf0c879, 1.0);
pub const CRIMSON: [f32; 4] = rgb(0x8e2a22, 1.0);
pub const WARN: [f32; 4] = rgb(0xe0a63e, 1.0);
pub const DANGER: [f32; 4] = rgb(0xe0604a, 1.0);

pub const fn with_alpha(c: [f32; 4], a: f32) -> [f32; 4] {
    [c[0], c[1], c[2], a]
}

/// Applies the colours and the shapes (small radii, thin borders) to the context's style.
/// Call it before `scale_all_sizes`, so the sizes scale with the overlay.
pub fn apply(style: &mut imgui::Style) {
    use StyleColor as C;
    let colors = [
        (C::Text, TEXT),
        (C::TextDisabled, FAINT),
        (C::WindowBg, BG),
        (C::ChildBg, with_alpha(SURFACE, 0.0)),
        (C::PopupBg, with_alpha(SURFACE_2, 0.98)),
        (C::Border, LINE),
        (C::BorderShadow, [0.0; 4]),
        (C::FrameBg, SURFACE_2),
        (C::FrameBgHovered, SURFACE_3),
        (C::FrameBgActive, rgb(0x36221f, 1.0)),
        (C::TitleBg, SURFACE_2),
        (C::TitleBgActive, SURFACE_2),
        (C::TitleBgCollapsed, with_alpha(SURFACE_2, 0.8)),
        (C::MenuBarBg, SURFACE),
        (C::ScrollbarBg, [0.0; 4]),
        (C::ScrollbarGrab, SURFACE_3),
        (C::ScrollbarGrabHovered, FAINT),
        (C::ScrollbarGrabActive, GOLD),
        (C::CheckMark, GOLD_2),
        (C::SliderGrab, GOLD),
        (C::SliderGrabActive, GOLD_2),
        (C::Button, SURFACE_2),
        (C::ButtonHovered, SURFACE_3),
        (C::ButtonActive, CRIMSON),
        (C::Header, with_alpha(CRIMSON, 0.35)),
        (C::HeaderHovered, with_alpha(CRIMSON, 0.22)),
        (C::HeaderActive, with_alpha(CRIMSON, 0.5)),
        (C::Separator, LINE),
        (C::SeparatorHovered, GOLD),
        (C::SeparatorActive, GOLD_2),
        (C::ResizeGrip, with_alpha(GOLD, 0.2)),
        (C::ResizeGripHovered, with_alpha(GOLD, 0.6)),
        (C::ResizeGripActive, GOLD),
        (C::Tab, SURFACE),
        (C::TabHovered, SURFACE_3),
        (C::TabSelected, with_alpha(CRIMSON, 0.45)),
        (C::TabSelectedOverline, GOLD),
        (C::TabDimmed, SURFACE),
        (C::TabDimmedSelected, SURFACE_2),
        (C::PlotLines, GOLD),
        (C::PlotLinesHovered, GOLD_2),
        (C::PlotHistogram, GOLD),
        (C::PlotHistogramHovered, GOLD_2),
        (C::TableHeaderBg, SURFACE_2),
        (C::TableBorderStrong, LINE),
        (C::TableBorderLight, rgb(0x2a1a18, 1.0)),
        (C::TableRowBg, [0.0; 4]),
        (C::TableRowBgAlt, with_alpha(SURFACE_2, 0.45)),
        (C::TextSelectedBg, with_alpha(GOLD, 0.3)),
        (C::TextLink, GOLD_2),
        (C::NavCursor, GOLD),
        (C::ModalWindowDimBg, [0.02, 0.01, 0.01, 0.6]),
    ];
    for (c, v) in colors {
        style.set_color(c, v);
    }
    style.set_window_rounding(6.0);
    style.set_child_rounding(4.0);
    style.set_frame_rounding(3.0);
    style.set_popup_rounding(4.0);
    style.set_window_border_size(1.0);
    style.set_child_border_size(1.0);
    style.set_popup_border_size(1.0);
    // Inputs and checkboxes get an outline, so they stand out from the window.
    style.set_frame_border_size(1.0);
    style.set_frame_padding([8.0, 4.0]);
    style.set_window_padding([10.0, 10.0]);
}

/// Draws `text` as a heading: Cinzel in gold when the font loaded, else gold text.
pub fn heading(ui: &Ui, font: Option<FontId>, text: &str) {
    let _f = font.map(|id| ui.push_font(id));
    ui.text_colored(GOLD_2, text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_colours_match_the_tokens() {
        assert_eq!(
            rgb(0xd1a14e, 1.0),
            [209.0 / 255.0, 161.0 / 255.0, 78.0 / 255.0, 1.0]
        );
        assert_eq!(with_alpha(GOLD, 0.5)[3], 0.5);
    }
}
