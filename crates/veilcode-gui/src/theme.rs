//! One palette for light and dark (D132), applied to egui's `Visuals` and
//! `Style` at startup. egui keeps a style per theme and switches between
//! them when the system or egui theme changes, so both are set once.
//! Default fonts only (D98). Every text/background pair is checked against
//! WCAG 2.x contrast 4.5:1 in G13 (D133).

use eframe::egui::{self, Color32, CornerRadius, Stroke, Theme, Visuals};

/// Corner radius of buttons and fields.
pub const RADIUS: u8 = 6;
/// Corner radius of result cards.
pub const CARD_RADIUS: u8 = 8;
/// Corner radius of veil chips.
pub const CHIP_RADIUS: u8 = 9;
/// Inner margin of result cards.
pub const CARD_MARGIN: i8 = 12;
/// Space between items, and inside buttons.
pub const ITEM_SPACING: [f32; 2] = [8.0, 6.0];
pub const BUTTON_PADDING: [f32; 2] = [10.0, 5.0];

/// Every colour the app uses, for one theme.
pub struct Palette {
    pub dark: bool,
    pub panel: Color32,
    pub window: Color32,
    pub faint: Color32,
    pub code: Color32,
    pub field: Color32,
    pub text: Color32,
    pub weak: Color32,
    pub separator: Color32,
    /// Outline of fields and buttons.
    pub border: Color32,
    pub button: Color32,
    pub button_text: Color32,
    pub hovered: Color32,
    pub hovered_text: Color32,
    pub active: Color32,
    pub active_text: Color32,
    pub selection: Color32,
    pub selection_text: Color32,
    pub error: Color32,
    pub warn: Color32,
    /// Indigo: wordmark, emblem, the current rail step.
    pub primary: Color32,
    pub on_primary: Color32,
    /// Teal: done rail steps, the emblem's rod.
    pub accent: Color32,
    pub on_accent: Color32,
    pub card: Color32,
    pub card_stroke: Color32,
    pub error_card: Color32,
    pub error_card_text: Color32,
    pub chip: Color32,
    pub chip_hatch: Color32,
    pub chip_text: Color32,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

pub const LIGHT: Palette = Palette {
    dark: false,
    panel: rgb(0xF7F7FA),
    window: rgb(0xFBFBFD),
    faint: rgb(0xEFEFF5),
    code: rgb(0xE9E9F0),
    field: rgb(0xFFFFFF),
    text: rgb(0x1F2330),
    weak: rgb(0x545B6B),
    separator: rgb(0xC9CBD6),
    border: rgb(0x9EA3B5),
    button: rgb(0xE4E5EE),
    button_text: rgb(0x1F2330),
    hovered: rgb(0xD6D8E6),
    hovered_text: rgb(0x11131A),
    active: rgb(0xC4C7DB),
    active_text: rgb(0x000000),
    selection: rgb(0x3730A3),
    selection_text: rgb(0xFFFFFF),
    error: rgb(0xB3261E),
    warn: rgb(0x8A4B00),
    primary: rgb(0x3730A3),
    on_primary: rgb(0xFFFFFF),
    accent: rgb(0x0F766E),
    on_accent: rgb(0xFFFFFF),
    card: rgb(0xFFFFFF),
    card_stroke: rgb(0xD5D7E0),
    error_card: rgb(0xFDECEC),
    error_card_text: rgb(0x8C1D18),
    chip: rgb(0xE9E7FB),
    chip_hatch: rgb(0xCFCAF3),
    chip_text: rgb(0x2A2370),
};

pub const DARK: Palette = Palette {
    dark: true,
    panel: rgb(0x17181F),
    window: rgb(0x1C1D27),
    faint: rgb(0x1E1F28),
    code: rgb(0x2A2C38),
    field: rgb(0x0E0F14),
    text: rgb(0xE6E7EE),
    weak: rgb(0xA3A8B8),
    separator: rgb(0x3A3C4C),
    border: rgb(0x4A4D60),
    button: rgb(0x2E3040),
    button_text: rgb(0xE6E7EE),
    hovered: rgb(0x3A3D52),
    hovered_text: rgb(0xFFFFFF),
    active: rgb(0x4A4E68),
    active_text: rgb(0xFFFFFF),
    selection: rgb(0xA5B4FC),
    selection_text: rgb(0x1E1B4B),
    error: rgb(0xFFB4AB),
    warn: rgb(0xFFB86B),
    primary: rgb(0xA5B4FC),
    on_primary: rgb(0x1E1B4B),
    accent: rgb(0x2DD4BF),
    on_accent: rgb(0x062925),
    card: rgb(0x20222D),
    card_stroke: rgb(0x3A3C4C),
    error_card: rgb(0x3B1A1D),
    error_card_text: rgb(0xFFB4AB),
    chip: rgb(0x2B2856),
    chip_hatch: rgb(0x3D3973),
    chip_text: rgb(0xE0DDFF),
};

/// The palette of the theme egui is drawing (`ui.visuals().dark_mode`).
pub fn palette(dark: bool) -> &'static Palette {
    if dark { &DARK } else { &LIGHT }
}

/// egui's visuals for `p`.
pub fn visuals(p: &Palette) -> Visuals {
    let mut v = if p.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.override_text_color = None;
    v.weak_text_color = Some(p.weak);
    v.panel_fill = p.panel;
    v.window_fill = p.window;
    v.window_stroke = hairline(p.separator);
    v.faint_bg_color = p.faint;
    v.code_bg_color = p.code;
    v.extreme_bg_color = p.field;
    v.text_edit_bg_color = Some(p.field);
    v.error_fg_color = p.error;
    v.warn_fg_color = p.warn;
    v.selection.bg_fill = p.selection;
    v.selection.stroke = hairline(p.selection_text);
    v.window_corner_radius = radius(CARD_RADIUS);
    v.menu_corner_radius = radius(RADIUS);
    widgets(&mut v.widgets, p);
    v
}

/// Widget fills and text colours; strokes stay egui's widths.
fn widgets(w: &mut egui::style::Widgets, p: &Palette) {
    let set = |wv: &mut egui::style::WidgetVisuals, fill: Color32, text: Color32| {
        wv.weak_bg_fill = fill;
        wv.bg_fill = fill;
        wv.fg_stroke.color = text;
        wv.corner_radius = radius(RADIUS);
    };
    set(&mut w.noninteractive, p.panel, p.text);
    w.noninteractive.bg_stroke = hairline(p.separator);
    set(&mut w.inactive, p.button, p.button_text);
    w.inactive.bg_stroke = hairline(p.border);
    set(&mut w.hovered, p.hovered, p.hovered_text);
    set(&mut w.active, p.active, p.active_text);
    set(&mut w.open, p.button, p.button_text);
    w.hovered.bg_stroke.color = p.primary;
    w.active.bg_stroke.color = p.primary;
}

/// Sets the light and dark styles once; egui picks the one matching the
/// system (or egui) theme preference, which is left unchanged.
pub fn apply(ctx: &egui::Context) {
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT));
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK));
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = ITEM_SPACING.into();
        s.spacing.button_padding = BUTTON_PADDING.into();
    });
}

/// D133: egui-file-dialog 0.15.0 draws its path and search fields on
/// `Frame::dark_canvas` (a fixed near-black fill, not a `Visuals` colour)
/// with the inactive widget text colour. That text is only readable with
/// the dark style, so the dialog is drawn with it in both themes.
pub fn with_dialog_style(ctx: &egui::Context, show: impl FnOnce(&egui::Context)) {
    if ctx.theme() == Theme::Dark {
        show(ctx);
        return;
    }
    let light = ctx.style_of(Theme::Light);
    ctx.set_style_of(Theme::Light, ctx.style_of(Theme::Dark));
    show(ctx);
    ctx.set_style_of(Theme::Light, light);
}

/// A thin stroke in `color`.
pub fn hairline(color: Color32) -> Stroke {
    Stroke::new(1.0, color)
}

/// `r` as an egui corner radius.
pub fn radius(r: u8) -> CornerRadius {
    CornerRadius::same(r)
}

#[cfg(test)]
mod tests;
