//! G13: WCAG 2.x contrast of every text/background pair (D133).

use super::*;

/// sRGB channel (0-255) to linear light, WCAG 2.x relative-luminance note.
fn linear(c: u8) -> f64 {
    let c = f64::from(c) / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(c: Color32) -> f64 {
    0.2126 * linear(c.r()) + 0.7152 * linear(c.g()) + 0.0722 * linear(c.b())
}

/// WCAG contrast ratio (L1 + 0.05) / (L2 + 0.05), L1 the lighter.
fn contrast(a: Color32, b: Color32) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// The premultiplied colour `fg` composited over the opaque `bg`.
fn over(fg: Color32, bg: Color32) -> Color32 {
    let keep = 255 - u16::from(fg.a());
    let mix = |f: u8, b: u8| (u16::from(f) + (u16::from(b) * keep + 127) / 255) as u8;
    Color32::from_rgb(
        mix(fg.r(), bg.r()),
        mix(fg.g(), bg.g()),
        mix(fg.b(), bg.b()),
    )
}

type Pair = (&'static str, Color32, Color32);

/// The pairs egui draws from `v`, and the app's own (cards, rail, chips).
fn pairs(v: &Visuals, p: &Palette) -> Vec<Pair> {
    let w = &v.widgets;
    let panel = v.panel_fill;
    vec![
        ("body text on panel", v.text_color(), panel),
        ("body text on window", v.text_color(), v.window_fill),
        ("body text on faint rows", v.text_color(), v.faint_bg_color),
        ("body text on code", v.text_color(), v.code_bg_color),
        ("weak text on panel", v.weak_text_color(), panel),
        ("weak text on window", v.weak_text_color(), v.window_fill),
        ("strong text on panel", v.strong_text_color(), panel),
        (
            "text-edit text on field",
            w.inactive.text_color(),
            v.text_edit_bg_color(),
        ),
        (
            "text-edit hint on field",
            v.weak_text_color(),
            v.text_edit_bg_color(),
        ),
        (
            "selected text",
            v.selection.stroke.color,
            v.selection.bg_fill,
        ),
        (
            "button text",
            w.inactive.text_color(),
            w.inactive.weak_bg_fill,
        ),
        ("checkbox label on panel", w.inactive.text_color(), panel),
        (
            "hovered button text",
            w.hovered.text_color(),
            w.hovered.weak_bg_fill,
        ),
        ("hovered label on panel", w.hovered.text_color(), panel),
        (
            "pressed button text",
            w.active.text_color(),
            w.active.weak_bg_fill,
        ),
        ("pressed label on panel", w.active.text_color(), panel),
        ("open menu text", w.open.text_color(), w.open.weak_bg_fill),
        ("error text on panel", v.error_fg_color, panel),
        ("warning text on panel", v.warn_fg_color, panel),
        ("result-card text", p.text, p.card),
        ("result-card weak text", p.weak, p.card),
        ("result-card strong text", v.strong_text_color(), p.card),
        ("error-card text", p.error_card_text, p.error_card),
        ("wordmark on panel", p.primary, panel),
        ("rail current number", p.on_primary, p.primary),
        ("rail current label", p.primary, panel),
        ("rail done mark", p.on_accent, p.accent),
        ("rail done label", p.accent, panel),
        ("rail available label", p.text, panel),
        ("rail locked label", p.weak, panel),
        ("veil-chip text on chip", p.chip_text, p.chip),
        ("veil-chip text on hatch", p.chip_text, p.chip_hatch),
    ]
}

/// What egui-file-dialog 0.15.0 draws, with the style the app gives it:
/// path and search fields on `Frame::dark_canvas` (black, alpha 250, over
/// the window fill) in the inactive text colour, and the picked file name
/// in the selection fill on the window.
fn dialog_pairs(v: &Visuals) -> Vec<Pair> {
    let canvas = over(Color32::from_black_alpha(250), v.window_fill);
    let text = v.widgets.inactive.text_color();
    vec![
        ("file dialog path field", text, canvas),
        ("file dialog search field", text, canvas),
        (
            "file dialog picked name",
            v.selection.bg_fill,
            v.window_fill,
        ),
        ("file dialog name field", text, v.text_edit_bg_color()),
    ]
}

/// The style egui-file-dialog is drawn with in `theme` (`with_dialog_style`).
fn dialog_visuals(theme: Theme) -> Visuals {
    let ctx = egui::Context::default();
    apply(&ctx);
    ctx.set_theme(theme);
    let mut seen = None;
    with_dialog_style(&ctx, |c| seen = Some(c.global_style().visuals.clone()));
    assert_eq!(ctx.theme(), theme, "theme preference unchanged");
    seen.expect("dialog drawn")
}

#[test]
fn g13_contrast_formula_matches_wcag() {
    let ratio = contrast(Color32::BLACK, Color32::WHITE);
    assert!((ratio - 21.0).abs() < 1e-9, "{ratio}");
    assert!((contrast(rgb(0x777777), rgb(0x777777)) - 1.0).abs() < 1e-12);
    // Grey 118 on white is the usual 4.54:1 example.
    let grey = contrast(rgb(0x767676), Color32::WHITE);
    assert!((grey - 4.54).abs() < 0.01, "{grey}");
    assert_eq!(
        over(Color32::from_black_alpha(255), Color32::WHITE),
        Color32::BLACK
    );
}

#[test]
fn g13_every_theme_text_pair_has_contrast_at_least_4_5() {
    let mut failing = Vec::new();
    for (name, theme, p) in [
        ("light", Theme::Light, &LIGHT),
        ("dark", Theme::Dark, &DARK),
    ] {
        let v = visuals(p);
        let all = pairs(&v, p)
            .into_iter()
            .chain(dialog_pairs(&dialog_visuals(theme)));
        for (pair, fg, bg) in all {
            assert!(
                fg.is_opaque() && bg.is_opaque(),
                "{name}: {pair} is translucent"
            );
            let ratio = contrast(fg, bg);
            // The table for the PR body (`-- --nocapture`).
            println!("{name} | {pair} | {ratio:.2}");
            if ratio < 4.5 {
                failing.push(format!("{name}: {pair} = {ratio:.2}"));
            }
        }
    }
    assert!(failing.is_empty(), "below 4.5:1: {failing:#?}");
}

#[test]
fn g13_apply_sets_both_themes_and_keeps_the_preference() {
    let ctx = egui::Context::default();
    let before = ctx.options(|o| o.theme_preference);
    apply(&ctx);
    assert_eq!(ctx.options(|o| o.theme_preference), before);
    assert_eq!(ctx.style_of(Theme::Light).visuals, visuals(&LIGHT));
    assert_eq!(ctx.style_of(Theme::Dark).visuals, visuals(&DARK));
    // The dialog's dark style is temporary: the light style comes back.
    ctx.set_theme(Theme::Light);
    assert!(dialog_visuals(Theme::Light).dark_mode);
    with_dialog_style(&ctx, |_| {});
    assert_eq!(ctx.style_of(Theme::Light).visuals, visuals(&LIGHT));
}
