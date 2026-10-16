//! The app's own widgets (D131, D132): the header with the veil emblem,
//! the step rail, result cards and veil chips. Everything is drawn with the
//! egui painter: no image files and no fonts beyond egui's defaults.

use crate::state::AppState;
use crate::theme::{self, Palette};
use crate::viewmodel::{ResultCard, StepState, WorkflowRail};
use eframe::egui::{
    self, Color32, Pos2, Rect, Response, Sense, Shape, Stroke, StrokeKind, Vec2, pos2, vec2,
};

fn palette(ui: &egui::Ui) -> &'static Palette {
    theme::palette(ui.visuals().dark_mode)
}

/// Diagonal lines `step` apart across `rect`, clipped to it.
fn hatch(painter: &egui::Painter, rect: Rect, step: f32, stroke: Stroke) {
    let p = painter.with_clip_rect(rect.intersect(painter.clip_rect()));
    let h = rect.height();
    let mut x = rect.left() - h;
    while x < rect.right() {
        p.line_segment([pos2(x, rect.bottom()), pos2(x + h, rect.top())], stroke);
        x += step;
    }
}

/// D132: a secret preview (D25: `abcd…(40)` or `…(5)`) on a hatched,
/// rounded chip, in monospace. Only the preview is ever drawn.
pub fn veil_chip(ui: &mut egui::Ui, preview: &str) -> Response {
    let p = palette(ui);
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(preview.to_string(), font, p.chip_text);
    let pad = vec2(8.0, 2.0);
    let (rect, response) = ui.allocate_exact_size(galley.size() + pad * 2.0, Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let r = theme::radius(theme::CHIP_RADIUS);
        painter.rect_filled(rect, r, p.chip);
        // Keep the hatch off the rounded ends.
        let band = rect.shrink2(vec2(f32::from(theme::CHIP_RADIUS) * 0.6, 0.0));
        hatch(painter, band, 5.0, Stroke::new(1.0, p.chip_hatch));
        painter.rect_stroke(rect, r, theme::hairline(p.chip_hatch), StrokeKind::Inside);
        painter.galley(rect.min + pad, galley, p.chip_text);
    }
    let label = format!("secret preview {preview}");
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, &label));
    response
}

/// The veil emblem: an indigo shield with a hatched veil and a teal rod.
fn emblem(ui: &mut egui::Ui) {
    let p = palette(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(24.0, 28.0), Sense::hover());
    let at = |x: f32, y: f32| rect.min + vec2(x, y);
    let shield: Vec<Pos2> = [
        (1.0, 4.0),
        (12.0, 1.0),
        (23.0, 4.0),
        (23.0, 14.0),
        (19.0, 21.0),
        (12.0, 27.0),
        (5.0, 21.0),
        (1.0, 14.0),
    ]
    .into_iter()
    .map(|(x, y)| at(x, y))
    .collect();
    let painter = ui.painter();
    painter.add(Shape::convex_polygon(shield, p.primary, Stroke::NONE));
    let veil = Rect::from_min_max(at(5.0, 8.0), at(19.0, 18.0));
    hatch(painter, veil, 4.0, Stroke::new(1.5, p.on_primary));
    painter.line_segment([at(4.0, 7.0), at(20.0, 7.0)], Stroke::new(2.0, p.accent));
}

/// The header: emblem and wordmark.
pub fn header(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        emblem(ui);
        let p = palette(ui);
        ui.label(
            egui::RichText::new("Veilcode")
                .size(22.0)
                .strong()
                .color(p.primary),
        );
        ui.label("Mask secrets in a copy of a code folder before sharing it.");
    });
}

/// The circle of one rail step: the number, or a drawn check mark.
fn step_mark(ui: &mut egui::Ui, number: usize, state: StepState) -> Response {
    let p = palette(ui);
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::click());
    let (c, r) = (rect.center(), 10.0);
    let painter = ui.painter();
    match state {
        StepState::Done => {
            painter.circle_filled(c, r, p.accent);
            let stroke = Stroke::new(2.0, p.on_accent);
            painter.line_segment([c + vec2(-5.0, 0.0), c + vec2(-1.5, 3.5)], stroke);
            painter.line_segment([c + vec2(-1.5, 3.5), c + vec2(5.0, -4.0)], stroke);
        }
        StepState::Current => {
            painter.circle_filled(c, r, p.primary);
            number_text(painter, c, number, p.on_primary);
        }
        StepState::Available => {
            painter.circle_stroke(c, r - 0.5, Stroke::new(1.5, p.primary));
            number_text(painter, c, number, p.text);
        }
        StepState::Locked => {
            painter.circle_stroke(c, r - 0.5, Stroke::new(1.0, p.weak));
            number_text(painter, c, number, p.weak);
        }
    }
    response
}

fn number_text(painter: &egui::Painter, c: Pos2, n: usize, color: Color32) {
    let font = egui::FontId::proportional(13.0);
    painter.text(c, egui::Align2::CENTER_CENTER, n.to_string(), font, color);
}

/// A small painted "next" chevron between rail steps.
fn chevron(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(10.0, 22.0), Sense::hover());
    let (c, s) = (rect.center(), Stroke::new(1.5, color));
    ui.painter()
        .line_segment([c + vec2(-2.0, -4.0), c + vec2(2.0, 0.0)], s);
    ui.painter()
        .line_segment([c + vec2(2.0, 0.0), c + vec2(-2.0, 4.0)], s);
}

fn state_word(s: StepState) -> &'static str {
    match s {
        StepState::Done => "done",
        StepState::Current => "current",
        StepState::Available => "available",
        StepState::Locked => "locked",
    }
}

/// D131: the step rail. A click on a step opens its screen when allowed.
pub fn rail(ui: &mut egui::Ui, state: &mut AppState, rail: &WorkflowRail) {
    let p = palette(ui);
    ui.horizontal(|ui| {
        for (i, s) in rail.steps.iter().enumerate() {
            if i > 0 {
                chevron(ui, p.weak);
            }
            let color = match s.state {
                StepState::Done => p.accent,
                StepState::Current => p.primary,
                StepState::Available => p.text,
                StepState::Locked => p.weak,
            };
            let mark = step_mark(ui, s.number, s.state);
            let mut text = egui::RichText::new(s.step.label()).color(color);
            if s.state == StepState::Current {
                text = text.strong();
            }
            let label = ui.add(egui::Label::new(text).sense(Sense::click()));
            let name = format!(
                "Step {} {}: {}",
                s.number,
                s.step.label(),
                state_word(s.state)
            );
            mark.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &name));
            if mark.clicked() || label.clicked() {
                state.go_to(s.step);
            }
        }
    });
}

/// D131: a result or error card, with its "Next: <step>" button.
pub fn card(ui: &mut egui::Ui, state: &mut AppState, card: &ResultCard) {
    let p = palette(ui);
    let (fill, text) = if card.error {
        (p.error_card, p.error_card_text)
    } else {
        (p.card, p.text)
    };
    let stroke = if card.error { p.error } else { p.card_stroke };
    egui::Frame::new()
        .fill(fill)
        .stroke(theme::hairline(stroke))
        .corner_radius(theme::radius(theme::CARD_RADIUS))
        .inner_margin(egui::Margin::same(theme::CARD_MARGIN))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(egui::RichText::new(&card.title).strong().color(text));
            if let Some((label, folder)) = &card.folder {
                ui.label(egui::RichText::new(format!("{label}: {folder}")).color(text));
            }
            for line in &card.lines {
                ui.label(egui::RichText::new(line).color(text));
            }
            if let Some(next) = card.next
                && ui.button(format!("Next: {}", next.label())).clicked()
            {
                state.go_to(next);
            }
        });
}
