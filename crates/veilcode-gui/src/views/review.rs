//! The mandatory review before every mask (D80).

use super::scan::profile_row;
use super::{chrome, finding_text};
use crate::app::Forms;
use crate::state::{AppState, Screen};
use crate::viewmodel::FindingRow;
use eframe::egui;
use veilcode_core::Scope;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Review findings");
    let Some(view) = state.review() else {
        ui.label("Scan a folder first.");
        return;
    };
    ui.label(
        "Ticked findings are masked. Untick false positives, or remember them in the profile.",
    );
    for group in &view.groups {
        let title = format!("{} ({})", group.label, group.rows.len());
        egui::CollapsingHeader::new(title)
            .id_salt(&group.label)
            .default_open(true)
            .show(ui, |ui| {
                for row in &group.rows {
                    finding_row(ui, state, forms, row);
                }
            });
    }
    let title = format!("Ignored (false positives) ({})", view.ignored.len());
    egui::CollapsingHeader::new(title)
        .id_salt("ignored")
        .default_open(false)
        .show(ui, |ui| {
            for row in &view.ignored {
                ui.horizontal(|ui| {
                    ui.label(finding_text(row));
                    chrome::veil_chip(ui, &row.preview);
                    if ui.button("Unignore").clicked() {
                        let r = state.unignore(&row.id);
                        state.report(r);
                    }
                });
            }
        });
    ui.separator();
    add_key(ui, state, forms);
    profile_row(ui, state, forms);
    ui.separator();
    if ui
        .add_enabled(!state.is_busy(), egui::Button::new(&view.confirm_label))
        .clicked()
    {
        match state.confirm_review() {
            Ok(_) => state.screen = Screen::Mask,
            Err(e) => state.report(Err(e)),
        }
    }
    everywhere_modal(ui, state, forms);
}

/// One finding: checkbox, preview, View; double-clicking the row outside
/// its widgets opens the viewer too (D137).
fn finding_row(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms, row: &FindingRow) {
    let r = clickable_row(ui, |ui| finding_widgets(ui, state, forms, row));
    if r.double_clicked() {
        let r = state.view_finding(&row.id);
        state.report(r);
    }
}

/// A left-to-right row that senses clicks on its background. It starts one
/// widget row high, like `ui.horizontal`; without that `max_rect` it takes
/// the whole rest of the panel and centres itself in it (D144).
pub(super) fn clickable_row(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) -> egui::Response {
    let size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
    let builder = egui::UiBuilder::new()
        .max_rect(egui::Rect::from_min_size(ui.cursor().min, size))
        .layout(egui::Layout::left_to_right(egui::Align::Center))
        .sense(egui::Sense::click());
    ui.scope_builder(builder, add).response
}

fn finding_widgets(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms, row: &FindingRow) {
    let mut ticked = row.ticked;
    if ui.checkbox(&mut ticked, finding_text(row)).changed() {
        let r = state.set_ticked(&row.id, ticked);
        state.report(r);
    }
    chrome::veil_chip(ui, &row.preview);
    let view = egui::Button::new("View");
    let hint = "Show the file around this finding (read-only)";
    if ui
        .add_enabled(!state.is_busy(), view)
        .on_hover_text(hint)
        .clicked()
    {
        let r = state.view_finding(&row.id);
        state.report(r);
    }
    if row.ticked {
        return;
    }
    if ui.button("Remember: this file").clicked() {
        let r = state.remember(&row.id, Scope::ThisFile, false);
        state.report(r);
    }
    if ui.button("Remember: everywhere").clicked() {
        forms.everywhere = Some(row.id.clone());
    }
}

fn add_key(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.horizontal(|ui| {
        ui.label("Add key name:");
        ui.add(egui::TextEdit::singleline(&mut forms.add_key).hint_text("e.g. customapi-pass"));
        let ok = !state.is_busy() && !forms.add_key.trim().is_empty();
        if ui
            .add_enabled(ok, egui::Button::new("Add and re-scan"))
            .clicked()
        {
            let r = state.add_key(&forms.add_key);
            if r.is_ok() {
                forms.add_key.clear();
            }
            state.report(r);
        }
    });
}

/// "Remember everywhere" ignores the key name in every file: confirm it.
fn everywhere_modal(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    let Some(id) = forms.everywhere.clone() else {
        return;
    };
    let modal = egui::Modal::new(egui::Id::new("remember-everywhere")).show(ui.ctx(), |ui| {
        ui.label(
            "Never auto-select this key name again, in every file and project using this profile?",
        );
        ui.horizontal(|ui| {
            if ui.button("Remember everywhere").clicked() {
                let r = state.remember(&id, Scope::Everywhere, true);
                state.report(r);
                forms.everywhere = None;
            }
            if ui.button("Cancel").clicked() {
                forms.everywhere = None;
            }
        });
    });
    if modal.should_close() {
        forms.everywhere = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs one frame of an 800×600 screen with `clickable_row` at the top
    /// of the central panel; returns the row, one widget row's height and
    /// the panel height left under the row.
    fn one_frame() -> (egui::Response, f32, f32) {
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        };
        let mut out = None;
        let output = ctx.run_ui(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let row = clickable_row(ui, |ui| {
                    let mut on = true;
                    ui.checkbox(&mut on, ".env:2 KEY_NAME");
                    ui.label("abcd… (32)");
                    let _ = ui.button("View");
                });
                let line = ui.spacing().interact_size.y;
                out = Some((row, line, ui.available_height()));
            });
        });
        output.drop_without_applying_deltas();
        out.expect("frame ran")
    }

    #[test]
    fn g21_finding_row_is_one_line_high() {
        let (row, line, left) = one_frame();
        assert!(
            row.rect.height() < 2.0 * line,
            "row is {} px high, one line is {line} px",
            row.rect.height()
        );
        assert!(left > 300.0, "only {left} px left under the row");
        assert!(row.sense.senses_click());
    }
}
