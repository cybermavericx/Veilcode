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
    let builder = egui::UiBuilder::new()
        .layout(egui::Layout::left_to_right(egui::Align::Center))
        .sense(egui::Sense::click());
    let r = ui.scope_builder(builder, |ui| finding_widgets(ui, state, forms, row));
    if r.response.double_clicked() {
        let r = state.view_finding(&row.id);
        state.report(r);
    }
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
