//! Scan a folder; findings list with checkboxes and previews.

use super::{chrome, finding_text, path_row};
use crate::app::{Forms, Target, typed_path};
use crate::state::AppState;
use crate::viewmodel::FindingRow;
use eframe::egui;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Scan");
    path_row(
        ui,
        "Project folder:",
        "folder to mask",
        &mut forms.scan_input,
        &mut forms.browse,
        Target::ScanInput,
    );
    profile_row(ui, state, forms);
    let can_scan = !state.is_busy() && typed_path(&forms.scan_input).is_some();
    if ui
        .add_enabled(can_scan, egui::Button::new("Scan"))
        .clicked()
        && let Some(input) = typed_path(&forms.scan_input)
    {
        let r = state.scan(input);
        state.report(r);
    }
    rescan_row(ui, state);
    let Some(card) = state.scan_card() else {
        return;
    };
    ui.separator();
    chrome::card(ui, state, &card);
    let Some(view) = state.review() else {
        return;
    };
    let rows: Vec<_> = view
        .groups
        .iter()
        .flat_map(|g| g.rows.clone())
        .chain(view.ignored.clone())
        .collect();
    for row in rows {
        ui.horizontal(|ui| finding(ui, state, &row));
    }
}

/// D136: scan the same folder again; the review starts over.
fn rescan_row(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui
            .add_enabled(state.can_rescan(), egui::Button::new("Rescan"))
            .clicked()
        {
            let r = state.rescan();
            state.report(r);
        }
        ui.weak(
            "Scans the last folder again: every finding is ticked again and the review restarts.",
        );
    });
}

/// The per-project profile option (D74), next to the per-project vault.
pub fn profile_row(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    let hint = "default profile (leave empty), or a per-project profile.toml";
    path_row(
        ui,
        "Profile file:",
        hint,
        &mut forms.profile_path,
        &mut forms.browse,
        Target::ProfileFile,
    );
    let wanted = typed_path(&forms.profile_path);
    if !state.is_busy() && wanted.as_deref() != state.profile_path() {
        let r = state.set_profile_path(wanted);
        state.report(r);
    }
}

/// One finding row: a checkbox, its location and its veil chip.
fn finding(ui: &mut egui::Ui, state: &mut AppState, row: &FindingRow) {
    let mut ticked = row.ticked;
    let text = finding_text(row);
    let label = if row.ignored {
        format!("{text}  (ignored by profile)")
    } else {
        text
    };
    if ui
        .add_enabled(!row.ignored, egui::Checkbox::new(&mut ticked, label))
        .changed()
    {
        let r = state.set_ticked(&row.id, ticked);
        state.report(r);
    }
    chrome::veil_chip(ui, &row.preview);
}
