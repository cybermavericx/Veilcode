//! Restore: input and output folders, session, "keep session", report.

use super::{chrome, finding_text, path_row};
use crate::app::{Forms, Target, typed_path};
use crate::state::AppState;
use eframe::egui;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Restore");
    let hint = "the masked folder after the AI edited it";
    path_row(
        ui,
        "Masked folder:",
        hint,
        &mut forms.restore_in,
        &mut forms.browse,
        Target::RestoreIn,
    );
    let hint = "a new folder (must not exist)";
    path_row(
        ui,
        "Output folder:",
        hint,
        &mut forms.restore_out,
        &mut forms.browse,
        Target::RestoreOut,
    );
    session_choice(ui, state, forms);
    ui.checkbox(
        &mut forms.restore_keep,
        "Keep session after a clean restore",
    );
    let ok = !state.is_busy()
        && typed_path(&forms.restore_in).is_some()
        && typed_path(&forms.restore_out).is_some();
    if ui.add_enabled(ok, egui::Button::new("Restore")).clicked()
        && let (Some(input), Some(out)) = (
            typed_path(&forms.restore_in),
            typed_path(&forms.restore_out),
        )
    {
        let r = state.restore(
            input,
            out,
            forms.restore_session.clone(),
            forms.restore_keep,
        );
        state.report(r);
    }
    let (Some(card), Some(r)) = (state.restore_card(), state.restore_view()) else {
        return;
    };
    ui.separator();
    chrome::card(ui, state, &card);
    for f in &r.new_secrets {
        ui.horizontal(|ui| {
            ui.label(format!("new: {}", finding_text(f)));
            chrome::veil_chip(ui, &f.preview);
        });
    }
}

fn session_choice(ui: &mut egui::Ui, state: &AppState, forms: &mut Forms) {
    let rows = state.sessions().map(|v| v.rows).unwrap_or_default();
    let selected = forms
        .restore_session
        .clone()
        .unwrap_or_else(|| "newest".to_string());
    ui.horizontal(|ui| {
        ui.label("Session:");
        egui::ComboBox::from_id_salt("restore-session")
            .selected_text(selected)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut forms.restore_session, None, "newest");
                for row in rows {
                    let text = format!("{} ({}, {} old)", row.id, row.label, row.age);
                    ui.selectable_value(&mut forms.restore_session, Some(row.id), text);
                }
            });
    });
}
