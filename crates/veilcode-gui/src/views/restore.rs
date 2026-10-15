//! Restore: input and output folders, session, "keep session", report.

use super::{count, path_row};
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
    let Some(r) = state.restore_view() else {
        return;
    };
    ui.separator();
    ui.strong(&r.outcome);
    count(ui, "Files written", r.files_written);
    count(ui, "Tokens replaced", r.tokens_replaced);
    count(ui, "New secrets (added since masking)", r.new_secrets.len());
    count(ui, "New secrets ignored by profile", r.ignored_new_secrets);
    count(ui, "Unknown tokens", r.unknown);
    count(ui, "Missing tokens", r.missing);
    count(ui, "Files not copied", r.not_copied);
    count(ui, "Tokens in unscanned files", r.tokens_in_unscanned);
    for f in &r.new_secrets {
        ui.label(format!(
            "new: {}:{}  {}  {}",
            f.rel_path, f.line, f.key_or_rule, f.preview
        ));
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
