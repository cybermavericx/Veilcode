//! Sessions: age and expiry columns, delete, "Purge all" with confirmation (D63).

use crate::app::Forms;
use crate::state::AppState;
use eframe::egui;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Sessions");
    let view = match state.sessions() {
        Ok(v) => v,
        Err(e) => {
            ui.label(e.to_string());
            return;
        }
    };
    ui.label(&view.summary);
    egui::Grid::new("sessions")
        .striped(true)
        .num_columns(6)
        .show(ui, |ui| {
            for h in ["Session", "Source", "Age", "Expires in", "Tokens", ""] {
                ui.strong(h);
            }
            ui.end_row();
            for row in &view.rows {
                ui.monospace(&row.id);
                ui.label(&row.label);
                ui.label(&row.age);
                ui.label(&row.expires_in);
                ui.label(row.tokens.to_string());
                if ui
                    .add_enabled(!state.is_busy(), egui::Button::new("Delete"))
                    .clicked()
                {
                    let r = state.delete_session(&row.id);
                    state.report(r);
                }
                ui.end_row();
            }
        });
    ui.separator();
    if ui
        .add_enabled(!view.rows.is_empty(), egui::Button::new("Purge all…"))
        .clicked()
    {
        forms.purge_confirm = true;
    }
    if forms.purge_confirm {
        purge_modal(ui, state, forms);
    }
}

fn purge_modal(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    let modal = egui::Modal::new(egui::Id::new("purge-all")).show(ui.ctx(), |ui| {
        ui.label("Remove every session and delete the vault file? Masked folders can then no longer be restored.");
        ui.horizontal(|ui| {
            if ui.button("Purge all").clicked() {
                let r = state.purge(true);
                state.report(r);
                forms.purge_confirm = false;
            }
            if ui.button("Cancel").clicked() {
                forms.purge_confirm = false;
            }
        });
    });
    if modal.should_close() {
        forms.purge_confirm = false;
    }
}
