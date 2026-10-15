//! Text Mode (SPEC §6.3): the only screen that shows real values, because
//! the user pasted them.

use super::count;
use crate::app::Forms;
use crate::state::AppState;
use eframe::egui;

/// The warning on restored text (SPEC §6.3).
const RESTORED_WARNING: &str = "contains real secrets — clipboard managers may keep history";

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Text Mode");
    ui.label("Paste text to mask, or masked text to restore:");
    ui.add(
        egui::TextEdit::multiline(&mut state.text.input)
            .code_editor()
            .desired_rows(10)
            .desired_width(f32::INFINITY),
    );
    let busy = state.is_busy();
    let keep = forms.text_keep;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("Mask text"))
            .clicked()
        {
            let r = state.mask_text();
            state.report(r);
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Restore text"))
            .clicked()
        {
            let r = state.restore_text(keep);
            state.report(r);
        }
        ui.checkbox(&mut forms.text_keep, "Keep session");
    });
    ui.separator();
    if state.text.output_restored {
        ui.colored_label(ui.visuals().warn_fg_color, RESTORED_WARNING);
    }
    let mut output = state.text.output.as_str();
    ui.add(
        egui::TextEdit::multiline(&mut output)
            .code_editor()
            .desired_rows(10)
            .desired_width(f32::INFINITY),
    );
    if let Some(r) = state.text_report() {
        ui.strong(&r.outcome);
        count(ui, "Tokens replaced", r.tokens_replaced);
        count(ui, "Unknown tokens", r.unknown);
        count(ui, "Missing tokens", r.missing);
        count(ui, "New secrets", r.new_secrets.len());
    }
}
