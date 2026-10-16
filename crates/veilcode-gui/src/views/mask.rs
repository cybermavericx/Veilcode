//! Mask: output folder, TTL, separate per-project vault (D64), report.

use super::{chrome, clear_fields, pass_row, path_row};
use crate::app::{Forms, Target, typed_path};
use crate::state::{AppState, MaskForm, Screen, SeparateVault};
use eframe::egui;
use veilcode_core::SecretString;

/// Egui ids of the separate-vault passphrase fields.
pub const PASS: &str = "mask-separate-pass";
pub const CONFIRM: &str = "mask-separate-confirm";

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Mask");
    if !state.review_confirmed() {
        ui.label("Review the findings and confirm before masking.");
        if ui.button("Go to Review").clicked() {
            state.screen = Screen::Review;
        }
    } else {
        options(ui, forms);
        let vault_ok = !forms.separate || typed_path(&forms.separate_path).is_some();
        let ok = !state.is_busy() && vault_ok && typed_path(&forms.mask_out).is_some();
        if ui
            .add_enabled(ok, egui::Button::new("Start mask"))
            .clicked()
        {
            submit(state, forms, ui.ctx());
        }
    }
    if let Some(card) = state.mask_card() {
        ui.separator();
        chrome::card(ui, state, &card);
    }
}

fn options(ui: &mut egui::Ui, forms: &mut Forms) {
    let hint = "a new folder outside the project (must not exist)";
    path_row(
        ui,
        "Output folder:",
        hint,
        &mut forms.mask_out,
        &mut forms.browse,
        Target::MaskOut,
    );
    ui.horizontal(|ui| {
        ui.label("Keep the session for:");
        ui.add(
            egui::DragValue::new(&mut forms.ttl_days)
                .range(1..=365)
                .suffix(" days"),
        );
    });
    ui.checkbox(&mut forms.separate, "Separate vault for this project");
    if forms.separate {
        let hint = "project vault file, e.g. myproject.vc";
        path_row(
            ui,
            "Project vault:",
            hint,
            &mut forms.separate_path,
            &mut forms.browse,
            Target::SeparateVault,
        );
        pass_row(ui, "Its passphrase:", &mut forms.separate_pass, PASS);
        pass_row(
            ui,
            "Repeat (new vault only):",
            &mut forms.separate_confirm,
            CONFIRM,
        );
    }
}

pub(super) fn submit(state: &mut AppState, forms: &mut Forms, ctx: &egui::Context) {
    let Some(out) = typed_path(&forms.mask_out) else {
        return;
    };
    let separate_vault = match (forms.separate, typed_path(&forms.separate_path)) {
        (true, Some(path)) => Some(SeparateVault {
            path,
            pass: SecretString::new(std::mem::take(&mut forms.separate_pass)),
            confirm: SecretString::new(std::mem::take(&mut forms.separate_confirm)),
        }),
        _ => None,
    };
    clear_fields(ctx, &[PASS, CONFIRM]);
    let form = MaskForm {
        ttl_days: forms.ttl_days,
        separate_vault,
    };
    let r = state.mask(out, form);
    state.report(r);
}
