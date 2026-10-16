//! Unlock or create the vault (default or a per-project file, D64).

use super::{chrome, clear_fields, help, pass_row, path_row};
use crate::app::{Forms, Target, typed_path};
use crate::state::{AppState, GuiError, create_problems, suggested_vault_path};
use crate::viewmodel::UNLOCK_HINT;
use eframe::egui;
use veilcode_core::SecretString;

/// Egui ids of the passphrase fields.
pub const PASS: &str = "unlock-pass";
pub const CONFIRM: &str = "unlock-confirm";

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Unlock vault");
    ui.label(UNLOCK_HINT);
    ui.horizontal(|ui| {
        ui.radio_value(&mut forms.create, false, "Open existing vault");
        ui.radio_value(&mut forms.create, true, "Create new vault");
    });
    let hint = "default vault (leave empty), or a per-project .vc file";
    path_row(
        ui,
        "Vault file:",
        hint,
        &mut forms.vault_path,
        &mut forms.browse,
        Target::VaultFile,
    );
    pass_row(ui, "Passphrase:", &mut forms.pass, PASS);
    let problems = if forms.create {
        pass_row(ui, "Repeat passphrase:", &mut forms.confirm, CONFIRM);
        ui.label("At least 12 characters. There is no recovery if you forget it.");
        let path = typed_path(&forms.vault_path).or_else(suggested_vault_path);
        create_problems(
            path.as_deref(),
            &forms.pass,
            &forms.confirm,
            &mut forms.vault_exists,
        )
    } else {
        Vec::new()
    };
    let error = ui.visuals().error_fg_color;
    for p in &problems {
        ui.colored_label(error, p.to_string());
    }
    let label = if forms.create { "Create" } else { "Unlock" };
    let ok = !state.is_busy() && problems.is_empty();
    if ui.add_enabled(ok, egui::Button::new(label)).clicked() {
        submit(state, forms, ui.ctx());
    }
    if let Some(card) = state.error_card() {
        chrome::card(ui, state, &card);
    }
    ui.separator();
    egui::CollapsingHeader::new("How Veilcode works")
        .default_open(true)
        .show(ui, |ui| help::steps(ui, &help::current()));
}

/// Takes the passphrases out of the forms first, so that on every exit path
/// they are dropped (zeroized) and the fields' egui state is cleared (D106).
pub(super) fn submit(state: &mut AppState, forms: &mut Forms, ctx: &egui::Context) {
    let pass = SecretString::new(std::mem::take(&mut forms.pass));
    let confirm = SecretString::new(std::mem::take(&mut forms.confirm));
    clear_fields(ctx, &[PASS, CONFIRM]);
    let result = start(state, forms, pass, confirm);
    state.report(result);
}

fn start(
    state: &mut AppState,
    forms: &Forms,
    pass: SecretString,
    confirm: SecretString,
) -> Result<(), GuiError> {
    state.set_vault_path(typed_path(&forms.vault_path))?;
    if forms.create {
        state.create_vault(pass, confirm)
    } else {
        state.unlock(pass)
    }
}
