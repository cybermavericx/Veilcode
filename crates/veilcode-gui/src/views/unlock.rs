//! Unlock or create the vault (default or a per-project file, D64).

use super::{clear_fields, pass_row, path_row};
use crate::app::{Forms, Target, typed_path};
use crate::state::{AppState, GuiError};
use eframe::egui;
use veilcode_core::SecretString;

/// Egui ids of the passphrase fields.
pub const PASS: &str = "unlock-pass";
pub const CONFIRM: &str = "unlock-confirm";

pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    ui.heading("Unlock vault");
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
    if forms.create {
        pass_row(ui, "Repeat passphrase:", &mut forms.confirm, CONFIRM);
        ui.label("At least 12 characters. There is no recovery if you forget it.");
    }
    let label = if forms.create { "Create" } else { "Unlock" };
    if ui
        .add_enabled(!state.is_busy(), egui::Button::new(label))
        .clicked()
    {
        submit(state, forms, ui.ctx());
    }
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
