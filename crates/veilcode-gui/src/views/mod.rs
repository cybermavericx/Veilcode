//! One module per screen. Views only read view models and call state
//! actions; no logic lives here. There are no links anywhere (SPEC §10.4).

pub mod chrome;
mod help;
mod mask;
mod restore;
mod review;
mod scan;
mod sessions;
mod text_mode;
mod unlock;
pub mod viewer;

use crate::app::{Forms, Target};
use crate::state::{AppState, Screen};
use crate::viewmodel::FindingRow;
use eframe::egui;

/// Shows the current screen (Unlock while a vault screen is chosen but the
/// vault is locked; Help is always available, D127).
pub fn show(ui: &mut egui::Ui, state: &mut AppState, forms: &mut Forms) {
    let screen = state.shown_screen();
    // The Unlock screen shows its error next to the button (D128).
    if screen != Screen::Unlock
        && let Some(card) = state.error_card()
    {
        chrome::card(ui, state, &card);
        ui.add_space(6.0);
    }
    match screen {
        Screen::Unlock => unlock::show(ui, state, forms),
        Screen::Scan => scan::show(ui, state, forms),
        Screen::Review => review::show(ui, state, forms),
        Screen::Mask => mask::show(ui, state, forms),
        Screen::Restore => restore::show(ui, state, forms),
        Screen::Sessions => sessions::show(ui, state, forms),
        Screen::TextMode => text_mode::show(ui, state, forms),
        Screen::Help => help::show(ui),
    }
}

/// A labelled path field with a "Browse…" button for the in-process picker.
fn path_row(
    ui: &mut egui::Ui,
    label: &str,
    hint: &str,
    value: &mut String,
    browse: &mut Option<Target>,
    target: Target,
) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(420.0),
        );
        if ui.button("Browse…").clicked() {
            *browse = Some(target);
        }
    });
}

/// A passphrase field (masked) with the fixed egui id `id`.
fn pass_row(ui: &mut egui::Ui, label: &str, value: &mut String, id: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .id(egui::Id::new(id))
                .desired_width(300.0),
        );
    });
}

/// One "name: value" line of a report.
fn count(ui: &mut egui::Ui, name: &str, n: usize) {
    ui.label(format!("{name}: {n}"));
}

/// One finding: "file:line  key or rule", then its preview on a veil chip.
fn finding_text(row: &FindingRow) -> String {
    format!("{}:{}  {}", row.rel_path, row.line, row.key_or_rule)
}

/// Forgets egui's state of these text fields, including the undo history
/// that holds earlier contents (D106).
fn clear_fields(ctx: &egui::Context, ids: &[&str]) {
    ctx.data_mut(|d| {
        for id in ids {
            d.remove::<egui::text_edit::TextEditState>(egui::Id::new(*id));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{GuiError, Outcome};
    use crate::worker::InlineRunner;
    use egui::text_edit::TextEditState;
    use veilcode_core::SystemClock;

    fn stored(ctx: &egui::Context, id: &str) -> bool {
        egui::TextEdit::load_state(ctx, egui::Id::new(id)).is_some()
    }

    #[test]
    fn g10_submit_clears_passphrase_field_state() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let ctx = egui::Context::default();
        let ids = [unlock::PASS, unlock::CONFIRM, mask::PASS, mask::CONFIRM];
        for id in ids {
            TextEditState::default().store(&ctx, egui::Id::new(id));
            assert!(stored(&ctx, id));
        }
        let runner = Box::new(InlineRunner::<Outcome>::default());
        let mut state = AppState::new(runner, Box::new(SystemClock));
        let mut forms = Forms {
            create: true,
            vault_path: tmp.path().join("v.vc").display().to_string(),
            pass: "one".to_string(),
            confirm: "two".to_string(),
            separate: true,
            separate_path: tmp.path().join("p.vc").display().to_string(),
            mask_out: tmp.path().join("out").display().to_string(),
            ..Forms::default()
        };
        unlock::submit(&mut state, &mut forms, &ctx);
        assert!(!stored(&ctx, unlock::PASS) && !stored(&ctx, unlock::CONFIRM));
        mask::submit(&mut state, &mut forms, &ctx);
        assert!(!stored(&ctx, mask::PASS) && !stored(&ctx, mask::CONFIRM));
        // While unlocked, choosing a vault file is refused (LockFirst): the
        // fields are cleared on that exit path too.
        let pass = || veilcode_core::SecretString::new("correct horse battery".to_string());
        state.create_vault(pass(), pass()).expect("create");
        state.poll();
        assert!(state.is_unlocked());
        TextEditState::default().store(&ctx, egui::Id::new(unlock::PASS));
        forms.pass = "typed".to_string();
        unlock::submit(&mut state, &mut forms, &ctx);
        assert!(matches!(state.error(), Some(GuiError::LockFirst)));
        assert!(!stored(&ctx, unlock::PASS), "field state kept on LockFirst");
        assert!(forms.pass.is_empty(), "passphrase kept on LockFirst");
    }
}
