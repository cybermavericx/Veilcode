//! Help: how Veilcode works, the safety rules and where files are stored
//! (D127). Fixed text from the guide model; no links.

use crate::viewmodel::{self, Guide};
use eframe::egui;
use veilcode_core::{default_profile_path, default_vault_path};

/// The guide for this system's default file locations.
pub(super) fn current() -> Guide {
    let (vault, profile) = (default_vault_path(), default_profile_path());
    viewmodel::guide(vault.as_deref(), profile.as_deref())
}

pub fn show(ui: &mut egui::Ui) {
    let g = current();
    ui.heading("Help");
    ui.strong("How Veilcode works");
    steps(ui, &g);
    ui.separator();
    ui.strong("Safety rules");
    for rule in g.safety {
        ui.label(format!("• {rule}"));
    }
    ui.separator();
    ui.strong("Where files are stored");
    for line in &g.storage {
        ui.label(line);
    }
    ui.label("On Windows both are in the local (non-roaming) app data folder.");
}

/// The numbered steps of the guide.
pub(super) fn steps(ui: &mut egui::Ui, g: &Guide) {
    for (i, step) in g.steps.iter().enumerate() {
        ui.label(format!("{}. {step}", i + 1));
    }
}
