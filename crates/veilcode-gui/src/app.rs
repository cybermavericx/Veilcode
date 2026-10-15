//! The eframe app: routes to the screens, feeds user input to the idle
//! timer, polls the worker and runs the in-process file picker.

use crate::state::{AppState, Outcome, Screen, wipe_string};
use crate::views;
use crate::worker::ThreadRunner;
use eframe::egui;
use egui_file_dialog::FileDialog;
use std::path::PathBuf;
use std::time::Duration;
use veilcode_core::{MaskOptions, SystemClock};

/// Which form field a file-picker result goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    VaultFile,
    ScanInput,
    ProfileFile,
    MaskOut,
    SeparateVault,
    RestoreIn,
    RestoreOut,
}

impl Target {
    /// Inputs are existing folders; everything else is a new path.
    fn picks_existing_dir(self) -> bool {
        matches!(self, Target::ScanInput | Target::RestoreIn)
    }
}

/// Text typed into the screens (UI-only; passphrases are moved into
/// `SecretString`s on submit and wiped on lock).
pub struct Forms {
    pub create: bool,
    pub vault_path: String,
    pub pass: String,
    pub confirm: String,
    pub scan_input: String,
    pub profile_path: String,
    pub add_key: String,
    /// A finding waiting for the "remember everywhere" confirmation.
    pub everywhere: Option<String>,
    pub mask_out: String,
    pub ttl_days: u32,
    pub separate: bool,
    pub separate_path: String,
    pub separate_pass: String,
    pub separate_confirm: String,
    pub restore_in: String,
    pub restore_out: String,
    pub restore_session: Option<String>,
    pub restore_keep: bool,
    pub text_keep: bool,
    pub purge_confirm: bool,
    /// Set by a "Browse…" button; the app opens the picker.
    pub browse: Option<Target>,
}

impl Default for Forms {
    fn default() -> Self {
        Forms {
            create: false,
            vault_path: String::new(),
            pass: String::new(),
            confirm: String::new(),
            scan_input: String::new(),
            profile_path: String::new(),
            add_key: String::new(),
            everywhere: None,
            mask_out: String::new(),
            ttl_days: MaskOptions::default().ttl_days,
            separate: false,
            separate_path: String::new(),
            separate_pass: String::new(),
            separate_confirm: String::new(),
            restore_in: String::new(),
            restore_out: String::new(),
            restore_session: None,
            restore_keep: false,
            text_keep: false,
            purge_confirm: false,
            browse: None,
        }
    }
}

impl Forms {
    /// Wipes every passphrase buffer and pending confirmation.
    fn wipe(&mut self) {
        #[cfg(test)]
        FORM_WIPES.with(|c| c.set(c.get() + 1));
        for s in [
            &mut self.pass,
            &mut self.confirm,
            &mut self.separate_pass,
            &mut self.separate_confirm,
        ] {
            wipe_string(std::mem::take(s));
        }
        self.everywhere = None;
        self.purge_confirm = false;
        self.restore_session = None;
    }

    fn field(&mut self, t: Target) -> &mut String {
        match t {
            Target::VaultFile => &mut self.vault_path,
            Target::ScanInput => &mut self.scan_input,
            Target::ProfileFile => &mut self.profile_path,
            Target::MaskOut => &mut self.mask_out,
            Target::SeparateVault => &mut self.separate_path,
            Target::RestoreIn => &mut self.restore_in,
            Target::RestoreOut => &mut self.restore_out,
        }
    }
}

#[cfg(test)]
thread_local! {
    static FORM_WIPES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Number of `Forms` wipes on this thread (G10).
#[cfg(test)]
pub fn form_wipes() -> usize {
    FORM_WIPES.with(|c| c.get())
}

/// After any lock (D106): drops UI copies of anything typed while
/// unlocked, including egui's per-widget memory (text edit undo history).
pub fn sync_lock(state: &mut AppState, forms: &mut Forms, ctx: &egui::Context) {
    if state.take_just_locked() {
        forms.wipe();
        ctx.memory_mut(|m| m.data.clear());
    }
}

/// An optional path typed by the user (`None` when blank).
pub fn typed_path(s: &str) -> Option<PathBuf> {
    let s = s.trim();
    (!s.is_empty()).then(|| PathBuf::from(s))
}

/// The application.
pub struct VeilApp {
    state: AppState,
    forms: Forms,
    dialog: FileDialog,
    target: Option<Target>,
}

impl VeilApp {
    /// Starts the worker thread; it wakes the UI when a job finishes.
    pub fn new(ctx: &egui::Context) -> std::io::Result<Self> {
        let ctx = ctx.clone();
        let runner = ThreadRunner::<Outcome>::start(move || ctx.request_repaint())?;
        Ok(VeilApp {
            state: AppState::new(Box::new(runner), Box::new(SystemClock)),
            forms: Forms::default(),
            dialog: FileDialog::new().show_new_folder_button(false),
            target: None,
        })
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let unlocked = self.state.is_unlocked();
        ui.horizontal(|ui| {
            let screens = [
                (Screen::Scan, "Scan"),
                (Screen::Review, "Review"),
                (Screen::Mask, "Mask"),
                (Screen::Restore, "Restore"),
                (Screen::Sessions, "Sessions"),
                (Screen::TextMode, "Text Mode"),
            ];
            for (screen, label) in screens {
                let selected = self.state.screen == screen;
                let button = egui::Button::selectable(selected, label);
                if ui.add_enabled(unlocked, button).clicked() {
                    self.state.screen = screen;
                }
            }
            ui.separator();
            if ui.button("Lock now").clicked() {
                self.state.lock();
            }
        });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.state.is_busy() {
                ui.spinner();
                ui.label("Working…");
            }
            if let Some(e) = self.state.error() {
                ui.colored_label(ui.visuals().error_fg_color, e.to_string());
            } else if let Some(n) = self.state.notice() {
                ui.label(n);
            }
        });
    }

    fn file_picker(&mut self, ctx: &egui::Context) {
        if let Some(t) = self.forms.browse.take() {
            self.target = Some(t);
            if t.picks_existing_dir() {
                self.dialog.pick_directory();
            } else {
                self.dialog.save_file();
            }
        }
        self.dialog.update(ctx);
        if let (Some(path), Some(t)) = (self.dialog.take_picked(), self.target) {
            *self.forms.field(t) = path.display().to_string();
            self.target = None;
        }
    }
}

/// Events that count as the user being present (resets the idle timer).
fn is_user_input(e: &egui::Event) -> bool {
    use egui::Event as E;
    matches!(
        e,
        E::Copy
            | E::Cut
            | E::Paste(_)
            | E::Text(_)
            | E::Key { .. }
            | E::PointerMoved(_)
            | E::MouseMoved(_)
            | E::PointerButton { .. }
            | E::MouseWheel { .. }
            | E::Touch { .. }
            | E::Zoom(_)
    )
}

impl eframe::App for VeilApp {
    /// Runs every frame and, through the repaint timer, also while the
    /// window is hidden: applies worker results and checks the idle lock.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.tick();
        sync_lock(&mut self.state, &mut self.forms, ctx);
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Fresh input of this pass only (no pass runs while hidden).
        if ui.ctx().input(|i| i.events.iter().any(is_user_input)) {
            self.state.note_input();
        }
        egui::Panel::top("nav").show(ui, |ui| self.top_bar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                views::show(ui, &mut self.state, &mut self.forms);
            });
        });
        let ctx = ui.ctx().clone();
        // Actions above may have locked (Lock now, a failed dispatch).
        sync_lock(&mut self.state, &mut self.forms, &ctx);
        self.file_picker(&ctx);
    }
}
