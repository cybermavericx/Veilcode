//! The eframe app: routes to the screens, feeds user input to the idle
//! timer, polls the worker and runs the in-process file picker.

use crate::state::{
    AppState, ExistsCache, Outcome, Screen, check_local, check_new_vault, existing_ancestor,
    suggested_vault_path, wipe_string,
};
use crate::views;
use crate::worker::ThreadRunner;
use eframe::egui;
use egui_file_dialog::FileDialog;
use std::path::{Path, PathBuf};
use std::time::Duration;
use veilcode_core::{MaskOptions, SystemClock, default_profile_path, default_vault_path};

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
    /// Whether the typed Create path exists, checked once per change (D130).
    pub vault_exists: ExistsCache,
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
            vault_exists: ExistsCache::default(),
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

/// Display names of the save and filter entries in the pickers.
const VAULT_FILES: &str = "Veilcode vault (*.vc)";
const PROFILE_FILES: &str = "Veilcode profile (*.toml)";

/// D125: the app, or an error screen when it cannot start (on Windows
/// there is no console that could show the error).
pub fn start(ctx: &egui::Context) -> Box<dyn eframe::App> {
    match VeilApp::new(ctx) {
        Ok(app) => Box::new(app),
        Err(e) => Box::new(StartupError(format!(
            "The background worker could not start: {e}"
        ))),
    }
}

/// Shown instead of the app when it could not start (D125).
pub struct StartupError(String);

impl eframe::App for StartupError {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Veilcode could not start");
            ui.label(&self.0);
            ui.label("Close this window and start Veilcode again.");
        });
    }
}

/// The tab label of a screen.
fn tab_label(s: Screen) -> &'static str {
    match s {
        Screen::Unlock => "Unlock",
        Screen::Scan => "Scan",
        Screen::Review => "Review",
        Screen::Mask => "Mask",
        Screen::Restore => "Restore",
        Screen::Sessions => "Sessions",
        Screen::TextMode => "Text Mode",
        Screen::Help => "Help",
    }
}

/// D126: a picker for `t`, already open. `create`: the Unlock screen is in
/// Create mode. No dialog offers to overwrite a file.
fn open_dialog(t: Target, create: bool) -> FileDialog {
    let base = FileDialog::new()
        .show_new_folder_button(false)
        .allow_file_overwrite(false);
    let mut d = match t {
        Target::ScanInput | Target::RestoreIn | Target::MaskOut | Target::RestoreOut => base,
        Target::VaultFile if !create => in_dir(base, default_vault_path())
            .add_file_filter_extensions(VAULT_FILES, vec!["vc"])
            .default_file_filter(VAULT_FILES),
        Target::VaultFile => save_as(base, suggested_vault_path(), "vault.vc", VAULT_FILES, "vc"),
        Target::SeparateVault => {
            let d = save_as(base, default_vault_path(), "project.vc", VAULT_FILES, "vc");
            use_existing(d)
        }
        Target::ProfileFile => {
            let d = save_as(
                base,
                default_profile_path(),
                "profile.toml",
                PROFILE_FILES,
                "toml",
            );
            use_existing(d)
        }
    };
    match t {
        _ if t.picks_existing_dir() => d.pick_directory(),
        Target::VaultFile if !create => d.pick_file(),
        _ => d.save_file(),
    }
    d
}

/// Opens in the nearest existing folder of `default`'s folder.
fn in_dir(d: FileDialog, default: Option<PathBuf>) -> FileDialog {
    let dir = default
        .as_deref()
        .and_then(Path::parent)
        .and_then(existing_ancestor);
    match dir {
        Some(dir) => d.initial_directory(dir),
        None => d,
    }
}

/// A save picker that suggests `name` and lists only `ext` files.
fn save_as(
    d: FileDialog,
    default: Option<PathBuf>,
    name: &str,
    kind: &str,
    ext: &str,
) -> FileDialog {
    in_dir(d, default)
        .default_file_name(name)
        .add_save_extension(kind, ext)
        .default_save_extension(kind)
}

/// For files that may exist and are then used, not replaced (a separate
/// vault is opened, a profile is read and updated): the dialog's
/// existing-file prompt says so instead of "Overwrite".
fn use_existing(mut d: FileDialog) -> FileDialog {
    d = d.allow_file_overwrite(true);
    let labels = d.labels_mut();
    labels.overwrite = "Use this file".to_string();
    labels.overwrite_file_modal_text =
        "already exists. Veilcode will use it and save its changes into it.".to_string();
    d
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
            dialog: FileDialog::new()
                .show_new_folder_button(false)
                .allow_file_overwrite(false),
            target: None,
        })
    }

    /// Tabs: Unlock while locked, the vault screens (disabled with a
    /// tooltip while locked, D127), Help always, and "Lock now".
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let unlocked = self.state.is_unlocked();
        ui.horizontal(|ui| {
            for screen in Screen::ALL {
                if screen == Screen::Unlock && unlocked {
                    continue;
                }
                let selected = self.state.shown_screen() == screen;
                let button = egui::Button::selectable(selected, tab_label(screen));
                let hint = self.state.tab_hint(screen);
                let mut r = ui.add_enabled(hint.is_none(), button);
                if let Some(h) = hint {
                    r = r.on_disabled_hover_text(h);
                }
                if r.clicked() {
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
            self.dialog = open_dialog(t, self.forms.create);
        }
        self.dialog.update(ctx);
        let (Some(path), Some(t)) = (self.dialog.take_picked(), self.target) else {
            return;
        };
        self.target = None;
        if let Err(e) = check_local(&path) {
            self.state.report(Err(e));
            return;
        }
        // D126: the dialog's path field can still name an existing file.
        if t == Target::VaultFile && self.forms.create {
            let r = check_new_vault(&path);
            if r.is_err() {
                self.state.report(r);
                return;
            }
        }
        *self.forms.field(t) = path.display().to_string();
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
