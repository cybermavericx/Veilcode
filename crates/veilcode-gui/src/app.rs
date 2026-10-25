//! The eframe app: routes to the screens, feeds user input to the idle
//! timer, polls the worker and runs the in-process file picker.

use crate::state::{
    AppState, ExistsCache, GuiError, Outcome, Screen, check_local, check_new_vault,
    existing_ancestor, suggested_vault_path, wipe_string,
};
use crate::theme;
use crate::viewmodel;
use crate::views::{self, chrome};
use crate::worker::ThreadRunner;
use eframe::egui;
use egui_file_dialog::{DialogMode, FileDialog};
use std::path::{Path, PathBuf};
use std::time::Duration;
use veilcode_core::{
    DEFAULT_PREFIX, MaskOptions, SystemClock, default_profile_path, default_vault_path,
    user_home_dir,
};

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

    /// The folder pickers, which start in `folder_start` (D144).
    fn is_folder(self) -> bool {
        matches!(
            self,
            Target::ScanInput | Target::RestoreIn | Target::MaskOut | Target::RestoreOut
        )
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
    /// The placeholder prefix as typed (D138).
    pub token_prefix: String,
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
            token_prefix: DEFAULT_PREFIX.to_string(),
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
        // D141: the prefix is filled again from the vault after the next scan.
        self.token_prefix = DEFAULT_PREFIX.to_string();
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
/// Also puts a scanned project's placeholder prefix into the form (D141).
pub fn sync_lock(state: &mut AppState, forms: &mut Forms, ctx: &egui::Context) {
    if state.take_just_locked() {
        forms.wipe();
        ctx.memory_mut(|m| m.data.clear());
    }
    if let Some(prefix) = state.take_prefix_fill() {
        forms.token_prefix = prefix;
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
    theme::apply(ctx);
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
fn open_dialog(t: Target, create: bool, start: Option<PathBuf>) -> FileDialog {
    let base = FileDialog::new()
        .show_new_folder_button(false)
        .allow_file_overwrite(false);
    let mut d = match t {
        Target::ScanInput | Target::RestoreIn | Target::MaskOut | Target::RestoreOut => {
            start_in(base, start)
        }
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
    match picker_settings(t, create) {
        // D135: the input folders list their files (they cannot be
        // submitted: PickDirectory accepts only a directory). egui-file-dialog
        // 0.15.0 offers this only through the deprecated `open`.
        (DialogMode::PickDirectory, true) => {
            #[allow(deprecated)]
            d.open(DialogMode::PickDirectory, true);
        }
        (DialogMode::PickDirectory, false) => d.pick_directory(),
        (DialogMode::PickFile, _) => d.pick_file(),
        _ => d.save_file(),
    }
    d
}

/// The dialog mode for `t` and whether it lists files (D126, D135).
pub fn picker_settings(t: Target, create: bool) -> (DialogMode, bool) {
    match t {
        _ if t.picks_existing_dir() => (DialogMode::PickDirectory, true),
        Target::VaultFile if !create => (DialogMode::PickFile, true),
        _ => (DialogMode::SaveFile, true),
    }
}

/// Puts a picked path into the field of `t`, after the checks the dialog
/// cannot make (D126, D130, D135).
pub fn accept_pick(state: &mut AppState, forms: &mut Forms, t: Target, path: &Path) {
    if let Err(e) = check_local(path) {
        state.report(Err(e));
        return;
    }
    if t.picks_existing_dir() && !path.is_dir() {
        state.report(Err(GuiError::NotAFolder));
        return;
    }
    // D126: the dialog's path field can still name an existing file.
    if t == Target::VaultFile && forms.create {
        let r = check_new_vault(path);
        if r.is_err() {
            state.report(r);
            return;
        }
    }
    *forms.field(t) = path.display().to_string();
}

/// Where a folder picker starts (D144): the nearest existing folder of the
/// typed path (of its parent, for the input pickers), else `home`. A relative path, or a network or device path
/// (refused as text first, D130, so no filesystem call reaches it), falls
/// back to `home`.
fn folder_start(t: Target, typed: &str, home: Option<PathBuf>) -> Option<PathBuf> {
    folder_start_with(t, typed, home, Path::is_dir)
}

/// `folder_start` with the folder check passed in, so tests can count the
/// filesystem calls.
fn folder_start_with(
    t: Target,
    typed: &str,
    home: Option<PathBuf>,
    mut is_dir: impl FnMut(&Path) -> bool,
) -> Option<PathBuf> {
    let typed = typed_path(typed).filter(|p| p.is_absolute() && check_local(p).is_ok());
    // D144 L1 (B): the dialog follows links while it lists a folder, so an
    // input folder (on Restore, the AI's folder) is neither checked nor
    // opened: its picker starts in the parent.
    let from = if t.picks_existing_dir() {
        typed
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
    } else {
        typed
    };
    from.and_then(|p| p.ancestors().find(|a| is_dir(a)).map(Path::to_path_buf))
        .or(home)
}

/// Opens in `start` (D144): not the process's current folder, which is the
/// install folder when Veilcode is started from the Start menu.
fn start_in(d: FileDialog, start: Option<PathBuf>) -> FileDialog {
    match start {
        Some(dir) => d.initial_directory(dir),
        None => d,
    }
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
            // Errors are shown as cards on the screens (D131).
            if let Some(n) = self.state.notice() {
                ui.label(n);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(viewmodel::status_line());
            });
        });
    }

    fn file_picker(&mut self, ctx: &egui::Context) {
        if let Some(t) = self.forms.browse.take() {
            self.target = Some(t);
            // Only the folder pickers use it: no filesystem call for the others.
            let start = t
                .is_folder()
                .then(|| folder_start(t, self.forms.field(t), user_home_dir()))
                .flatten();
            self.dialog = open_dialog(t, self.forms.create, start);
        }
        let dialog = &mut self.dialog;
        theme::with_dialog_style(ctx, |ctx| {
            dialog.update(ctx);
        });
        let (Some(path), Some(t)) = (self.dialog.take_picked(), self.target) else {
            return;
        };
        self.target = None;
        accept_pick(&mut self.state, &mut self.forms, t, &path);
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
        egui::Panel::top("nav").show(ui, |ui| {
            chrome::header(ui);
            self.top_bar(ui);
            ui.separator();
            let rail = self.state.rail();
            chrome::rail(ui, &mut self.state, &rail);
            ui.add_space(4.0);
        });
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                views::show(ui, &mut self.state, &mut self.forms);
            });
        });
        let ctx = ui.ctx().clone();
        views::viewer::show(&ctx, &mut self.state);
        // Actions above may have locked (Lock now, a failed dispatch).
        sync_lock(&mut self.state, &mut self.forms, &ctx);
        self.file_picker(&ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::InlineRunner;
    use egui_file_dialog::DialogMode;

    #[test]
    fn g15_input_pickers_list_files_and_the_others_are_unchanged() {
        let dir_with_files = (DialogMode::PickDirectory, true);
        assert_eq!(picker_settings(Target::ScanInput, false), dir_with_files);
        assert_eq!(picker_settings(Target::RestoreIn, true), dir_with_files);
        let save = (DialogMode::SaveFile, true);
        for t in [
            Target::MaskOut,
            Target::RestoreOut,
            Target::SeparateVault,
            Target::ProfileFile,
        ] {
            assert_eq!(picker_settings(t, false), save, "{t:?}");
        }
        let open_vault = (DialogMode::PickFile, true);
        assert_eq!(picker_settings(Target::VaultFile, false), open_vault);
        assert_eq!(picker_settings(Target::VaultFile, true), save);
        let d = open_dialog(Target::ScanInput, false, None);
        assert_eq!(d.mode(), DialogMode::PickDirectory);
    }

    /// egui-file-dialog 0.15.0 has no getter for `show_files`, so only the
    /// mode of the real dialog is checked; the files flag is checked on
    /// `picker_settings`, which `open_dialog` matches on.
    #[test]
    fn g15b_real_input_dialogs_are_folder_pickers() {
        for t in [Target::ScanInput, Target::RestoreIn] {
            assert_eq!(
                open_dialog(t, false, None).mode(),
                DialogMode::PickDirectory,
                "{t:?}"
            );
            assert_eq!(picker_settings(t, false), (DialogMode::PickDirectory, true));
        }
        assert_eq!(
            open_dialog(Target::MaskOut, false, None).mode(),
            DialogMode::SaveFile
        );
        assert_eq!(
            open_dialog(Target::VaultFile, false, None).mode(),
            DialogMode::PickFile
        );
    }

    #[test]
    fn g22_folder_start_prefers_the_typed_folder_then_home() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let home = tmp.path().join("home");
        let typed = tmp.path().join("work");
        std::fs::create_dir_all(&home).expect("home");
        std::fs::create_dir_all(&typed).expect("work");
        let start = |t: &str| folder_start(Target::MaskOut, t, Some(home.clone()));
        let s = typed.display().to_string();
        assert_eq!(start(&s), Some(typed.clone()));
        let missing = typed.join("not-yet").join("out");
        assert_eq!(start(&missing.display().to_string()), Some(typed.clone()));
        assert_eq!(start(""), Some(home.clone()));
        assert_eq!(start("  "), Some(home.clone()));
        assert_eq!(start("relative/dir"), Some(home.clone()));
        let file = typed.join("app.js");
        std::fs::write(&file, b"x").expect("write");
        assert_eq!(start(&file.display().to_string()), Some(typed.clone()));
        #[cfg(unix)]
        assert_eq!(start("/"), Some(PathBuf::from("/")));
    }

    /// D144 L1 (B): an input picker starts in the typed folder's parent and
    /// never checks the typed folder itself (the dialog follows links).
    #[test]
    fn g22_input_pickers_start_in_the_parent_of_the_typed_folder() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let typed = tmp.path().join("ai-output");
        std::fs::create_dir_all(&typed).expect("typed");
        let home = Some(tmp.path().join("home"));
        for t in [Target::ScanInput, Target::RestoreIn] {
            let mut seen = Vec::new();
            let start = folder_start_with(t, &typed.display().to_string(), home.clone(), |p| {
                seen.push(p.to_path_buf());
                p.is_dir()
            });
            assert_eq!(start.as_deref(), Some(tmp.path()), "{t:?}");
            assert!(!seen.contains(&typed), "{t:?} checked the typed folder");
            let missing = typed.join("gone");
            let s = missing.display().to_string();
            assert_eq!(
                folder_start(t, &s, home.clone()),
                Some(typed.clone()),
                "{t:?}"
            );
            #[cfg(unix)]
            assert_eq!(folder_start(t, "/", home.clone()), home, "{t:?}");
        }
        let s = typed.display().to_string();
        assert_eq!(folder_start(Target::MaskOut, &s, home), Some(typed));
    }

    /// D130: network and device paths are refused as text, so the folder
    /// check is never called for them.
    #[test]
    fn g22_network_and_device_paths_make_no_filesystem_call() {
        let home = PathBuf::from("home");
        for typed in [
            r"\\server\share\dir",
            "//host/share",
            r"\\?\UNC\server\share",
            r"\\.\pipe\x",
            r"\??\C:\x",
            r"\\?\GLOBALROOT\Device",
        ] {
            let mut calls = 0;
            let start = folder_start_with(Target::ScanInput, typed, Some(home.clone()), |_| {
                calls += 1;
                true
            });
            assert_eq!(start, Some(home.clone()), "{typed}");
            assert_eq!(calls, 0, "{typed}");
        }
        assert_eq!(folder_start(Target::MaskOut, "", None), None);
    }

    #[test]
    fn g22_folder_dialogs_open_in_the_start_folder() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        for t in [
            Target::ScanInput,
            Target::RestoreIn,
            Target::MaskOut,
            Target::RestoreOut,
        ] {
            let mut d = open_dialog(t, false, Some(tmp.path().to_path_buf()));
            assert_eq!(d.config_mut().initial_directory, tmp.path(), "{t:?}");
        }
    }

    #[test]
    fn g15_a_picked_file_is_refused_for_input_folders() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let file = tmp.path().join("app.js");
        std::fs::write(&file, b"x").expect("write");
        let runner = Box::new(InlineRunner::<Outcome>::default());
        let mut state = AppState::new(runner, Box::new(SystemClock));
        let mut forms = Forms::default();
        for t in [Target::ScanInput, Target::RestoreIn] {
            accept_pick(&mut state, &mut forms, t, &file);
            assert!(forms.field(t).is_empty(), "{t:?} took a file");
            let msg = state.error().map(ToString::to_string);
            assert_eq!(msg.as_deref(), Some("choose a folder, not a file"));
            accept_pick(&mut state, &mut forms, t, tmp.path());
            assert_eq!(*forms.field(t), tmp.path().display().to_string());
        }
        accept_pick(&mut state, &mut forms, Target::MaskOut, &file);
        assert_eq!(forms.mask_out, file.display().to_string());
    }
}
