//! App state and actions. No egui types here, so G1-G3 and G7 test it
//! without a window. Every Argon2 or file-I/O step runs as a job on the
//! `Runner` (worker.rs); while a job needs the vault, the vault travels
//! with the job and comes back with its result.

use crate::idle::{IDLE_LIMIT_SECS, IdleTimer};
use crate::viewmodel::{
    self, MaskView, Progress, RestoreView, ResultCard, ReviewView, SessionsView, Step, WorkflowRail,
};
use crate::worker::{Job, Runner};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use veilcode_core::{
    Clock, CoreError, Finding, MaskOptions, MaskReport, Profile, RestoreReport, ScanOptions,
    ScanReport, Scope, SecretBytes, SecretString, Selection, SessionId, Vault,
    default_profile_path, default_vault_path,
};

#[cfg(test)]
thread_local! {
    static KEY_WIPES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static STALE_TEXT_WIPES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Number of `KeyGuard` wipes on this thread (G3).
#[cfg(test)]
pub fn key_wipes() -> usize {
    KEY_WIPES.with(|c| c.get())
}

/// Number of stale Text Mode results wiped on this thread (G10).
#[cfg(test)]
pub fn stale_text_wipes() -> usize {
    STALE_TEXT_WIPES.with(|c| c.get())
}

/// The screens of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Scan,
    Review,
    Mask,
    Restore,
    Sessions,
    TextMode,
    Help,
}

impl Screen {
    pub const ALL: [Screen; 8] = [
        Screen::Unlock,
        Screen::Scan,
        Screen::Review,
        Screen::Mask,
        Screen::Restore,
        Screen::Sessions,
        Screen::TextMode,
        Screen::Help,
    ];
}

/// Why an action was refused or failed. Messages never hold values.
#[derive(Debug)]
pub enum GuiError {
    Locked,
    Busy,
    LockFirst,
    NoScan,
    ReviewNotConfirmed,
    ConfirmRequired,
    PassphraseMismatch,
    VaultExists,
    UnknownFinding,
    UnknownSession,
    NoDefaultPath,
    RelativePath,
    NetworkPath,
    PathUnresolved,
    VaultInProject,
    ProfileInProject,
    WorkerStopped,
    /// `DISPLAY` is not a live local X server (D105, D109; Linux only).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    RemoteDisplay,
    Core(CoreError),
    /// The vault on disk may differ from memory (D67): it was locked.
    Reopen(CoreError),
}

impl From<CoreError> for GuiError {
    fn from(e: CoreError) -> Self {
        GuiError::Core(e)
    }
}

impl fmt::Display for GuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            GuiError::Locked => "the vault is locked; unlock it first",
            GuiError::Busy => "still working on the previous action",
            GuiError::LockFirst => "lock the vault before choosing another vault file",
            GuiError::NoScan => "scan a folder first",
            GuiError::ReviewNotConfirmed => "review the findings and confirm before masking",
            GuiError::ConfirmRequired => "this needs confirmation",
            GuiError::PassphraseMismatch => "the passphrases do not match",
            GuiError::VaultExists => "a vault already exists at this path; open it instead",
            GuiError::UnknownFinding => "finding not found; scan again",
            GuiError::UnknownSession => "session not found",
            GuiError::NoDefaultPath => "no default location on this system; choose a file",
            GuiError::RelativePath => "the path is relative: use Browse… or a full path",
            GuiError::NetworkPath => "network and device paths are not supported",
            GuiError::PathUnresolved => {
                "could not check that this path is outside the project folder; choose another path"
            }
            GuiError::VaultInProject => "keep the vault outside the project folder",
            GuiError::ProfileInProject => "keep the profile outside the project folder",
            GuiError::WorkerStopped => "the background worker stopped; restart Veilcode",
            GuiError::RemoteDisplay => {
                "DISPLAY does not name a running local X server, so Veilcode did not start \
                 (with such a value the display library may connect over TCP). Unset DISPLAY to \
                 use Wayland, or start a local X server"
            }
            GuiError::Core(e) => return write!(f, "{e}"),
            GuiError::Reopen(e) => {
                return write!(
                    f,
                    "{e}. The vault was locked: unlock it again to see its state"
                );
            }
        };
        f.write_str(msg)
    }
}

/// Owns the unlocked vault. Wiping (or dropping) it drops the `Vault`,
/// whose key and values are zeroized by the core types.
pub struct KeyGuard(Vault);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        KEY_WIPES.with(|c| c.set(c.get() + 1));
    }
}

enum VaultState {
    Locked,
    Unlocked(KeyGuard),
    /// The vault is with a running job.
    InWorker,
}

/// What a finished job produced.
enum Done {
    Unlocked(usize),
    Scanned(PathBuf, ScanReport),
    Masked(MaskReport, PathBuf, Option<PathBuf>),
    Restored(RestoreReport, PathBuf),
    Notice(String),
    TextMasked(String),
    TextRestored(String, RestoreReport),
}

/// A job's result, tagged with the lock epoch it was started in.
pub struct Outcome {
    epoch: u64,
    guard: Option<KeyGuard>,
    result: Result<Done, GuiError>,
}

/// The review state of the current scan (D80).
struct ScanState {
    input: PathBuf,
    report: ScanReport,
    /// Non-ignored findings the user unticked.
    unticked: BTreeSet<String>,
    confirmed: bool,
    /// This scan was masked (the rail shows Review and Mask done).
    masked: bool,
}

impl ScanState {
    fn ticked(&self) -> BTreeSet<String> {
        let ticked = |f: &&Finding| f.ignored.is_none() && !self.unticked.contains(&f.id);
        self.report
            .findings
            .iter()
            .filter(ticked)
            .map(|f| f.id.clone())
            .collect()
    }
}

/// A separate per-project vault for one mask (D64).
pub struct SeparateVault {
    pub path: PathBuf,
    pub pass: SecretString,
    /// Must equal `pass` when the vault is created.
    pub confirm: SecretString,
}

/// Mask screen options.
pub struct MaskForm {
    pub ttl_days: u32,
    pub separate_vault: Option<SeparateVault>,
}

impl Default for MaskForm {
    fn default() -> Self {
        MaskForm {
            ttl_days: MaskOptions::default().ttl_days,
            separate_vault: None,
        }
    }
}

/// Text Mode buffers: the only place real values may be shown (SPEC §10.4).
#[derive(Default)]
pub struct TextBuffers {
    pub input: String,
    pub output: String,
    /// The output holds restored secrets (show the clipboard warning).
    pub output_restored: bool,
}

impl TextBuffers {
    fn wipe(&mut self) {
        wipe_string(std::mem::take(&mut self.input));
        wipe_string(std::mem::take(&mut self.output));
        self.output_restored = false;
    }
}

/// Zeroizes a string's buffer by handing it to a core secret type.
pub fn wipe_string(s: String) {
    drop(SecretBytes::new(s.into_bytes()));
}

/// The whole app state.
pub struct AppState {
    pub screen: Screen,
    pub text: TextBuffers,
    vault: VaultState,
    vault_path: Option<PathBuf>,
    profile_path: Option<PathBuf>,
    runner: Box<dyn Runner<Outcome>>,
    pending: bool,
    epoch: u64,
    /// Set by every lock; the app then wipes its forms and egui memory.
    just_locked: bool,
    clock: Box<dyn Clock>,
    idle: IdleTimer,
    scan: Option<ScanState>,
    mask_result: Option<MaskView>,
    restore_result: Option<RestoreView>,
    text_report: Option<RestoreView>,
    error: Option<GuiError>,
    notice: Option<String>,
}

#[cfg(test)]
mod tests;

impl AppState {
    /// A locked state using the default vault and profile paths.
    pub fn new(runner: Box<dyn Runner<Outcome>>, clock: Box<dyn Clock>) -> Self {
        let idle = IdleTimer::new(clock.now_unix());
        AppState {
            screen: Screen::Unlock,
            text: TextBuffers::default(),
            vault: VaultState::Locked,
            vault_path: None,
            profile_path: None,
            runner,
            pending: false,
            epoch: 0,
            just_locked: false,
            clock,
            idle,
            scan: None,
            mask_result: None,
            restore_result: None,
            text_report: None,
            error: None,
            notice: None,
        }
    }

    /// True while a vault is open (also while a job holds it).
    pub fn is_unlocked(&self) -> bool {
        !matches!(self.vault, VaultState::Locked)
    }

    /// True while a job runs.
    pub fn is_busy(&self) -> bool {
        self.pending
    }

    /// Shows the result of a refused action.
    pub fn report(&mut self, result: Result<(), GuiError>) {
        if let Err(e) = result {
            self.notice = None;
            self.error = Some(e);
        }
    }

    /// The last error, if any.
    pub fn error(&self) -> Option<&GuiError> {
        self.error.as_ref()
    }

    /// The last informational message, if any.
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    /// The chosen profile file (`None`: the default).
    pub fn profile_path(&self) -> Option<&Path> {
        self.profile_path.as_deref()
    }

    /// Chooses the vault file (a per-project vault, D64); only while locked.
    pub fn set_vault_path(&mut self, path: Option<PathBuf>) -> Result<(), GuiError> {
        if self.is_unlocked() {
            return Err(GuiError::LockFirst);
        }
        self.vault_path = path;
        Ok(())
    }

    /// Chooses the profile file (a per-project profile, D74). The current
    /// scan, if any, needs a new review.
    pub fn set_profile_path(&mut self, path: Option<PathBuf>) -> Result<(), GuiError> {
        if self.pending {
            return Err(GuiError::Busy);
        }
        self.profile_path = path;
        if let Some(scan) = &mut self.scan {
            scan.confirmed = false;
        }
        Ok(())
    }

    /// Locks now: drops (and so zeroizes) the vault and every view that
    /// came from it, and wipes the Text Mode buffers. A running job's
    /// result is discarded when it arrives.
    pub fn lock(&mut self) {
        self.epoch += 1;
        self.just_locked = true;
        self.vault = VaultState::Locked;
        self.scan = None;
        self.mask_result = None;
        self.restore_result = None;
        self.text_report = None;
        self.text.wipe();
        self.screen = Screen::Unlock;
    }

    /// True once after any lock (D106): the caller wipes UI copies.
    pub fn take_just_locked(&mut self) -> bool {
        std::mem::take(&mut self.just_locked)
    }

    /// Records user input (resets the idle timer).
    pub fn note_input(&mut self) {
        self.idle.reset(self.clock.now_unix());
    }

    /// Called every frame and on a timer: applies finished jobs and
    /// auto-locks after `IDLE_LIMIT_SECS` without input (D100).
    pub fn tick(&mut self) {
        self.poll();
        if self.is_unlocked() && self.idle.expired(self.clock.now_unix()) {
            self.lock();
            self.notice = Some(format!(
                "locked after {} minutes without input",
                IDLE_LIMIT_SECS / 60
            ));
        }
    }

    /// Applies a finished job, if any. Never blocks.
    pub fn poll(&mut self) {
        if !self.pending {
            return;
        }
        match self.runner.try_take() {
            None => {}
            Some(Ok(outcome)) => {
                self.pending = false;
                self.apply(outcome);
            }
            Some(Err(_)) => {
                self.pending = false;
                self.lock();
                self.error = Some(GuiError::WorkerStopped);
            }
        }
    }

    fn apply(&mut self, o: Outcome) {
        if o.epoch != self.epoch {
            discard(o);
            return;
        }
        if let Some(guard) = o.guard {
            self.vault = VaultState::Unlocked(guard);
        }
        match o.result {
            Ok(done) => self.apply_done(done),
            Err(e) if self.needs_reopen(&e) => {
                self.lock();
                self.error = Some(e);
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// D67: a failed forget-save leaves memory ahead of disk.
    fn needs_reopen(&self, e: &GuiError) -> bool {
        matches!(e, GuiError::Reopen(_))
    }

    fn apply_done(&mut self, done: Done) {
        match done {
            Done::Unlocked(expired) => {
                self.idle.reset(self.clock.now_unix());
                self.screen = Screen::Scan;
                if expired > 0 {
                    self.notice = Some(format!("{expired} expired sessions removed"));
                }
            }
            Done::Scanned(input, report) => self.apply_scan(input, report),
            Done::Masked(r, out, vault) => {
                let vault = vault.map(|p| p.display().to_string());
                let out = out.display().to_string();
                self.mask_result = Some(viewmodel::mask_view(&r, out, vault));
                if let Some(scan) = &mut self.scan {
                    scan.confirmed = false;
                    scan.masked = true;
                }
            }
            Done::Restored(r, out) => {
                let out = Some(out.display().to_string());
                self.restore_result = Some(viewmodel::restore_view(&r, out));
            }
            Done::Notice(msg) => self.notice = Some(msg),
            Done::TextMasked(text) => self.set_text_output(text, None),
            Done::TextRestored(text, r) => self.set_text_output(text, Some(&r)),
        }
    }

    fn apply_scan(&mut self, input: PathBuf, report: ScanReport) {
        let mut unticked = match self.scan.take() {
            Some(old) if old.input == input => old.unticked,
            _ => BTreeSet::new(),
        };
        unticked.retain(|id| report.findings.iter().any(|f| &f.id == id));
        self.scan = Some(ScanState {
            input,
            report,
            unticked,
            confirmed: false,
            masked: false,
        });
    }

    fn set_text_output(&mut self, text: String, report: Option<&RestoreReport>) {
        wipe_string(std::mem::replace(&mut self.text.output, text));
        self.text.output_restored = report.is_some();
        self.text_report = report.map(|r| viewmodel::restore_view(r, None));
    }

    /// The review model of the current scan.
    pub fn review(&self) -> Option<ReviewView> {
        let scan = self.scan.as_ref()?;
        Some(viewmodel::review_view(
            &scan.report.findings,
            &scan.ticked(),
        ))
    }

    /// The scanned folder, the number of scanned files and of findings.
    pub fn scan_summary(&self) -> Option<(&Path, usize, usize)> {
        let s = self.scan.as_ref()?;
        Some((
            &s.input,
            s.report.scanned_files.len(),
            s.report.findings.len(),
        ))
    }

    /// True once the review of the current scan is confirmed.
    pub fn review_confirmed(&self) -> bool {
        self.scan.as_ref().is_some_and(|s| s.confirmed)
    }

    /// The last mask result.
    pub fn mask_view(&self) -> Option<MaskView> {
        self.mask_result.clone()
    }

    /// The last restore result.
    pub fn restore_view(&self) -> Option<RestoreView> {
        self.restore_result.clone()
    }

    /// Counts of the last Text Mode restore.
    pub fn text_report(&self) -> Option<&RestoreView> {
        self.text_report.as_ref()
    }

    /// The Sessions screen model (D63). Reads memory only.
    pub fn sessions(&self) -> Result<SessionsView, GuiError> {
        let v = self.vault_ref()?;
        let now = self.clock.now_unix();
        Ok(viewmodel::sessions_view(v.sessions(), &v.status(), now))
    }

    fn vault_ref(&self) -> Result<&Vault, GuiError> {
        match &self.vault {
            VaultState::Locked => Err(GuiError::Locked),
            VaultState::InWorker => Err(GuiError::Busy),
            VaultState::Unlocked(g) => Ok(&g.0),
        }
    }

    /// The vault's session id whose text is `id`.
    fn session_id(&self, id: &str) -> Result<SessionId, GuiError> {
        let v = self.vault_ref()?;
        let s = v.sessions().iter().find(|s| s.id.as_str() == id);
        s.map(|s| s.id.clone()).ok_or(GuiError::UnknownSession)
    }

    fn vault_file(&self) -> Result<PathBuf, GuiError> {
        let path = self.vault_path.clone().or_else(default_vault_path);
        let path = path.ok_or(GuiError::NoDefaultPath)?;
        check_local(&path)?;
        check_absolute(&path)?;
        Ok(path)
    }

    fn profile_file(&self) -> Result<PathBuf, GuiError> {
        let path = self.profile_path.clone().or_else(default_profile_path);
        let path = path.ok_or(GuiError::NoDefaultPath)?;
        check_local(&path)?;
        check_absolute(&path)?;
        Ok(path)
    }
}

/// Scans `input` with the profile at `profile` (read fresh from disk).
fn scan_job(input: PathBuf, profile: &Path) -> Result<Done, GuiError> {
    let p = Profile::load(profile)?;
    let report = veilcode_core::scan(&input, &ScanOptions::default(), &p)?;
    Ok(Done::Scanned(input, report))
}

/// The ticked findings as an explicit selection (D51, D78).
fn selection(scan: &ScanState) -> Selection {
    Selection::Ids(scan.ticked())
}

/// Actions: each checks the state, then queues one job.
impl AppState {
    /// Opens the vault file.
    pub fn unlock(&mut self, pass: SecretString) -> Result<(), GuiError> {
        self.start_unlock(pass, None)
    }

    /// Creates a new vault file (written on the first mask).
    pub fn create_vault(
        &mut self,
        pass: SecretString,
        confirm: SecretString,
    ) -> Result<(), GuiError> {
        self.start_unlock(pass, Some(confirm))
    }

    fn start_unlock(
        &mut self,
        pass: SecretString,
        confirm: Option<SecretString>,
    ) -> Result<(), GuiError> {
        if self.pending {
            return Err(GuiError::Busy);
        }
        if confirm.as_ref().is_some_and(|c| *c != pass) {
            return Err(GuiError::PassphraseMismatch);
        }
        let path = self.vault_file()?;
        if confirm.is_some() {
            check_new_vault(&path)?;
        }
        if self.is_unlocked() {
            self.lock();
        }
        let epoch = self.epoch;
        let create = confirm.is_some();
        self.dispatch(Box::new(move || {
            let (guard, result) = match open_or_create(&path, &pass, create) {
                Ok(v) => {
                    let expired = v.expired_removed();
                    (Some(KeyGuard(v)), Ok(Done::Unlocked(expired)))
                }
                Err(e) => (None, Err(e)),
            };
            Outcome {
                epoch,
                guard,
                result,
            }
        }))
    }

    /// Scans `input` with the current profile.
    pub fn scan(&mut self, input: PathBuf) -> Result<(), GuiError> {
        self.ready()?;
        let profile = self.profile_file()?;
        check_local(&input)?;
        self.keep_outside(&input)?;
        self.run_plain(move || scan_job(input, &profile))
    }

    /// Ticks or unticks one finding; the review must be confirmed again.
    pub fn set_ticked(&mut self, id: &str, ticked: bool) -> Result<(), GuiError> {
        let scan = self.scan.as_mut().ok_or(GuiError::NoScan)?;
        if !scan.report.findings.iter().any(|f| f.id == id) {
            return Err(GuiError::UnknownFinding);
        }
        if ticked {
            scan.unticked.remove(id);
        } else {
            scan.unticked.insert(id.to_string());
        }
        scan.confirmed = false;
        Ok(())
    }

    /// Remembers a finding as a false positive in its file or, by key name,
    /// everywhere; "everywhere" needs `confirmed` (D80). Saves and re-scans.
    pub fn remember(&mut self, id: &str, scope: Scope, confirmed: bool) -> Result<(), GuiError> {
        self.ready()?;
        if scope == Scope::Everywhere && !confirmed {
            return Err(GuiError::ConfirmRequired);
        }
        let f = self.finding(id)?;
        self.edit_profile(move |p| p.ignore_finding(&f, scope))
    }

    /// Stops ignoring a finding; it is ticked again. Saves and re-scans.
    pub fn unignore(&mut self, id: &str) -> Result<(), GuiError> {
        self.ready()?;
        let f = self.finding(id)?;
        if let Some(scan) = &mut self.scan {
            scan.unticked.remove(id);
        }
        self.edit_profile(move |p| p.unignore_finding(&f))
    }

    /// Adds a key name to `extra_keys`, saves and re-scans (D80).
    pub fn add_key(&mut self, name: &str) -> Result<(), GuiError> {
        self.ready()?;
        let name = name.trim().to_string();
        self.edit_profile(move |p| p.add_extra_key(&name))
    }

    fn finding(&self, id: &str) -> Result<Finding, GuiError> {
        let scan = self.scan.as_ref().ok_or(GuiError::NoScan)?;
        let f = scan.report.findings.iter().find(|f| f.id == id);
        f.cloned().ok_or(GuiError::UnknownFinding)
    }

    fn edit_profile(
        &mut self,
        edit: impl FnOnce(&mut Profile) -> Result<bool, CoreError> + Send + 'static,
    ) -> Result<(), GuiError> {
        let input = self.scan.as_ref().ok_or(GuiError::NoScan)?.input.clone();
        let path = self.profile_file()?;
        self.keep_outside(&input)?;
        self.run_plain(move || {
            let mut p = Profile::load(&path)?;
            if edit(&mut p)? {
                p.save(&path)?;
            }
            scan_job(input, &path)
        })
    }

    /// Confirms the review; returns the confirm label ("Mask N secrets").
    pub fn confirm_review(&mut self) -> Result<String, GuiError> {
        let scan = self.scan.as_mut().ok_or(GuiError::NoScan)?;
        scan.confirmed = true;
        Ok(viewmodel::confirm_label(scan.ticked().len()))
    }

    /// Masks the ticked findings into the new folder `out`. Refused until
    /// the review is confirmed (D80).
    pub fn mask(&mut self, out: PathBuf, form: MaskForm) -> Result<(), GuiError> {
        self.ready()?;
        let scan = self.scan.as_ref().ok_or(GuiError::NoScan)?;
        check_local(&out)?;
        self.keep_outside(&scan.input)?;
        if let Some(sv) = &form.separate_vault {
            check_local(&sv.path)?;
            check_absolute(&sv.path)?;
            check_outside(&sv.path, &scan.input, GuiError::VaultInProject)?;
            check_outside(&sv.path, &out, GuiError::VaultInProject)?;
        }
        if !scan.confirmed {
            return Err(GuiError::ReviewNotConfirmed);
        }
        let job = MaskJob {
            report: scan.report.clone(),
            selection: selection(scan),
            input: scan.input.clone(),
            out,
            opts: MaskOptions {
                ttl_days: form.ttl_days,
                ..MaskOptions::default()
            },
        };
        match form.separate_vault {
            Some(sv) => self.run_plain(move || job.run_separate(sv)),
            None => self.run_vault(move |v| job.run(v, None)),
        }
    }

    /// Restores `input` into the new folder `out` (SPEC §6.2); `session`
    /// is a session id (default: the newest).
    pub fn restore(
        &mut self,
        input: PathBuf,
        out: PathBuf,
        session: Option<String>,
        keep: bool,
    ) -> Result<(), GuiError> {
        self.ready()?;
        check_local(&input)?;
        check_local(&out)?;
        self.keep_outside(&input)?;
        let session = session.map(|s| self.session_id(&s)).transpose()?;
        let (profile, vault) = (self.profile_file()?, self.vault_file()?);
        self.run_vault(move |v| {
            let p = Profile::load(&profile)?;
            let r = veilcode_core::restore(&input, &out, v, session.as_ref(), keep, &p);
            r.map(|r| Done::Restored(r, out))
                .map_err(|e| forget_error(e, &vault))
        })
    }

    /// Deletes one session (D63).
    pub fn delete_session(&mut self, id: &str) -> Result<(), GuiError> {
        self.ready()?;
        let id = self.session_id(id)?;
        self.run_vault(move |v| {
            v.delete_session(&id)?;
            Ok(Done::Notice("session deleted".to_string()))
        })
    }

    /// Removes every session and the vault file; needs `confirmed` (D63).
    pub fn purge(&mut self, confirmed: bool) -> Result<(), GuiError> {
        self.ready()?;
        if !confirmed {
            return Err(GuiError::ConfirmRequired);
        }
        self.run_vault(|v| {
            let r = v.purge()?;
            let msg = format!(
                "{} sessions and {} entries removed",
                r.sessions_removed, r.entries_removed
            );
            Ok(Done::Notice(msg))
        })
    }

    /// Masks the Text Mode input (SPEC §6.3).
    pub fn mask_text(&mut self) -> Result<(), GuiError> {
        self.ready()?;
        let text = self.text.input.clone();
        self.run_vault(move |v| {
            let r = veilcode_core::mask_text(&text, v);
            wipe_string(text);
            Ok(Done::TextMasked(r?.0))
        })
    }

    /// Restores the Text Mode input against the newest text session.
    pub fn restore_text(&mut self, keep: bool) -> Result<(), GuiError> {
        self.ready()?;
        let text = self.text.input.clone();
        let vault = self.vault_file()?;
        self.run_vault(move |v| {
            let r = veilcode_core::restore_text(&text, v, None, keep);
            wipe_string(text);
            let (out, report) = r.map_err(|e| forget_error(e, &vault))?;
            Ok(Done::TextRestored(out, report))
        })
    }

    /// Unlocked, and no job running.
    fn ready(&self) -> Result<(), GuiError> {
        match self.vault {
            VaultState::Locked => Err(GuiError::Locked),
            _ if self.pending => Err(GuiError::Busy),
            VaultState::InWorker => Err(GuiError::Busy),
            VaultState::Unlocked(_) => Ok(()),
        }
    }

    /// Queues a job that does not need the vault.
    fn run_plain(
        &mut self,
        f: impl FnOnce() -> Result<Done, GuiError> + Send + 'static,
    ) -> Result<(), GuiError> {
        let epoch = self.epoch;
        self.dispatch(Box::new(move || Outcome {
            epoch,
            guard: None,
            result: f(),
        }))
    }

    /// Queues a job that takes the vault with it and hands it back.
    fn run_vault(
        &mut self,
        f: impl FnOnce(&mut Vault) -> Result<Done, GuiError> + Send + 'static,
    ) -> Result<(), GuiError> {
        let mut guard = match std::mem::replace(&mut self.vault, VaultState::InWorker) {
            VaultState::Unlocked(g) => g,
            other => {
                self.vault = other;
                return Err(GuiError::Locked);
            }
        };
        let epoch = self.epoch;
        self.dispatch(Box::new(move || {
            let result = f(&mut guard.0);
            Outcome {
                epoch,
                guard: Some(guard),
                result,
            }
        }))
    }

    fn dispatch(&mut self, job: Job<Outcome>) -> Result<(), GuiError> {
        self.error = None;
        self.notice = None;
        match self.runner.submit(job) {
            Ok(()) => {
                self.pending = true;
                Ok(())
            }
            Err(_) => {
                // The job, and any vault in it, was dropped with the send.
                self.lock();
                Err(GuiError::WorkerStopped)
            }
        }
    }
}

/// Opens the vault at `path`, or creates it (refusing to replace a file).
fn open_or_create(path: &Path, pass: &SecretString, create: bool) -> Result<Vault, GuiError> {
    if !create {
        return Ok(Vault::open(path, pass)?);
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(GuiError::VaultExists);
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| CoreError::Io {
            path: parent.to_path_buf(),
            kind: e.kind(),
        })?;
    }
    Ok(Vault::create(path, pass)?)
}

/// Drops a result that arrived after a lock (D106). The guard zeroizes on
/// drop; Text Mode output is a plain `String`, so it is wiped first.
fn discard(o: Outcome) {
    if let Ok(Done::TextRestored(text, _) | Done::TextMasked(text)) = o.result {
        wipe_string(text);
        #[cfg(test)]
        STALE_TEXT_WIPES.with(|c| c.set(c.get() + 1));
    }
}

/// D67: a failed save or removal of the vault after a restore wrote its
/// output means memory and disk differ, so the vault must be reopened.
fn forget_error(e: CoreError, vault: &Path) -> GuiError {
    let at_vault = match &e {
        CoreError::VaultChanged | CoreError::SaveLocked => true,
        CoreError::Io { path, .. } => path == vault || is_tmp_of(path, vault),
        _ => false,
    };
    if at_vault {
        GuiError::Reopen(e)
    } else {
        GuiError::Core(e)
    }
}

fn is_tmp_of(path: &Path, vault: &Path) -> bool {
    let mut tmp = vault.as_os_str().to_owned();
    tmp.push(".tmp");
    path == Path::new(&tmp)
}

/// Everything one mask needs, moved into the job.
struct MaskJob {
    report: ScanReport,
    selection: Selection,
    input: PathBuf,
    out: PathBuf,
    opts: MaskOptions,
}

impl MaskJob {
    fn run(self, v: &mut Vault, separate: Option<PathBuf>) -> Result<Done, GuiError> {
        let r = veilcode_core::mask(
            &self.report,
            &self.selection,
            &self.input,
            &self.out,
            v,
            &self.opts,
        )?;
        Ok(Done::Masked(r, self.out, separate))
    }

    /// Masks into a separate per-project vault, opened or created here.
    fn run_separate(self, sv: SeparateVault) -> Result<Done, GuiError> {
        let exists = std::fs::symlink_metadata(&sv.path).is_ok();
        if !exists && sv.pass != sv.confirm {
            return Err(GuiError::PassphraseMismatch);
        }
        let mut vault = open_or_create(&sv.path, &sv.pass, !exists)?;
        drop(sv.pass);
        self.run(&mut vault, Some(sv.path))
    }
}

/// Minimum passphrase length in characters, counted as core counts it
/// (Unicode scalar values, D8). Core's constant is private.
const MIN_PASSPHRASE_CHARS: usize = 12;

/// The tooltip of a tab that needs an open vault (D127).
pub const LOCKED_HINT: &str = "Create or open a vault first";

impl Screen {
    /// Every screen except Unlock and Help needs an open vault.
    pub fn needs_vault(self) -> bool {
        !matches!(self, Screen::Unlock | Screen::Help)
    }
}

impl AppState {
    /// Why the tab of `s` is disabled, if it is (D127).
    pub fn tab_hint(&self, s: Screen) -> Option<&'static str> {
        (!self.is_unlocked() && s.needs_vault()).then_some(LOCKED_HINT)
    }

    /// The screen to draw: Unlock while a locked screen is selected.
    pub fn shown_screen(&self) -> Screen {
        match self.tab_hint(self.screen) {
            Some(_) => Screen::Unlock,
            None => self.screen,
        }
    }

    /// The step rail (D131).
    pub fn rail(&self) -> WorkflowRail {
        let scan = self.scan.as_ref();
        viewmodel::workflow_rail(&Progress {
            unlocked: self.is_unlocked(),
            scanned: scan.is_some(),
            confirmed: scan.is_some_and(|s| s.confirmed),
            masked: scan.is_some_and(|s| s.masked),
            restored: self.restore_result.is_some(),
        })
    }

    /// The card after the current scan.
    pub fn scan_card(&self) -> Option<ResultCard> {
        let (input, files, findings) = self.scan_summary()?;
        let input = input.display().to_string();
        Some(viewmodel::scan_card(&input, files, findings))
    }

    /// The card after the last mask.
    pub fn mask_card(&self) -> Option<ResultCard> {
        self.mask_view().as_ref().map(viewmodel::mask_card)
    }

    /// The card after the last folder restore.
    pub fn restore_card(&self) -> Option<ResultCard> {
        self.restore_result.as_ref().map(viewmodel::restore_card)
    }

    /// The last error as a card.
    pub fn error_card(&self) -> Option<ResultCard> {
        self.error().map(|e| viewmodel::error_card(e.to_string()))
    }

    /// Goes to the screen of `step` ("Next: <step>", a rail click), if its
    /// tab is enabled. The Unlock screen is hidden while unlocked.
    pub fn go_to(&mut self, step: Step) {
        let screen = step_screen(step);
        let hidden = screen == Screen::Unlock && self.is_unlocked();
        if !hidden && self.tab_hint(screen).is_none() {
            self.screen = screen;
        }
    }

    /// D126: the vault and profile files must not be inside `folder`.
    fn keep_outside(&self, folder: &Path) -> Result<(), GuiError> {
        check_outside(&self.vault_file()?, folder, GuiError::VaultInProject)?;
        check_outside(&self.profile_file()?, folder, GuiError::ProfileInProject)
    }
}

/// The screen of a rail step.
pub fn step_screen(step: Step) -> Screen {
    match step {
        Step::Vault => Screen::Unlock,
        Step::Scan => Screen::Scan,
        Step::Review => Screen::Review,
        Step::Mask => Screen::Mask,
        Step::Restore => Screen::Restore,
    }
}

/// D128: every reason the Create button is disabled, in display order.
/// `path` is the vault file to create (`None`: no default location). The
/// filesystem is asked only when the path changes (D130), never for a
/// network or device path.
pub fn create_problems(
    path: Option<&Path>,
    pass: &str,
    confirm: &str,
    cache: &mut ExistsCache,
) -> Vec<GuiError> {
    let mut problems = Vec::new();
    match path.map(|p| check_local(p).and_then(|()| check_absolute(p)).map(|()| p)) {
        None => problems.push(GuiError::NoDefaultPath),
        Some(Err(e)) => problems.push(e),
        Some(Ok(p)) if cache.exists(p) => problems.push(GuiError::VaultExists),
        Some(Ok(_)) => {}
    }
    if pass.chars().count() < MIN_PASSPHRASE_CHARS {
        problems.push(GuiError::Core(CoreError::PassphraseTooShort));
    }
    if pass != confirm {
        problems.push(GuiError::PassphraseMismatch);
    }
    problems
}

/// Whether the last asked path exists, re-checked only when it changes
/// (D130: no filesystem call every frame). Submit always checks again.
#[derive(Default)]
pub struct ExistsCache {
    last: Option<(PathBuf, bool)>,
    #[cfg(test)]
    checks: usize,
}

impl ExistsCache {
    fn exists(&mut self, p: &Path) -> bool {
        match &self.last {
            Some((q, exists)) if q == p => *exists,
            _ => {
                #[cfg(test)]
                {
                    self.checks += 1;
                }
                let exists = std::fs::symlink_metadata(p).is_ok();
                self.last = Some((p.to_path_buf(), exists));
                exists
            }
        }
    }

    /// Number of filesystem checks made (D130 test).
    #[cfg(test)]
    pub fn fs_checks(&self) -> usize {
        self.checks
    }
}

/// D130: refuses network and device paths as text, before any filesystem
/// call: two leading separators (`\\server`, `//host`, `\\?\UNC\`, `\\.\`)
/// or `\??\`. Only the verbatim local-disk form `\\?\X:\` is allowed.
pub fn check_local(p: &Path) -> Result<(), GuiError> {
    let s = p.as_os_str().as_encoded_bytes();
    let sep = |b: Option<&u8>| matches!(b, Some(b'\\' | b'/'));
    let verbatim_disk = s.len() >= 7
        && s.starts_with(br"\\?\")
        && s[4].is_ascii_alphabetic()
        && s[5] == b':'
        && s[6] == b'\\';
    let unc_like = sep(s.first()) && sep(s.get(1));
    if (unc_like && !verbatim_disk) || s.starts_with(br"\??\") {
        Err(GuiError::NetworkPath)
    } else {
        Ok(())
    }
}

/// D126: a vault or profile path must be absolute (typed relative paths
/// would depend on the folder the app was started from).
pub fn check_absolute(path: &Path) -> Result<(), GuiError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(GuiError::RelativePath)
    }
}

/// D126, D28: Create refuses any existing path (file, folder or link).
pub fn check_new_vault(path: &Path) -> Result<(), GuiError> {
    check_local(path)?;
    check_absolute(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(GuiError::VaultExists),
        Err(_) => Ok(()),
    }
}

/// D126, D130: refuses `file` (with `err`) when it is inside `folder`,
/// also compared case-insensitively. Fails closed: when `folder` resolves
/// but `file` cannot be resolved, it is refused too. A `folder` that does
/// not resolve is left to core, which reports it.
pub fn check_outside(file: &Path, folder: &Path, err: GuiError) -> Result<(), GuiError> {
    check_local(file)?;
    check_local(folder)?;
    let Some(folder) = resolve(folder) else {
        return Ok(());
    };
    let file = resolve(file).ok_or(GuiError::PathUnresolved)?;
    let lower = |p: &Path| -> Vec<String> {
        let parts = p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase());
        parts.collect()
    };
    if file.starts_with(&folder) || lower(&file).starts_with(&lower(&folder)) {
        Err(err)
    } else {
        Ok(())
    }
}

/// `p` with links and `..` resolved by the OS as far as it exists; the
/// missing rest is resolved lexically. `None` when an entry exists but
/// cannot be resolved (a dangling link, a file used as a folder, no
/// access), so a caller can fail closed.
fn resolve(p: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let (mut tail, mut skip, mut cur) = (Vec::new(), 0usize, p);
    loop {
        match std::fs::canonicalize(cur) {
            Ok(real) => return Some(tail.iter().rev().fold(real, |acc, name| acc.join(name))),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return None,
            Err(_) if std::fs::symlink_metadata(cur).is_ok() => return None,
            Err(_) => {}
        }
        let (parent, last) = (cur.parent()?, cur.components().next_back()?);
        match last {
            Component::ParentDir => skip += 1,
            Component::Normal(_) if skip > 0 => skip -= 1,
            Component::Normal(name) => tail.push(name),
            _ => {}
        }
        cur = parent;
    }
}

/// D126: Create suggests the default vault file (D81).
pub fn suggested_vault_path() -> Option<PathBuf> {
    default_vault_path()
}

/// The nearest folder of `p` (or `p` itself) that exists: where a picker
/// opens, since the default folders may not exist yet.
pub fn existing_ancestor(p: &Path) -> Option<PathBuf> {
    p.ancestors().find(|a| a.is_dir()).map(Path::to_path_buf)
}
