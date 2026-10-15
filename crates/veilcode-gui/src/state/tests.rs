//! G1, G2, G3, G7 and G10: the app-state layer without a window (TEST_CASES P6).

use super::*;
use crate::app::{Forms, form_wipes, sync_lock};
use crate::test_support::{
    TestClock, assert_no_secret, fake_github_pat, fake_password, write_tree,
};
use crate::viewmodel::FindingRow;
use crate::worker::{Deferred, InlineRunner};
use std::path::Path;
use tempfile::TempDir;
use veilcode_core::IgnoreEntry;

const T0: u64 = 1_800_000_000;

struct Fixture {
    tmp: TempDir,
    input: PathBuf,
    clock: TestClock,
    pat: String,
    password: String,
    custom: String,
}

impl Fixture {
    fn new() -> Fixture {
        let tmp = TempDir::new().expect("tempdir");
        let input = tmp.path().join("project");
        let (pat, password, custom) = (fake_github_pat(), fake_password(), fake_password());
        let env = format!("DB_PASSWORD={password}\nAPP_NAME=demo\n");
        let js = format!("const token = \"{pat}\";\n");
        let yml = format!("customapi-pass: {custom}\n");
        write_tree(
            &input,
            &[
                (".env", env.as_bytes()),
                ("src/config.js", js.as_bytes()),
                ("config.yml", yml.as_bytes()),
            ],
        );
        Fixture {
            tmp,
            input,
            clock: TestClock::new(T0),
            pat,
            password,
            custom,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn profile_path(&self) -> PathBuf {
        self.path("profile.toml")
    }

    fn secrets(&self) -> Vec<String> {
        vec![self.pat.clone(), self.password.clone(), self.custom.clone()]
    }

    /// A locked state with an inline worker, the test clock and tempdir paths.
    fn state(&self) -> AppState {
        let mut s = AppState::new(
            Box::new(InlineRunner::default()),
            Box::new(self.clock.clone()),
        );
        s.set_vault_path(Some(self.path("vault.vc")))
            .expect("locked");
        s.set_profile_path(Some(self.profile_path())).expect("idle");
        s
    }

    fn unlocked(&self) -> AppState {
        let mut s = self.state();
        let pass = || SecretString::new("correct horse battery".to_string());
        done(&mut s, |s| s.create_vault(pass(), pass()));
        assert!(s.is_unlocked());
        s
    }

    fn scanned(&self) -> AppState {
        let mut s = self.unlocked();
        done(&mut s, |s| s.scan(self.input.clone()));
        s
    }
}

/// Runs `action`, expects it to be accepted, drains the worker and expects
/// no error from the job.
fn done(s: &mut AppState, action: impl FnOnce(&mut AppState) -> Result<(), GuiError>) {
    if let Err(e) = action(s) {
        panic!("action refused: {e}");
    }
    s.poll();
    if let Some(e) = s.error() {
        panic!("job failed: {e}");
    }
}

fn row<'a>(view: &'a ReviewView, rel_path: &str) -> &'a FindingRow {
    view.groups
        .iter()
        .flat_map(|g| &g.rows)
        .chain(&view.ignored)
        .find(|r| r.rel_path == rel_path)
        .unwrap_or_else(|| panic!("no row for {rel_path}"))
}

fn review(s: &AppState) -> ReviewView {
    s.review().expect("review model")
}

fn profile_on_disk(fx: &Fixture) -> Profile {
    Profile::load(&fx.profile_path()).expect("load profile")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

fn assert_all_locked(s: &mut AppState, fx: &Fixture) {
    assert!(matches!(s.scan(fx.input.clone()), Err(GuiError::Locked)));
    let form = MaskForm::default();
    assert!(matches!(s.mask(fx.path("m"), form), Err(GuiError::Locked)));
    let r = s.restore(fx.path("m"), fx.path("r"), None, false);
    assert!(matches!(r, Err(GuiError::Locked)));
    assert!(matches!(s.sessions(), Err(GuiError::Locked)));
    s.text.input = format!("DB_PASSWORD={}", fx.password);
    assert!(matches!(s.mask_text(), Err(GuiError::Locked)));
}

#[test]
fn g1_actions_fail_while_locked_and_succeed_after_unlock() {
    let fx = Fixture::new();
    let mut s = fx.state();
    assert_all_locked(&mut s, &fx);
    let pass = || SecretString::new("correct horse battery".to_string());
    done(&mut s, |s| s.create_vault(pass(), pass()));

    done(&mut s, |s| s.scan(fx.input.clone()));
    assert_eq!(review(&s).selected, 2);
    s.confirm_review().expect("confirm");
    done(&mut s, |s| s.mask(fx.path("masked"), MaskForm::default()));
    assert_eq!(s.mask_view().expect("mask view").secrets_masked, 2);
    assert_eq!(s.sessions().expect("sessions").rows.len(), 1);
    let (masked, restored) = (fx.path("masked"), fx.path("restored"));
    done(&mut s, |s| s.restore(masked, restored, None, false));
    let rv = s.restore_view().expect("restore view");
    assert!(rv.session_forgotten);
    assert_eq!(
        read(&fx.path("restored/src/config.js")),
        read(&fx.input.join("src/config.js"))
    );
    assert_eq!(s.sessions().expect("sessions").rows.len(), 0);
    s.text.input = format!("DB_PASSWORD={}\n", fx.password);
    done(&mut s, |s| s.mask_text());
    assert!(s.text.output.starts_with("DB_PASSWORD=VEILCODE_"));
    assert_no_secret(s.text.output.as_bytes(), &[&fx.password]);

    s.lock();
    assert!(!s.is_unlocked());
    assert_all_locked(&mut s, &fx);
}

#[test]
fn g2_view_models_hold_previews_only() {
    let fx = Fixture::new();
    let mut s = fx.scanned();
    let secrets = fx.secrets();
    let mut debug = format!("{:?}", review(&s));
    s.confirm_review().expect("confirm");
    done(&mut s, |s| s.mask(fx.path("masked"), MaskForm::default()));
    debug += &format!("{:?}", s.mask_view().expect("mask view"));
    // Read the sessions model while the mask session exists, so it is not empty.
    let sessions = s.sessions().expect("sessions");
    assert_eq!(sessions.rows.len(), 1, "the mask session is listed");
    debug += &format!("{sessions:?}");
    // The "AI" adds a new secret, so restore reports it (as a preview).
    let added = fake_password();
    let new_env = format!("API_SECRET={added}\n");
    write_tree(&fx.path("masked"), &[("new/.env", new_env.as_bytes())]);
    let (masked, restored) = (fx.path("masked"), fx.path("restored"));
    done(&mut s, |s| s.restore(masked, restored, None, false));
    let rv = s.restore_view().expect("restore view");
    assert_eq!(rv.new_secrets.len(), 1);
    assert!(!rv.session_forgotten);
    debug += &format!("{rv:?}");
    debug += &format!("{:?}", s.sessions().expect("sessions"));
    assert!(debug.contains(&rv.new_secrets[0].preview));
    assert_no_secret(debug.as_bytes(), &secrets);
    assert_no_secret(debug.as_bytes(), &[&added]);
}

#[test]
fn g3_idle_auto_lock_drops_the_key() {
    let fx = Fixture::new();
    let mut s = fx.unlocked();
    s.text.input = format!("DB_PASSWORD={}\n", fx.password);
    let before = key_wipes();
    fx.clock.advance(600);
    s.tick();
    assert!(s.is_unlocked());
    assert_eq!(key_wipes(), before);
    fx.clock.advance(1);
    s.tick();
    assert!(!s.is_unlocked());
    assert_eq!(key_wipes(), before + 1);
    assert!(s.text.input.is_empty());
    assert!(matches!(s.sessions(), Err(GuiError::Locked)));
}

#[test]
fn g3_input_at_nine_minutes_resets_the_timer() {
    let fx = Fixture::new();
    let mut s = fx.unlocked();
    let before = key_wipes();
    fx.clock.advance(540);
    s.note_input();
    fx.clock.advance(61);
    s.tick();
    assert!(s.is_unlocked(), "601 s after unlock but 61 s after input");
    fx.clock.advance(539);
    s.tick();
    assert!(s.is_unlocked());
    fx.clock.advance(1);
    s.tick();
    assert!(!s.is_unlocked());
    assert_eq!(key_wipes(), before + 1);
}

#[test]
fn g7_review_lists_findings_and_ignored_section() {
    let fx = Fixture::new();
    let mut p = Profile::default();
    p.ignore_key("DB_PASSWORD").expect("ignore key");
    p.save(&fx.profile_path()).expect("save profile");
    let s = fx.scanned();
    let view = review(&s);
    let pat = row(&view, "src/config.js");
    assert_eq!((pat.line, pat.ticked, pat.ignored), (1, true, false));
    assert_eq!(pat.preview, format!("{}…({})", &fx.pat[..4], fx.pat.len()));
    assert!(view.groups.iter().any(|g| g.label == pat.key_or_rule));
    assert_eq!(view.ignored.len(), 1);
    let env = &view.ignored[0];
    assert_eq!(
        (env.rel_path.as_str(), env.key_or_rule.as_str()),
        (".env", "DB_PASSWORD")
    );
    assert_eq!((env.line, env.ticked, env.ignored), (1, false, true));
    assert_eq!(view.selected, 1);
    assert_no_secret(format!("{view:?}").as_bytes(), &fx.secrets());
}

#[test]
fn g7_untick_removes_from_selection_and_label_counts() {
    let fx = Fixture::new();
    let mut s = fx.scanned();
    assert_eq!(review(&s).confirm_label, "Mask 2 secrets");
    let id = row(&review(&s), "src/config.js").id.clone();
    s.set_ticked(&id, false).expect("untick");
    let view = review(&s);
    assert!(!row(&view, "src/config.js").ticked);
    assert_eq!(
        (view.selected, view.confirm_label.as_str()),
        (1, "Mask 1 secrets")
    );
    s.confirm_review().expect("confirm");
    done(&mut s, |s| s.mask(fx.path("masked"), MaskForm::default()));
    assert_eq!(s.mask_view().expect("mask view").secrets_masked, 1);
    assert!(read(&fx.path("masked/src/config.js")).contains(&fx.pat));
    assert_no_secret(read(&fx.path("masked/.env")).as_bytes(), &[&fx.password]);
}

#[test]
fn g7_remember_this_file_and_everywhere_use_profile_scopes() {
    let fx = Fixture::new();
    let mut s = fx.scanned();
    let id = row(&review(&s), ".env").id.clone();
    done(&mut s, |s| s.remember(&id, Scope::ThisFile, false));
    let entry = IgnoreEntry {
        rel_path: ".env".to_string(),
        key_name: Some("DB_PASSWORD".to_string()),
        rule_id: None,
    };
    assert_eq!(profile_on_disk(&fx).ignored(), &[entry]);
    assert!(profile_on_disk(&fx).ignored_keys().is_empty());
    assert!(row(&review(&s), ".env").ignored);
    done(&mut s, |s| s.unignore(&id));
    let refused = s.remember(&id, Scope::Everywhere, false);
    assert!(matches!(refused, Err(GuiError::ConfirmRequired)));
    assert_eq!(profile_on_disk(&fx), Profile::default());
    done(&mut s, |s| s.remember(&id, Scope::Everywhere, true));
    assert_eq!(
        profile_on_disk(&fx).ignored_keys(),
        &["DB_PASSWORD".to_string()]
    );
    assert!(profile_on_disk(&fx).ignored().is_empty());
    let env = row(&review(&s), ".env").clone();
    assert_eq!((env.ignored, env.ticked), (true, false));
}

#[test]
fn g7_unignore_reticks_the_finding() {
    let fx = Fixture::new();
    let mut s = fx.scanned();
    let id = row(&review(&s), ".env").id.clone();
    done(&mut s, |s| s.remember(&id, Scope::ThisFile, false));
    assert_eq!(review(&s).selected, 1);
    done(&mut s, |s| s.unignore(&id));
    let env = row(&review(&s), ".env").clone();
    assert_eq!((env.ignored, env.ticked), (false, true));
    assert_eq!(review(&s).selected, 2);
    assert_eq!(profile_on_disk(&fx), Profile::default());
}

#[test]
fn g7_add_key_name_saves_and_rescans() {
    let fx = Fixture::new();
    let mut s = fx.scanned();
    let has_yml = |v: &ReviewView| {
        v.groups
            .iter()
            .flat_map(|g| &g.rows)
            .any(|r| r.rel_path == "config.yml")
    };
    assert!(!has_yml(&review(&s)));
    done(&mut s, |s| s.add_key("customapi-pass"));
    assert_eq!(
        profile_on_disk(&fx).extra_keys(),
        &["customapi-pass".to_string()]
    );
    let view = review(&s);
    let ini = row(&view, "config.yml");
    assert_eq!((ini.line, ini.ticked, ini.ignored), (1, true, false));
    assert_eq!(view.selected, 3);
    assert_no_secret(format!("{view:?}").as_bytes(), &fx.secrets());
}

#[test]
fn g7_mask_needs_a_confirmed_review() {
    let fx = Fixture::new();
    let mut s = fx.unlocked();
    assert!(matches!(s.confirm_review(), Err(GuiError::NoScan)));
    done(&mut s, |s| s.scan(fx.input.clone()));
    let refused = s.mask(fx.path("masked"), MaskForm::default());
    assert!(matches!(refused, Err(GuiError::ReviewNotConfirmed)));
    assert!(!fx.path("masked").exists());
    s.confirm_review().expect("confirm");
    // Any re-scan (here after a profile edit) needs a new review.
    done(&mut s, |s| s.add_key("customapi-pass"));
    let refused = s.mask(fx.path("masked"), MaskForm::default());
    assert!(matches!(refused, Err(GuiError::ReviewNotConfirmed)));
    assert_eq!(s.confirm_review().expect("confirm"), "Mask 3 secrets");
    done(&mut s, |s| s.mask(fx.path("masked"), MaskForm::default()));
    assert_eq!(s.mask_view().expect("mask view").secrets_masked, 3);
}

/// G10 harness: a state on a `Deferred` runner, its forms and an egui
/// context (no window), as `VeilApp` holds them.
struct Slow {
    s: AppState,
    worker: Deferred<Outcome>,
    forms: Forms,
    ctx: eframe::egui::Context,
}

impl Slow {
    fn unlocked(fx: &Fixture) -> Slow {
        let worker = Deferred::new();
        let mut s = AppState::new(Box::new(worker.clone()), Box::new(fx.clock.clone()));
        s.set_vault_path(Some(fx.path("vault.vc"))).expect("locked");
        s.set_profile_path(Some(fx.profile_path())).expect("idle");
        let mut slow = Slow {
            s,
            worker,
            forms: Forms::default(),
            ctx: eframe::egui::Context::default(),
        };
        let pass = || SecretString::new("correct horse battery".to_string());
        slow.run(|s| s.create_vault(pass(), pass()));
        assert!(slow.s.is_unlocked());
        slow
    }

    /// Starts `action` and lets its job finish.
    fn run(&mut self, action: impl FnOnce(&mut AppState) -> Result<(), GuiError>) {
        if let Err(e) = action(&mut self.s) {
            panic!("action refused: {e}");
        }
        self.frame();
        if let Some(e) = self.s.error() {
            panic!("job failed: {e}");
        }
    }

    /// One app frame: the worker finishes, the state ticks, the app syncs.
    fn frame(&mut self) {
        self.worker.finish();
        self.s.tick();
        sync_lock(&mut self.s, &mut self.forms, &self.ctx);
    }

    /// Something typed into the forms and egui memory.
    fn type_into_forms(&mut self) {
        self.forms.pass = "typed".to_string();
        self.ctx
            .data_mut(|d| d.insert_temp(eframe::egui::Id::new("g10"), 7u32));
    }

    /// The forms and egui memory were wiped and nothing came back.
    fn assert_wiped(&self, forms_before: usize) {
        assert!(form_wipes() > forms_before, "forms not wiped");
        assert!(self.forms.pass.is_empty());
        let id = eframe::egui::Id::new("g10");
        assert_eq!(self.ctx.data_mut(|d| d.get_temp::<u32>(id)), None);
        assert!(!self.s.is_unlocked(), "vault came back");
        assert!(self.s.scan_summary().is_none(), "scan came back");
        assert!(self.s.mask_view().is_none(), "mask view came back");
        assert!(self.s.text_report().is_none(), "text report came back");
        assert!(self.s.text.output.is_empty(), "text came back");
    }

    /// Locks while the started job runs, then delivers its result.
    fn lock_then_deliver(&mut self) {
        let (keys, forms) = (key_wipes(), form_wipes());
        self.type_into_forms();
        self.s.lock();
        self.frame();
        assert!(key_wipes() > keys, "key not wiped");
        self.assert_wiped(forms);
    }
}

#[test]
fn g10_scan_result_after_lock_is_discarded() {
    let fx = Fixture::new();
    let mut slow = Slow::unlocked(&fx);
    slow.s.scan(fx.input.clone()).expect("scan starts");
    slow.lock_then_deliver();
}

#[test]
fn g10_mask_result_after_lock_is_discarded() {
    let fx = Fixture::new();
    let mut slow = Slow::unlocked(&fx);
    slow.run(|s| s.scan(fx.input.clone()));
    slow.s.confirm_review().expect("confirm");
    let form = MaskForm::default();
    slow.s.mask(fx.path("masked"), form).expect("mask starts");
    slow.lock_then_deliver();
}

#[test]
fn g10_restore_text_after_lock_is_wiped_and_discarded() {
    let fx = Fixture::new();
    let mut slow = Slow::unlocked(&fx);
    slow.s.text.input = format!("const token = \"{}\";\n", fx.pat);
    slow.run(|s| s.mask_text());
    assert!(!slow.s.text.output.contains(&fx.pat), "masked");
    slow.s.text.input = slow.s.text.output.clone();
    let stale = stale_text_wipes();
    slow.s.restore_text(false).expect("restore starts");
    slow.lock_then_deliver();
    assert_eq!(stale_text_wipes(), stale + 1, "stale text not wiped");
}

#[test]
fn g10_worker_stopped_locks_and_wipes() {
    let fx = Fixture::new();
    let mut slow = Slow::unlocked(&fx);
    slow.s.text.input = "x".to_string();
    slow.s.mask_text().expect("job starts");
    let (keys, forms) = (key_wipes(), form_wipes());
    slow.type_into_forms();
    slow.worker.stop();
    slow.frame();
    assert!(matches!(slow.s.error(), Some(GuiError::WorkerStopped)));
    assert!(key_wipes() > keys, "key not wiped");
    slow.assert_wiped(forms);
}

#[test]
fn g10_dispatch_failure_locks_and_wipes() {
    let fx = Fixture::new();
    let mut slow = Slow::unlocked(&fx);
    let (keys, forms) = (key_wipes(), form_wipes());
    slow.type_into_forms();
    slow.worker.stop();
    let r = slow.s.scan(fx.input.clone());
    assert!(matches!(r, Err(GuiError::WorkerStopped)));
    sync_lock(&mut slow.s, &mut slow.forms, &slow.ctx);
    assert!(key_wipes() > keys, "key not wiped");
    slow.assert_wiped(forms);
}

#[test]
fn g10_idle_lock_wipes_forms() {
    let fx = Fixture::new();
    let mut slow = Slow::unlocked(&fx);
    let forms = form_wipes();
    slow.type_into_forms();
    fx.clock.advance(IDLE_LIMIT_SECS + 1);
    slow.frame();
    slow.assert_wiped(forms);
}
