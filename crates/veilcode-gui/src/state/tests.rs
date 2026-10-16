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

// ---- G11: guide and locked-state hints (D127) ----

#[test]
fn g11_locked_tabs_report_the_hint_and_help_is_always_reachable() {
    let fx = Fixture::new();
    let mut s = fx.state();
    for screen in Screen::ALL {
        let hint = s.tab_hint(screen);
        if matches!(screen, Screen::Unlock | Screen::Help) {
            assert_eq!(hint, None, "{screen:?}");
        } else {
            assert_eq!(hint, Some("Create or open a vault first"), "{screen:?}");
        }
        s.screen = screen;
        let shown = if hint.is_some() {
            Screen::Unlock
        } else {
            screen
        };
        assert_eq!(s.shown_screen(), shown, "{screen:?}");
    }
    let mut s = fx.unlocked();
    for screen in Screen::ALL {
        assert_eq!(s.tab_hint(screen), None, "{screen:?}");
        s.screen = screen;
        assert_eq!(s.shown_screen(), screen, "{screen:?}");
    }
}

#[test]
fn g11_guide_has_steps_and_safety_rules_and_no_links() {
    let fx = Fixture::new();
    let (vault, profile) = (fx.path("data/vault.vc"), fx.path("config/profile.toml"));
    let g = viewmodel::guide(Some(&vault), Some(&profile));
    let steps = [
        "Create or open a vault",
        "Scan",
        "Review what will be masked",
        "Mask into a new folder",
        "Restore the AI's folder into another new folder",
    ];
    assert_eq!(g.steps.len(), 5);
    for (step, want) in g.steps.iter().zip(steps) {
        assert!(step.contains(want), "{step}");
    }
    assert!(g.steps[3].contains("give that folder to the AI"));
    let rules = [
        "never modified",
        "must be a new folder",
        "outside the project folder",
        "throwaway",
    ];
    assert_eq!(g.safety.len(), 4);
    for (rule, want) in g.safety.iter().zip(rules) {
        assert!(rule.contains(want), "{rule}");
    }
    let storage = g.storage.join("\n");
    assert!(storage.contains(&vault.display().to_string()), "{storage}");
    assert!(
        storage.contains(&profile.display().to_string()),
        "{storage}"
    );
    let none = viewmodel::guide(None, None);
    assert_eq!(none.storage.len(), 2);
    let debug = format!("{g:?}{none:?}{}", viewmodel::UNLOCK_HINT);
    assert!(!debug.contains("http"), "{debug}");
    assert_no_secret(debug.as_bytes(), &fx.secrets());
}

// ---- G12: vault and profile path safety (D126, D128) ----

fn messages(problems: &[GuiError]) -> Vec<String> {
    problems.iter().map(|e| e.to_string()).collect()
}

const GOOD: &str = "correct horse battery";

#[test]
fn g12_create_refuses_an_existing_file_before_any_core_call() {
    let fx = Fixture::new();
    let wp = fx.path("wp-config.php");
    std::fs::write(&wp, b"<?php\n").expect("write");
    let mut s = fx.state();
    s.set_vault_path(Some(wp.clone())).expect("locked");
    let pass = || SecretString::new(GOOD.to_string());
    let r = s.create_vault(pass(), pass());
    assert!(matches!(r, Err(GuiError::VaultExists)), "{r:?}");
    assert!(!s.is_busy() && !s.is_unlocked(), "a job was dispatched");
    assert_eq!(read(&wp), "<?php\n");
    let p = problems(Some(&wp), GOOD, GOOD);
    assert_eq!(
        messages(&p),
        ["a vault already exists at this path; open it instead"]
    );
}

#[test]
fn g12_relative_vault_and_profile_paths_are_refused() {
    let fx = Fixture::new();
    let mut s = fx.state();
    s.set_vault_path(Some(PathBuf::from("vault.vc")))
        .expect("locked");
    let pass = || SecretString::new(GOOD.to_string());
    for r in [s.create_vault(pass(), pass()), s.unlock(pass())] {
        let msg = r.expect_err("relative vault accepted").to_string();
        assert!(msg.contains("use Browse… or a full path"), "{msg}");
    }
    assert!(!s.is_busy());
    let p = problems(Some(Path::new("vault.vc")), GOOD, GOOD);
    assert!(matches!(p.as_slice(), [GuiError::RelativePath]), "{p:?}");
    let mut s = fx.unlocked();
    s.set_profile_path(Some(PathBuf::from("profile.toml")))
        .expect("idle");
    let r = s.scan(fx.input.clone());
    assert!(matches!(r, Err(GuiError::RelativePath)), "{r:?}");
    assert!(!s.is_busy());
}

#[test]
fn g12_vault_inside_the_project_folder_is_refused() {
    let fx = Fixture::new();
    let mut s = fx.state();
    s.set_vault_path(Some(fx.input.join("sub/vault.vc")))
        .expect("locked");
    let pass = || SecretString::new(GOOD.to_string());
    done(&mut s, |s| s.create_vault(pass(), pass()));
    // Also through a `..` detour to the same folder.
    for input in [fx.input.clone(), fx.input.join("src/..")] {
        let msg = s.scan(input).expect_err("vault in project").to_string();
        assert_eq!(msg, "keep the vault outside the project folder");
        assert!(!s.is_busy());
    }
    // Restoring a folder that holds the vault is refused too.
    let mut s = fx.unlocked();
    let r = s.restore(fx.tmp.path().to_path_buf(), fx.path("r"), None, false);
    assert!(matches!(r, Err(GuiError::VaultInProject)), "{r:?}");
    assert!(!fx.path("r").exists());
    // A separate per-project vault (D64) inside the project is refused.
    let mut s = fx.scanned();
    s.confirm_review().expect("confirm");
    let form = MaskForm {
        separate_vault: Some(SeparateVault {
            path: fx.input.join("project.vc"),
            pass: SecretString::new(GOOD.to_string()),
            confirm: SecretString::new(GOOD.to_string()),
        }),
        ..MaskForm::default()
    };
    let r = s.mask(fx.path("masked"), form);
    assert!(matches!(r, Err(GuiError::VaultInProject)), "{r:?}");
    assert!(!fx.path("masked").exists() && !fx.input.join("project.vc").exists());
}

#[test]
fn g12_profile_inside_the_project_folder_is_refused() {
    let fx = Fixture::new();
    let inside = fx.input.join(".veilcode/profile.toml");
    let mut s = fx.unlocked();
    s.set_profile_path(Some(inside.clone())).expect("idle");
    let msg = s.scan(fx.input.clone()).expect_err("profile in project");
    assert_eq!(
        msg.to_string(),
        "keep the profile outside the project folder"
    );
    let mut s = fx.scanned();
    s.confirm_review().expect("confirm");
    s.set_profile_path(Some(inside.clone())).expect("idle");
    let r = s.mask(fx.path("masked"), MaskForm::default());
    assert!(matches!(r, Err(GuiError::ProfileInProject)), "{r:?}");
    let r = s.restore(fx.input.clone(), fx.path("r"), None, false);
    assert!(matches!(r, Err(GuiError::ProfileInProject)), "{r:?}");
    assert!(!inside.exists() && !fx.path("masked").exists() && !fx.path("r").exists());
}

#[test]
fn g12_create_is_disabled_until_path_length_and_match_are_valid() {
    let fx = Fixture::new();
    let new = fx.path("new/vault.vc");
    assert!(problems(Some(&new), GOOD, GOOD).is_empty());
    let short = "passphrase must be at least 12 characters";
    let mismatch = "the passphrases do not match";
    assert_eq!(messages(&problems(Some(&new), "short", "short")), [short]);
    // Characters are counted as core counts them (Unicode scalar values).
    let (e11, e12) = ("é".repeat(11), "é".repeat(12));
    assert_eq!(messages(&problems(Some(&new), &e11, &e11)), [short]);
    assert!(problems(Some(&new), &e12, &e12).is_empty());
    assert_eq!(messages(&problems(Some(&new), GOOD, "other")), [mismatch]);
    let all = problems(Some(Path::new("v.vc")), "short", "other");
    let relative = GuiError::RelativePath.to_string();
    assert_eq!(messages(&all), [relative.as_str(), short, mismatch]);
    let none = problems(None, GOOD, GOOD);
    assert!(
        matches!(none.as_slice(), [GuiError::NoDefaultPath]),
        "{none:?}"
    );
}

#[test]
fn g12_suggested_create_path_is_the_local_data_vault() {
    let fx = Fixture::new();
    let suggested = suggested_vault_path();
    assert_eq!(suggested, default_vault_path());
    let p = suggested.expect("a local data dir in the test environment");
    assert_eq!(p.file_name(), Some(std::ffi::OsStr::new("vault.vc")));
    assert!(p.is_absolute(), "{}", p.display());
    // The picker opens in the nearest folder that exists.
    let deep = fx.path("a/b/c");
    assert_eq!(existing_ancestor(&deep), Some(fx.tmp.path().to_path_buf()));
    assert_eq!(existing_ancestor(&fx.input), Some(fx.input.clone()));
}

/// `create_problems` with a fresh existence cache.
fn problems(path: Option<&Path>, pass: &str, confirm: &str) -> Vec<GuiError> {
    create_problems(path, pass, confirm, &mut ExistsCache::default())
}

// ---- G12 additions from the security review (D130) ----

const NETWORK: &str = "network and device paths are not supported";

#[test]
fn g12_network_and_device_paths_are_refused_as_text() {
    let refused = [
        r"\\server\share\vault.vc",
        r"\\?\UNC\server\share\vault.vc",
        r"\\.\pipe\veilcode",
        r"\\.\C:\vault.vc",
        "//host/share/vault.vc",
        r"\/host\share",
        r"/\host\share",
        r"\??\UNC\server\share",
    ];
    for p in refused {
        let msg = check_local(Path::new(p)).expect_err(p).to_string();
        assert_eq!(msg, NETWORK, "{p}");
    }
    for p in [
        r"\\?\C:\data\vault.vc",
        r"C:\data\vault.vc",
        "/tmp/vault.vc",
        "v.vc",
    ] {
        assert!(check_local(Path::new(p)).is_ok(), "{p}");
    }
    // The existence cache is never consulted for such a path.
    let mut cache = ExistsCache::default();
    let unc = Path::new(r"\\server\share\vault.vc");
    let p = create_problems(Some(unc), GOOD, GOOD, &mut cache);
    assert_eq!(messages(&p), [NETWORK]);
    assert_eq!(cache.fs_checks(), 0);
}

#[test]
fn g12_network_paths_are_refused_by_every_action() {
    let fx = Fixture::new();
    let unc = || PathBuf::from(r"\\server\share\x");
    let pass = || SecretString::new(GOOD.to_string());
    let mut s = fx.state();
    s.set_vault_path(Some(unc())).expect("locked");
    let r = s.create_vault(pass(), pass());
    assert_eq!(r.expect_err("unc vault").to_string(), NETWORK);
    let mut s = fx.unlocked();
    assert_eq!(s.scan(unc()).expect_err("unc input").to_string(), NETWORK);
    let r = s.restore(unc(), fx.path("r"), None, false);
    assert_eq!(r.expect_err("unc restore in").to_string(), NETWORK);
    let r = s.restore(fx.path("m"), unc(), None, false);
    assert_eq!(r.expect_err("unc restore out").to_string(), NETWORK);
    let mut s = fx.scanned();
    s.confirm_review().expect("confirm");
    let r = s.mask(unc(), MaskForm::default());
    assert_eq!(r.expect_err("unc mask out").to_string(), NETWORK);
    let form = MaskForm {
        separate_vault: Some(SeparateVault {
            path: unc(),
            pass: pass(),
            confirm: pass(),
        }),
        ..MaskForm::default()
    };
    let r = s.mask(fx.path("masked"), form);
    assert_eq!(r.expect_err("unc separate vault").to_string(), NETWORK);
    s.set_profile_path(Some(unc())).expect("idle");
    let r = s.scan(fx.input.clone());
    assert_eq!(r.expect_err("unc profile").to_string(), NETWORK);
    assert!(!s.is_busy());
}

#[test]
fn g12_create_path_existence_is_checked_once_per_change() {
    let fx = Fixture::new();
    let (a, b) = (fx.path("a.vc"), fx.path("b.vc"));
    let mut cache = ExistsCache::default();
    assert!(create_problems(Some(&a), GOOD, GOOD, &mut cache).is_empty());
    std::fs::write(&a, b"x").expect("write");
    for _ in 0..3 {
        // Same path string: no new filesystem call (the result is cached).
        assert!(create_problems(Some(&a), GOOD, GOOD, &mut cache).is_empty());
    }
    assert_eq!(cache.fs_checks(), 1);
    assert!(create_problems(Some(&b), GOOD, GOOD, &mut cache).is_empty());
    let p = create_problems(Some(&a), GOOD, GOOD, &mut cache);
    assert!(matches!(p.as_slice(), [GuiError::VaultExists]), "{p:?}");
    assert_eq!(cache.fs_checks(), 3);
    // Submit checks again, whatever the cache says.
    let mut s = fx.state();
    s.set_vault_path(Some(a)).expect("locked");
    let pass = || SecretString::new(GOOD.to_string());
    assert!(matches!(
        s.create_vault(pass(), pass()),
        Err(GuiError::VaultExists)
    ));
}

#[test]
fn g12_case_differing_vault_path_inside_project_is_refused() {
    let fx = Fixture::new();
    let upper = fx.tmp.path().join("PROJECT").join("vault.vc");
    let r = check_outside(&upper, &fx.input, GuiError::VaultInProject);
    assert!(matches!(r, Err(GuiError::VaultInProject)), "{r:?}");
    let other = fx.tmp.path().join("project2").join("vault.vc");
    assert!(check_outside(&other, &fx.input, GuiError::VaultInProject).is_ok());
}

#[test]
fn g12_separate_vault_inside_the_output_folder_is_refused() {
    let fx = Fixture::new();
    let mut s = fx.scanned();
    s.confirm_review().expect("confirm");
    let out = fx.path("masked");
    let form = MaskForm {
        separate_vault: Some(SeparateVault {
            path: out.join("project.vc"),
            pass: SecretString::new(GOOD.to_string()),
            confirm: SecretString::new(GOOD.to_string()),
        }),
        ..MaskForm::default()
    };
    let r = s.mask(out.clone(), form);
    assert!(matches!(r, Err(GuiError::VaultInProject)), "{r:?}");
    assert!(!out.exists());
}

#[cfg(unix)]
#[test]
fn g12_symlink_into_the_project_is_refused() {
    let fx = Fixture::new();
    let link = fx.path("link");
    std::os::unix::fs::symlink(&fx.input, &link).expect("symlink");
    let r = check_outside(&link.join("vault.vc"), &fx.input, GuiError::VaultInProject);
    assert!(matches!(r, Err(GuiError::VaultInProject)), "{r:?}");
}

#[cfg(unix)]
#[test]
fn g12_unresolvable_vault_path_fails_closed() {
    let fx = Fixture::new();
    let dangling = fx.path("dangling.vc");
    std::os::unix::fs::symlink(fx.input.join("gone/vault.vc"), &dangling).expect("symlink");
    let file = fx.path("plain-file");
    std::fs::write(&file, b"x").expect("write");
    for p in [dangling, file.join("vault.vc")] {
        let r = check_outside(&p, &fx.input, GuiError::VaultInProject);
        let msg = r.expect_err("unresolvable path accepted").to_string();
        assert!(msg.starts_with("could not check"), "{msg}");
    }
}
