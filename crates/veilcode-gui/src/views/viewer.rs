//! The read-only finding viewer window (D137). It draws what
//! `Viewer::shown` returns; it never opens the file in another program and
//! its labels cannot be selected, so it offers no copy.

use crate::state::{AppState, Viewer, ViewerBody};
use crate::theme::{self, Palette};
use eframe::egui::{self, Color32, FontId, TextFormat, text::LayoutJob};
use veilcode_core::{PartKind, ViewLine};

/// Shows the viewer window while one is open.
pub fn show(ctx: &egui::Context, state: &mut AppState) {
    let Some(viewer) = state.viewer() else {
        return;
    };
    let mut open = true;
    let state_busy = state.is_busy();
    let (mut toggle, mut close) = (false, false);
    let title = format!("View {}", viewer.title());
    egui::Window::new(title)
        .id(egui::Id::new("finding-viewer"))
        .open(&mut open)
        .default_size([760.0, 520.0])
        .collapsible(false)
        .show(ctx, |ui| {
            let label = if viewer.revealed() { "Hide" } else { "Reveal" };
            ui.horizontal(|ui| {
                let busy = state_busy;
                toggle = ui.add_enabled(!busy, egui::Button::new(label)).clicked();
                close = ui.button("Close").clicked();
                ui.label("Read-only. Other findings in this file stay masked.");
            });
            ui.separator();
            body(ui, viewer);
        });
    if toggle {
        let r = state.toggle_reveal();
        state.report(r);
    }
    if close || !open {
        state.close_viewer();
    }
}

fn body(ui: &mut egui::Ui, viewer: &Viewer) {
    let lines = match viewer.body() {
        ViewerBody::Lines(lines) => lines,
        ViewerBody::Message(msg) => {
            ui.label(msg);
            return;
        }
    };
    let p = theme::palette(ui.visuals().dark_mode);
    egui::ScrollArea::both().show(ui, |ui| {
        for line in lines {
            let fill = if line.hit {
                p.hit_line
            } else {
                Color32::TRANSPARENT
            };
            egui::Frame::new().fill(fill).show(ui, |ui| {
                let job = line_job(ui, viewer, line, p);
                ui.add(egui::Label::new(job).selectable(false).extend());
            });
        }
    });
}

/// One line as a layout: number, then each part in its colours.
fn line_job(ui: &egui::Ui, viewer: &Viewer, line: &ViewLine, p: &Palette) -> LayoutJob {
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let fmt = |color: Color32, background: Color32| TextFormat {
        font_id: FontId::clone(&font),
        color,
        background,
        ..TextFormat::default()
    };
    let mut job = LayoutJob::default();
    job.append(
        &format!("{:>6}  ", line.number),
        0.0,
        fmt(p.weak, Color32::TRANSPARENT),
    );
    for part in &line.parts {
        let format = match part.kind {
            PartKind::Plain => fmt(p.text, Color32::TRANSPARENT),
            PartKind::Cut => fmt(p.weak, Color32::TRANSPARENT),
            PartKind::Selected | PartKind::Other => fmt(p.chip_text, p.chip),
        };
        job.append(viewer.shown(part), 0.0, format);
    }
    job
}
