//! The finding viewer's state (D137). No egui types: the view draws what
//! `Viewer::shown` returns. File text stays in core's wiped buffers and is
//! dropped with the `Viewer` (close, another finding, lock).

use std::fmt;
use veilcode_core::{FindingView, PartKind, ViewLine, ViewPart};

/// Drawn instead of a hidden value.
pub const MASK: &str = "••••••";

#[cfg(test)]
thread_local! {
    static VIEWER_WIPES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Number of `Viewer`s dropped on this thread (G17).
#[cfg(test)]
pub fn viewer_wipes() -> usize {
    VIEWER_WIPES.with(|c| c.get())
}

/// One open viewer: the finding's context and whether its value is shown.
/// Until Reveal, the view holds only offsets and lengths for every finding.
pub struct Viewer {
    id: String,
    title: String,
    view: FindingView,
    revealed: bool,
}

/// What the viewer window shows.
pub enum ViewerBody<'a> {
    Lines(&'a [ViewLine]),
    /// Why there is nothing to show.
    Message(&'static str),
}

impl Viewer {
    /// A viewer for finding `id` (`title`: "file:line"). `revealed`: the
    /// view came from `reveal_finding` and holds the value.
    pub(crate) fn new(id: String, title: String, view: FindingView, revealed: bool) -> Viewer {
        Viewer {
            id,
            title,
            view,
            revealed,
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn revealed(&self) -> bool {
        self.revealed
    }

    /// Back to hidden: the value's text is dropped (wiped).
    pub(crate) fn hide(&mut self) {
        self.view.hide_values();
        self.revealed = false;
    }

    pub fn body(&self) -> ViewerBody<'_> {
        match &self.view {
            FindingView::Lines(lines) => ViewerBody::Lines(lines),
            other => ViewerBody::Message(viewer_message(other)),
        }
    }

    /// The text to draw for `part`: other findings always, and the viewed
    /// value until Reveal, are drawn as `MASK`.
    pub fn shown<'a>(&self, part: &'a ViewPart) -> &'a str {
        match part.kind {
            PartKind::Other => MASK,
            PartKind::Selected if !self.revealed => MASK,
            _ => part.text(),
        }
    }
}

/// The message for a view without lines.
pub fn viewer_message(view: &FindingView) -> &'static str {
    match view {
        FindingView::TooLarge => "file too large to preview (over 2 MiB)",
        FindingView::Changed => "file changed since the scan — rescan to view it",
        FindingView::Lines(_) => "",
    }
}

impl fmt::Debug for Viewer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines = match &self.view {
            FindingView::Lines(l) => l.len(),
            _ => 0,
        };
        f.debug_struct("Viewer")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("revealed", &self.revealed)
            .field("lines", &lines)
            .finish()
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        #[cfg(test)]
        VIEWER_WIPES.with(|c| c.set(c.get() + 1));
    }
}
