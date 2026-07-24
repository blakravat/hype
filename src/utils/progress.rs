use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

/// Single global progress bar for the whole run: spinner, elapsed time,
/// bar, IPs done/total, percent. Draws to stderr, so it never mixes into
/// the piped stdout host list (`hype < hosts.txt > active.txt`).
#[derive(Clone)]
pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    /// Create the bar for `total` hosts and start it ticking immediately.
    pub fn new(total: u64) -> Self {
        let bar = ProgressBar::new(total);
        bar.set_style(style());
        bar.enable_steady_tick(Duration::from_millis(100));
        Self { bar }
    }

    /// Mark one more host as finished being checked.
    pub fn inc(&self) {
        self.bar.inc(1);
    }

    /// Run `f` with the bar hidden, then redraw it — keeps a stdout print
    /// from tearing the bar mid-redraw; the printed line lands above it.
    pub fn suspend<F: FnOnce() -> R, R>(&self, f: F) -> R {
        self.bar.suspend(f)
    }

    /// Finish and remove the bar completely, leaving no trace on screen.
    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

/// Build the shared template: spinner, elapsed time, bar, pos/len, percent.
fn style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner} [{elapsed_precise}] [{bar:30}] {pos}/{len} ({percent}%)")
        .expect("static progress bar template is valid")
        .progress_chars("#>-")
}