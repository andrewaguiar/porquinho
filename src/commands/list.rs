use crate::cli::{self, BOLD, CYAN, DIM, RESET};
use crate::vault::Entry;

pub fn run(entries: &[Entry]) {
    if entries.is_empty() {
        cli::info("No entries yet. Use /create to add one.");
        return;
    }
    for entry in entries {
        println!(
            "{CYAN}●{RESET} {BOLD}{}{RESET} {DIM}({}){RESET} key: {DIM}****{RESET}",
            entry.name, entry.provider
        );
    }
}
