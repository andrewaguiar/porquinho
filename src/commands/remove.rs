use aes_gcm::{Aes256Gcm, Key};

use crate::cli;
use crate::vault::{self, Entry};

pub fn run(entries: &mut Vec<Entry>, key: &Key<Aes256Gcm>) {
    let name = cli::prompt("Name");
    let Some(index) = entries.iter().position(|e| e.name == name) else {
        cli::error(&format!("No entry named '{name}'."));
        return;
    };
    let answer = cli::prompt(&format!("Remove '{name}'? [y/N]"));
    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        entries.remove(index);
        vault::save_entries(entries, key);
        cli::success(&format!("Entry '{name}' removed."));
    } else {
        cli::info("Aborted.");
    }
}
