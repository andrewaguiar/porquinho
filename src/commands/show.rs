use aes_gcm::{Aes256Gcm, Key};

use crate::cli::{self, BOLD, CYAN, DIM, GREEN, RESET};
use crate::crypto;
use crate::vault::Entry;

pub fn run(entries: &[Entry], key: &Key<Aes256Gcm>) {
    let name = cli::prompt("Name");
    let Some(entry) = entries.iter().find(|e| e.name == name) else {
        cli::error(&format!("No entry named '{name}'."));
        return;
    };
    match crypto::decrypt(key, &entry.key) {
        Ok(plaintext) => println!(
            "{CYAN}●{RESET} {BOLD}{}{RESET} {DIM}({}){RESET} key: {GREEN}{}{RESET}",
            entry.name, entry.provider, plaintext
        ),
        Err(err) => cli::error(&err),
    }
}
