use aes_gcm::{Aes256Gcm, Key};

use crate::cli;
use crate::crypto;
use crate::vault::{self, Entry};

pub fn run(entries: &mut [Entry], key: &Key<Aes256Gcm>) {
    let name = cli::prompt("Name");
    let Some(entry) = entries.iter_mut().find(|e| e.name == name) else {
        cli::error(&format!("No entry named '{name}'."));
        return;
    };
    let api_key = cli::prompt_secret("New API key");
    if api_key.is_empty() {
        cli::error("API key cannot be empty.");
        return;
    }
    entry.key = crypto::encrypt(key, api_key.as_bytes());
    vault::save_entries(entries, key);
    cli::success(&format!("Entry '{name}' updated."));
}
