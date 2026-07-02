use aes_gcm::{Aes256Gcm, Key};

use crate::cli;
use crate::crypto;
use crate::vault::{self, Entry};

pub fn run(entries: &mut Vec<Entry>, key: &Key<Aes256Gcm>) {
    let name = cli::prompt("Name");
    if name.is_empty() {
        cli::error("Name cannot be empty.");
        return;
    }
    if entries.iter().any(|e| e.name == name) {
        cli::error(&format!(
            "An entry named '{name}' already exists. Use /update to change its key."
        ));
        return;
    }
    let provider = cli::prompt("Provider");
    let api_key = cli::prompt_secret("API key");
    if api_key.is_empty() {
        cli::error("API key cannot be empty.");
        return;
    }
    entries.push(Entry {
        name: name.clone(),
        provider,
        key: crypto::encrypt(key, api_key.as_bytes()),
    });
    vault::save_entries(entries, key);
    cli::success(&format!("Entry '{name}' created."));
}
