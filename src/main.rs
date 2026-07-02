mod cli;
mod commands;
mod crypto;
mod vault;

use std::fs;

use cli::{CYAN, GREEN, RESET};

fn main() {
    fs::create_dir_all(vault::porquinho_dir()).expect("failed to create ~/.porquinho");

    cli::print_banner();

    let salt = vault::load_or_create_salt();
    let master = cli::prompt_secret("Master key");
    if master.is_empty() {
        cli::error("Master key cannot be empty.");
        std::process::exit(1);
    }
    let key = crypto::derive_key(&master, &salt);
    if !vault::verify_master_key(&key) {
        cli::error("Wrong master key.");
        std::process::exit(1);
    }

    let mut entries = vault::load_entries(&key);
    println!();
    cli::success(&format!(
        "Vault unlocked ({} entries). Type {CYAN}/help{RESET}{GREEN} for commands.",
        entries.len()
    ));
    println!();

    loop {
        let line = cli::prompt_command();
        match line.as_str() {
            "" => {}
            "/list" => commands::list::run(&entries),
            "/create" => commands::create::run(&mut entries, &key),
            "/remove" => commands::remove::run(&mut entries, &key),
            "/update" => commands::update::run(&mut entries, &key),
            "/show" => commands::show::run(&entries, &key),
            "/help" => commands::help::run(),
            "/quit" | "/exit" => break,
            other => cli::error(&format!("Unknown command '{other}'. Type /help for commands.")),
        }
    }
}
