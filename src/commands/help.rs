use crate::cli::{BOLD, CYAN, RESET};

pub fn run() {
    let commands = [
        ("/list", "List all entries (keys stay hidden)"),
        ("/create", "Create a new entry"),
        ("/update", "Change the key of an existing entry"),
        ("/show", "Show an entry with its key decrypted"),
        ("/remove", "Remove an entry (asks for confirmation)"),
        ("/help", "Show this help"),
        ("/quit", "Exit"),
    ];
    println!("{BOLD}Commands:{RESET}");
    for (name, description) in commands {
        println!("  {CYAN}{name:<8}{RESET} {description}");
    }
}
