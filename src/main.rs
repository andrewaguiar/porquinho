use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

const NONCE_LEN: usize = 12;
const CHECK_PLAINTEXT: &[u8] = b"porquinho-master-key-check";

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";

const BANNER: &str = r#"
██████╗  ██████╗ ██████╗  ██████╗ ██╗   ██╗██╗███╗   ██╗██╗  ██╗ ██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗██║   ██║██║████╗  ██║██║  ██║██╔═══██╗
██████╔╝██║   ██║██████╔╝██║   ██║██║   ██║██║██╔██╗ ██║███████║██║   ██║
██╔═══╝ ██║   ██║██╔══██╗██║▄▄ ██║██║   ██║██║██║╚██╗██║██╔══██║██║   ██║
██║     ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║██║ ╚████║██║  ██║╚██████╔╝
╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚══▀▀═╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝"#;

#[derive(Serialize, Deserialize)]
struct Entry {
    name: String,
    provider: String,
    key: String,
}

fn porquinho_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME environment variable not set");
    PathBuf::from(home).join(".porquinho")
}

fn config_path() -> PathBuf {
    porquinho_dir().join("config.json")
}

fn salt_path() -> PathBuf {
    porquinho_dir().join("salt")
}

fn check_path() -> PathBuf {
    porquinho_dir().join("check")
}

fn load_or_create_salt() -> Vec<u8> {
    let path = salt_path();
    if path.exists() {
        let encoded = fs::read_to_string(&path).expect("failed to read salt file");
        B64.decode(encoded.trim()).expect("salt file is corrupted")
    } else {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        fs::write(&path, B64.encode(salt)).expect("failed to write salt file");
        info(&format!("Generated new salt at {}", path.display()));
        salt.to_vec()
    }
}

fn derive_key(master: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut hasher = Sha512::new();
    hasher.update(master.as_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();
    // AES-256 needs 32 bytes; take the first half of the SHA-512 digest.
    *Key::<Aes256Gcm>::from_slice(&digest[..32])
}

fn encrypt(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ciphertext);
    B64.encode(blob)
}

fn decrypt(key: &Key<Aes256Gcm>, encoded: &str) -> Result<String, String> {
    let blob = B64
        .decode(encoded)
        .map_err(|_| "stored key is not valid base64".to_string())?;
    if blob.len() <= NONCE_LEN {
        return Err("stored key is too short".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "decryption failed (wrong master key?)".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "decrypted data is not valid UTF-8".to_string())
}

fn verify_master_key(key: &Key<Aes256Gcm>) -> bool {
    let path = check_path();
    if path.exists() {
        let encoded = fs::read_to_string(&path).expect("failed to read check file");
        match decrypt(key, encoded.trim()) {
            Ok(value) => value.as_bytes() == CHECK_PLAINTEXT,
            Err(_) => false,
        }
    } else {
        fs::write(&path, encrypt(key, CHECK_PLAINTEXT)).expect("failed to write check file");
        success("Master key registered for this vault.");
        true
    }
}

fn load_entries() -> Vec<Entry> {
    let path = config_path();
    if !path.exists() {
        return Vec::new();
    }
    let content = fs::read_to_string(&path).expect("failed to read config.json");
    serde_json::from_str(&content).expect("config.json is corrupted")
}

fn save_entries(entries: &[Entry]) {
    let json = serde_json::to_string_pretty(entries).expect("failed to serialize entries");
    fs::write(config_path(), json).expect("failed to write config.json");
}

fn success(message: &str) {
    println!("{GREEN}✔ {message}{RESET}");
}

fn error(message: &str) {
    println!("{RED}✘ {message}{RESET}");
}

fn info(message: &str) {
    println!("{DIM}{message}{RESET}");
}

fn read_line_or_exit() -> String {
    let mut input = String::new();
    if io::stdin().read_line(&mut input).unwrap() == 0 {
        println!();
        std::process::exit(0);
    }
    input.trim().to_string()
}

fn prompt(label: &str) -> String {
    print!("{YELLOW}{label}:{RESET} ");
    io::stdout().flush().unwrap();
    read_line_or_exit()
}

fn prompt_secret(label: &str) -> String {
    if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{MAGENTA}{label}:{RESET} ")).unwrap()
    } else {
        print!("{MAGENTA}{label}:{RESET} ");
        io::stdout().flush().unwrap();
        read_line_or_exit()
    }
}

fn prompt_command() -> String {
    print!("{CYAN}{BOLD}porquinho>{RESET} ");
    io::stdout().flush().unwrap();
    read_line_or_exit()
}

fn cmd_list(entries: &[Entry]) {
    if entries.is_empty() {
        info("No entries yet. Use /create to add one.");
        return;
    }
    for entry in entries {
        println!(
            "{CYAN}●{RESET} {BOLD}{}{RESET} {DIM}({}){RESET} key: {DIM}****{RESET}",
            entry.name, entry.provider
        );
    }
}

fn cmd_create(entries: &mut Vec<Entry>, key: &Key<Aes256Gcm>) {
    let name = prompt("Name");
    if name.is_empty() {
        error("Name cannot be empty.");
        return;
    }
    if entries.iter().any(|e| e.name == name) {
        error(&format!(
            "An entry named '{name}' already exists. Use /update to change its key."
        ));
        return;
    }
    let provider = prompt("Provider");
    let api_key = prompt_secret("API key");
    if api_key.is_empty() {
        error("API key cannot be empty.");
        return;
    }
    entries.push(Entry {
        name: name.clone(),
        provider,
        key: encrypt(key, api_key.as_bytes()),
    });
    save_entries(entries);
    success(&format!("Entry '{name}' created."));
}

fn cmd_remove(entries: &mut Vec<Entry>) {
    let name = prompt("Name");
    let Some(index) = entries.iter().position(|e| e.name == name) else {
        error(&format!("No entry named '{name}'."));
        return;
    };
    let answer = prompt(&format!("Remove '{name}'? [y/N]"));
    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        entries.remove(index);
        save_entries(entries);
        success(&format!("Entry '{name}' removed."));
    } else {
        info("Aborted.");
    }
}

fn cmd_update(entries: &mut [Entry], key: &Key<Aes256Gcm>) {
    let name = prompt("Name");
    let Some(entry) = entries.iter_mut().find(|e| e.name == name) else {
        error(&format!("No entry named '{name}'."));
        return;
    };
    let api_key = prompt_secret("New API key");
    if api_key.is_empty() {
        error("API key cannot be empty.");
        return;
    }
    entry.key = encrypt(key, api_key.as_bytes());
    save_entries(entries);
    success(&format!("Entry '{name}' updated."));
}

fn cmd_show(entries: &[Entry], key: &Key<Aes256Gcm>) {
    let name = prompt("Name");
    let Some(entry) = entries.iter().find(|e| e.name == name) else {
        error(&format!("No entry named '{name}'."));
        return;
    };
    match decrypt(key, &entry.key) {
        Ok(plaintext) => println!(
            "{CYAN}●{RESET} {BOLD}{}{RESET} {DIM}({}){RESET} key: {GREEN}{}{RESET}",
            entry.name, entry.provider, plaintext
        ),
        Err(err) => error(&err),
    }
}

fn print_help() {
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

fn main() {
    let dir = porquinho_dir();
    fs::create_dir_all(&dir).expect("failed to create ~/.porquinho");

    println!("{YELLOW}{BOLD}{BANNER}{RESET}");
    println!("{DIM}         your API key piggy bank{RESET}");
    println!();

    let salt = load_or_create_salt();
    let master = prompt_secret("Master key");
    if master.is_empty() {
        error("Master key cannot be empty.");
        std::process::exit(1);
    }
    let key = derive_key(&master, &salt);
    if !verify_master_key(&key) {
        error("Wrong master key.");
        std::process::exit(1);
    }

    let mut entries = load_entries();
    println!();
    success(&format!(
        "Vault unlocked ({} entries). Type {CYAN}/help{RESET}{GREEN} for commands.",
        entries.len()
    ));
    println!();

    loop {
        let line = prompt_command();
        match line.as_str() {
            "" => {}
            "/list" => cmd_list(&entries),
            "/create" => cmd_create(&mut entries, &key),
            "/remove" => cmd_remove(&mut entries),
            "/update" => cmd_update(&mut entries, &key),
            "/show" => cmd_show(&entries, &key),
            "/help" => print_help(),
            "/quit" | "/exit" => break,
            other => error(&format!("Unknown command '{other}'. Type /help for commands.")),
        }
    }
}
