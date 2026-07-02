use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{Aes256Gcm, Key};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::cli;
use crate::crypto;

const CHECK_PLAINTEXT: &[u8] = b"porquinho-master-key-check";

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub provider: String,
    pub key: String,
}

pub fn porquinho_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let home = std::env::var("HOME").expect("HOME environment variable not set");
        PathBuf::from(home).join(".66251a1c61a1bfaeed88b163b6908b258a7af9ba")
    })
}

fn config_path() -> PathBuf {
    porquinho_dir().join("c")
}

fn salt_path() -> PathBuf {
    porquinho_dir().join("s")
}

fn check_path() -> PathBuf {
    porquinho_dir().join("k")
}

pub fn load_or_create_salt() -> Vec<u8> {
    let path = salt_path();
    if path.exists() {
        let encoded = fs::read_to_string(&path).expect("failed to read salt file");
        B64.decode(encoded.trim()).expect("salt file is corrupted")
    } else {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        fs::write(&path, B64.encode(salt)).expect("failed to write salt file");
        cli::info(&format!("Generated new salt at {}", path.display()));
        salt.to_vec()
    }
}

pub fn verify_master_key(key: &Key<Aes256Gcm>) -> bool {
    let path = check_path();
    if path.exists() {
        let encoded = fs::read_to_string(&path).expect("failed to read check file");
        match crypto::decrypt(key, encoded.trim()) {
            Ok(value) => value.as_bytes() == CHECK_PLAINTEXT,
            Err(_) => false,
        }
    } else {
        fs::write(&path, crypto::encrypt(key, CHECK_PLAINTEXT))
            .expect("failed to write check file");
        cli::success("Master key registered for this vault.");
        true
    }
}

pub fn load_entries(key: &Key<Aes256Gcm>) -> Vec<Entry> {
    let path = config_path();
    if !path.exists() {
        return Vec::new();
    }
    let content = fs::read_to_string(&path).expect("failed to read vault file");
    let json = crypto::decrypt(key, content.trim()).expect("failed to decrypt vault file");
    serde_json::from_str(&json).expect("vault file is corrupted")
}

pub fn save_entries(entries: &[Entry], key: &Key<Aes256Gcm>) {
    let json = serde_json::to_string(entries).expect("failed to serialize entries");
    fs::write(config_path(), crypto::encrypt(key, json.as_bytes()))
        .expect("failed to write vault file");
}
