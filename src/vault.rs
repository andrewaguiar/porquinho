use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{Aes256Gcm, Key};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::cli;
use crate::crypto;

const CHECK_PLAINTEXT: &[u8] = b"porquinho-master-key-check";

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub provider: String,
    pub key: String,
}

pub fn porquinho_dir() -> PathBuf {
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
    let content = fs::read_to_string(&path).expect("failed to read config.json");
    let json = crypto::decrypt(key, content.trim()).expect("failed to decrypt config.json");
    serde_json::from_str(&json).expect("config.json is corrupted")
}

pub fn save_entries(entries: &[Entry], key: &Key<Aes256Gcm>) {
    let json = serde_json::to_string(entries).expect("failed to serialize entries");
    fs::write(config_path(), crypto::encrypt(key, json.as_bytes()))
        .expect("failed to write config.json");
}
