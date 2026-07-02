use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha512};

const NONCE_LEN: usize = 12;

pub fn derive_key(master: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut hasher = Sha512::new();
    hasher.update(master.as_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();
    // AES-256 needs 32 bytes; take the first half of the SHA-512 digest.
    *Key::<Aes256Gcm>::from_slice(&digest[..32])
}

pub fn encrypt(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ciphertext);
    B64.encode(blob)
}

pub fn decrypt(key: &Key<Aes256Gcm>, encoded: &str) -> Result<String, String> {
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
