use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2};
use base64::engine::general_purpose;
use base64::Engine;  // Import the Engine trait to use the encode and decode methods
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use crate::errors::CredentialManagerError;
use crate::models::Credential;
use crate::utils::get_config_path;
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use colored::Colorize;

pub fn add_credential(
    service: &str,
    username: &str,
    password: &str,
    encryption_level: u8,
    master_password: &SecretString,
) -> Result<(), CredentialManagerError> {
    let (mut credentials, _, salt, _) = load_credentials(master_password)?;

    let credential = Credential {
        username: username.to_string(),
        password: SecretString::from(password.to_string()),
    };

    credentials.insert(service.to_string(), credential);

    save_credentials(&credentials, encryption_level, &salt, master_password)?;
    println!("{}", format!("Credential added for service: {}", service).green());
    Ok(())
}

fn derive_key(password: &SecretString, salt: &SaltString) -> [u8; 32] {
    let argon2 = Argon2::default();
    let password_bytes = password.expose_secret().as_bytes();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password_bytes, salt.as_salt().as_bytes(), &mut key)
        .expect("Key derivation failed");
    key
}

fn encrypt_data(key: &[u8; 32], plaintext: &[u8], encryption_level: u8) -> (Vec<u8>, [u8; 12]) {
    let mut nonce = [0u8; 12]; // 96 bits
    OsRng.fill_bytes(&mut nonce); // Securely generate a random nonce

    let ciphertext = match encryption_level {
        1 => {
            let cipher = Aes256Gcm::new(key.into());
            cipher
                .encrypt(&Nonce::from_slice(&nonce), plaintext)
                .expect("Encryption failed")
        }
        2 => {
            let cipher = ChaCha20Poly1305::new(key.into());
            cipher
                .encrypt(&Nonce::from_slice(&nonce), plaintext)
                .expect("Encryption failed")
        }
        _ => panic!("Invalid encryption level"),
    };

    (ciphertext, nonce)
}

fn decrypt_data(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    encryption_level: u8,
) -> Vec<u8> {
    match encryption_level {
        1 => {
            let cipher = Aes256Gcm::new(key.into());
            cipher
                .decrypt(&Nonce::from_slice(nonce), ciphertext)
                .expect("Decryption failed")
        }
        2 => {
            let cipher = ChaCha20Poly1305::new(key.into());
            cipher
                .decrypt(&Nonce::from_slice(nonce), ciphertext)
                .expect("Decryption failed")
        }
        _ => panic!("Invalid encryption level"),
    }
}

pub fn load_credentials(
    master_password: &SecretString,
) -> Result<(HashMap<String, Credential>, u8, SaltString, [u8; 12]), CredentialManagerError> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        let data = fs::read_to_string(&config_path).map_err(|_| CredentialManagerError::CredentialFileReadError)?;
        let json: serde_json::Value =
            serde_json::from_str(&data).map_err(|_| CredentialManagerError::JsonParseError)?;

        let encryption_level = json["encryption_level"]
            .as_u64()
            .ok_or(CredentialManagerError::InvalidEncryptionLevel)? as u8;
        let salt_str = json["salt"].as_str().ok_or(CredentialManagerError::InvalidSalt)?;
        let nonce_b64 = json["nonce"].as_str().ok_or(CredentialManagerError::InvalidNonce)?;
        let ciphertext_b64 = json["credentials"].as_str().ok_or(CredentialManagerError::InvalidCiphertext)?;

        let salt = SaltString::new(salt_str).map_err(|_| CredentialManagerError::InvalidSalt)?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(nonce_b64)
            .map_err(|_| CredentialManagerError::InvalidNonce)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext = general_purpose::STANDARD
            .decode(ciphertext_b64)
            .map_err(|_| CredentialManagerError::InvalidCiphertext)?;

        let key = derive_key(master_password, &salt);

        let decrypted_data = decrypt_data(&key, &ciphertext, &nonce, encryption_level);

        let credentials: HashMap<String, Credential> =
            serde_json::from_slice(&decrypted_data).map_err(|_| CredentialManagerError::JsonParseError)?;

        Ok((credentials, encryption_level, salt, nonce))
    } else {
        Ok((
            HashMap::new(),
            1,                                 // Default encryption level
            SaltString::generate(&mut OsRng),  // Generate new salt
            [0u8; 12],                         // Placeholder nonce
        ))
    }
}

pub fn save_credentials(
    credentials: &HashMap<String, Credential>,
    encryption_level: u8,
    salt: &SaltString,
    master_password: &SecretString,
) -> Result<(), CredentialManagerError> {
    let config_path = get_config_path()?;
    let plaintext = serde_json::to_vec(credentials).map_err(|_| CredentialManagerError::CredentialSerializationError)?;

    let key = derive_key(master_password, salt);

    let (ciphertext, nonce) = encrypt_data(&key, &plaintext, encryption_level);

    let data = json!({
        "encryption_level": encryption_level,
        "salt": salt.as_str(),
        "nonce": general_purpose::STANDARD.encode(&nonce),
        "credentials": general_purpose::STANDARD.encode(&ciphertext),
    });

    fs::write(&config_path, data.to_string()).map_err(|_| CredentialManagerError::CredentialFileWriteError)?;

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| CredentialManagerError::CredentialFilePermissionError)?;
    Ok(())
}
