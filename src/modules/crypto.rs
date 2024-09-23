use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2};
use base64::engine::general_purpose;
use base64::Engine;  // Import the Engine trait to use the encode and decode methods
use secrecy::{ExposeSecret, SecretString, SecretBox}; // SecretBox is used for secure memory handling of binary data
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use crate::modules::errors::CredentialManagerError;
use crate::modules::models::Credential;
use crate::modules::utils::get_config_path;
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
    // Load existing credentials from storage
    let (mut credentials, _, salt, _) = load_credentials(master_password)?;

    // Create a new credential with the provided service, username, and password
    let credential = Credential {
        username: username.to_string(),
        password: SecretString::from(password.to_string()),
    };

    // Insert the new credential into the credentials HashMap
    credentials.insert(service.to_string(), credential);

    // Save the updated credentials to storage
    save_credentials(&credentials, encryption_level, &salt, master_password)?;
    println!("{}", format!("Credential added for service: {}", service).green());
    Ok(())
}

// Derives a cryptographic key from the master password and salt using Argon2
// The derived key is wrapped in SecretBox for secure in-memory handling
fn derive_key(password: &SecretString, salt: &SaltString) -> SecretBox<[u8; 32]> {
    let argon2 = Argon2::default(); // Argon2 is used for password hashing and key derivation
    let password_bytes = password.expose_secret().as_bytes(); // Expose the secret to get the raw bytes
    let mut key = [0u8; 32]; // 256-bit key for AES-256 encryption

    // Derive the key using Argon2 and the provided salt
    argon2
        .hash_password_into(password_bytes, salt.as_salt().as_bytes(), &mut key)
        .expect("Key derivation failed");

    // Wrap the derived key in SecretBox to ensure it is securely handled in memory
    SecretBox::new(Box::new(key))
}

// Encrypts the plaintext using the provided key and encryption level (AES or ChaCha20)
fn encrypt_data(key: &SecretBox<[u8; 32]>, plaintext: &[u8], encryption_level: u8) -> (Vec<u8>, [u8; 12]) {
    let mut nonce = [0u8; 12]; // Nonce for encryption (96 bits)
    OsRng.fill_bytes(&mut nonce); // Securely generate a random nonce

    // Choose the encryption algorithm based on the specified level
    let ciphertext = match encryption_level {
        1 => {
            let cipher = Aes256Gcm::new(key.expose_secret().into()); // AES-256-GCM encryption
            cipher
                .encrypt(&Nonce::from_slice(&nonce), plaintext)
                .expect("Encryption failed")
        }
        2 => {
            let cipher = ChaCha20Poly1305::new(key.expose_secret().into()); // ChaCha20-Poly1305 encryption
            cipher
                .encrypt(&Nonce::from_slice(&nonce), plaintext)
                .expect("Encryption failed")
        }
        _ => panic!("Invalid encryption level"), // Panic if an invalid encryption level is provided
    };

    (ciphertext, nonce) // Return the ciphertext and nonce
}

// Decrypts the ciphertext using the provided key and encryption level (AES or ChaCha20)
fn decrypt_data(
    key: &SecretBox<[u8; 32]>, // The key is securely handled with SecretBox
    ciphertext: &[u8],
    nonce: &[u8; 12],
    encryption_level: u8,
) -> Vec<u8> {
    // Choose the decryption algorithm based on the specified level
    match encryption_level {
        1 => {
            let cipher = Aes256Gcm::new(key.expose_secret().into()); // AES-256-GCM decryption
            cipher
                .decrypt(&Nonce::from_slice(nonce), ciphertext)
                .expect("Decryption failed")
        }
        2 => {
            let cipher = ChaCha20Poly1305::new(key.expose_secret().into()); // ChaCha20-Poly1305 decryption
            cipher
                .decrypt(&Nonce::from_slice(nonce), ciphertext)
                .expect("Decryption failed")
        }
        _ => panic!("Invalid encryption level"), // Panic if an invalid encryption level is provided
    }
}

// Loads credentials from the stored configuration file
pub fn load_credentials(
    master_password: &SecretString,
) -> Result<(HashMap<String, Credential>, u8, SaltString, [u8; 12]), CredentialManagerError> {
    let config_path = get_config_path()?; // Get the path to the configuration file
    if config_path.exists() {
        let data = fs::read_to_string(&config_path).map_err(|_| CredentialManagerError::CredentialFileReadError)?;
        let json: serde_json::Value =
            serde_json::from_str(&data).map_err(|_| CredentialManagerError::JsonParseError)?;

        // Extract encryption details from the stored JSON
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

        // Derive the key using the master password and the extracted salt
        let key = derive_key(master_password, &salt);

        // Decrypt the stored credentials
        let decrypted_data = decrypt_data(&key, &ciphertext, &nonce, encryption_level);

        // Deserialize the decrypted data into a HashMap of credentials
        let credentials: HashMap<String, Credential> =
            serde_json::from_slice(&decrypted_data).map_err(|_| CredentialManagerError::JsonParseError)?;

        // Return the credentials, encryption level, salt, and nonce
        Ok((credentials, encryption_level, salt, nonce))
    } else {
        // If the file doesn't exist, return an empty set of credentials and default encryption settings
        Ok((
            HashMap::new(),
            1,                                 // Default encryption level
            SaltString::generate(&mut OsRng),  // Generate new salt
            [0u8; 12],                         // Placeholder nonce
        ))
    }
}

// Saves credentials to the configuration file securely
pub fn save_credentials(
    credentials: &HashMap<String, Credential>,
    encryption_level: u8,
    salt: &SaltString,
    master_password: &SecretString,
) -> Result<(), CredentialManagerError> {
    let config_path = get_config_path()?; // Get the path to the configuration file

    // Serialize the credentials to a JSON format
    let plaintext = serde_json::to_vec(credentials).map_err(|_| CredentialManagerError::CredentialSerializationError)?;

    // Derive a key from the master password and the provided salt
    let key = derive_key(master_password, salt);

    // Encrypt the serialized credentials
    let (ciphertext, nonce) = encrypt_data(&key, &plaintext, encryption_level);

    // Prepare the JSON object to store the encrypted data
    let data = json!({
        "encryption_level": encryption_level,
        "salt": salt.as_str(),
        "nonce": general_purpose::STANDARD.encode(&nonce),
        "credentials": general_purpose::STANDARD.encode(&ciphertext),
    });

    // Write the encrypted data to the configuration file
    fs::write(&config_path, data.to_string()).map_err(|_| CredentialManagerError::CredentialFileWriteError)?;

    // Set file permissions to be read/write for the owner only (0600)
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| CredentialManagerError::CredentialFilePermissionError)?;
    
    Ok(())
}
