use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::ChaCha20Poly1305;
use clap::{Arg, ArgAction, Command};
use dirs::config_dir;
use rand::{Rng, RngCore};
use rand_word::new as generate_words;
use rpassword::prompt_password;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;
use thiserror::Error;  // Import thiserror crate
use colored::*;        // Import colored crate


#[derive(Error, Debug)]
enum CredentialManagerError {
    #[error("Invalid length value")]
    InvalidLengthValue,
    #[error("Failed to read password")]
    PasswordReadError,
    // #[error("Passwords do not match")]
    // PasswordMismatch,
    #[error("Failed to read credentials file")]
    CredentialFileReadError,
    #[error("Failed to parse JSON")]
    JsonParseError,
    #[error("Invalid encryption level")]
    InvalidEncryptionLevel,
    #[error("Invalid salt")]
    InvalidSalt,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Failed to serialize credentials")]
    CredentialSerializationError,
    #[error("Failed to write credentials file")]
    CredentialFileWriteError,
    #[error("Failed to create configuration directory")]
    ConfigDirCreationError,
    #[error("Failed to set permissions on configuration directory")]
    ConfigDirPermissionError,
    #[error("Failed to set permissions on credentials file")]
    CredentialFilePermissionError,
}

#[derive(Serialize, Deserialize)]
struct Credential {
    username: String,
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    password: SecretString,
}

// Custom serialization for SecretString
fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

// Custom deserialization for SecretString
fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}

fn main() -> Result<(), CredentialManagerError> {
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("add", sub_m)) => handle_add_command(sub_m),
        Some(("get", sub_m)) => handle_get_command(sub_m),
        Some(("delete", sub_m)) => handle_delete_command(sub_m),
        Some(("list", _)) => handle_list_command(),
        Some(("generate-password", sub_m)) => handle_generate_password_command(sub_m),
        Some(("generate-passphrase", sub_m)) => handle_generate_passphrase_command(sub_m),
        _ => unreachable!(),
    }
}

fn build_cli() -> Command {
    Command::new("SmeagolSeal")
        .version("0.1.0")
        .author("Your Name <you@example.com>")
        .about("A fast and secure credential manager")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Add a new credential")
                .arg(Arg::new("service").required(true).help("Service name"))
                .arg(Arg::new("username").required(true).help("Username"))
                .arg(Arg::new("password").required(false).help("Password"))
                .arg(
                    Arg::new("generate-password")
                        .short('p')
                        .long("generate-password")
                        .help("Generate a strong random password")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("generate-passphrase")
                        .short('w')
                        .long("generate-passphrase")
                        .help("Generate a passphrase as the password")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("words")
                        .short('w')
                        .long("words")
                        .value_name("NUMBER_OF_WORDS")
                        .help("Number of words in the generated passphrase")
                        .default_value("4")
                        .requires("generate-passphrase"),
                )
                .arg(
                    Arg::new("length")
                        .short('l')
                        .long("length")
                        .value_name("LENGTH")
                        .help("Length of the generated password")
                        .default_value("16")
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-symbols")
                        .short('s')
                        .long("include-symbols")
                        .help("Include symbols in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("exclude-ambiguous")
                        .short('a')
                        .long("exclude-ambiguous")
                        .help("Exclude ambiguous characters (e.g., O, 0, I, l)")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-uppercase")
                        .short('u')
                        .long("include-uppercase")
                        .help("Include uppercase letters in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-lowercase")
                        .short('o')
                        .long("include-lowercase")
                        .help("Include lowercase letters in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-numbers")
                        .short('n')
                        .long("include-numbers")
                        .help("Include numbers in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("encryption")
                        .short('e')
                        .long("encryption")
                        .value_name("ENCRYPTION_LEVEL")
                        .help("Encryption level: 1 (AES-256-GCM), 2 (ChaCha20-Poly1305)")
                        .default_value("1"),
                ),
        )
        .subcommand(
            Command::new("get")
                .about("Retrieve a credential")
                .arg(Arg::new("service").required(true).help("Service name")),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a credential")
                .arg(Arg::new("service").required(true).help("Service name")),
        )
        .subcommand(Command::new("list").about("List all stored credentials"))
}

fn handle_add_command(sub_m: &clap::ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let username = sub_m.get_one::<String>("username").unwrap();

    let password = get_password(sub_m)?;
    
    // Display the generated password or passphrase
    println!("Generated password/passphrase: {}", password);

    validate_password_strength(&password)?;

    let master_password = get_master_password(false)?;

    let encryption_level = sub_m
        .get_one::<String>("encryption")
        .unwrap_or(&"1".to_string())
        .parse::<u8>()
        .unwrap_or(1);

    add_credential(service, username, &password, encryption_level, &master_password)?;

    // Drop the master password from memory as soon as it's no longer needed
    drop(master_password);

    Ok(())
}

fn handle_get_command(sub_m: &clap::ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    get_credential(service)?;
    Ok(())
}

fn handle_delete_command(sub_m: &clap::ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    delete_credential(service)?;
    Ok(())
}

fn handle_list_command() -> Result<(), CredentialManagerError> {
    list_credentials()?;
    Ok(())
}

fn handle_generate_password_command(sub_m: &clap::ArgMatches) -> Result<(), CredentialManagerError> {
    let password = get_password(sub_m)?;
    println!("Generated password: {}", password.green());
    Ok(())
}

fn handle_generate_passphrase_command(sub_m: &clap::ArgMatches) -> Result<(), CredentialManagerError> {
    let num_words = sub_m
        .get_one::<String>("words")
        .unwrap()
        .parse::<usize>()
        .map_err(|_| CredentialManagerError::InvalidLengthValue)?;

    validate_passphrase_length(num_words)?;

    let passphrase = generate_passphrase(num_words);
    println!("Generated passphrase: {}", passphrase.green());
    Ok(())
}

fn get_password(sub_m: &clap::ArgMatches) -> Result<String, CredentialManagerError> {
    if *sub_m.get_one::<bool>("generate-password").unwrap_or(&false) {
        generate_password_from_args(sub_m)
    } else if *sub_m.get_one::<bool>("generate-passphrase").unwrap_or(&false) {
        generate_passphrase_from_args(sub_m)
    } else if let Some(pass) = sub_m.get_one::<String>("password") {
        Ok(pass.clone())
    } else {
        // Prompt for password if not provided
        prompt_password("Enter password: ").map_err(|_| CredentialManagerError::PasswordReadError)
    }
}

fn generate_password_from_args(sub_m: &clap::ArgMatches) -> Result<String, CredentialManagerError> {
    let length = sub_m
        .get_one::<String>("length")
        .unwrap()
        .parse::<usize>()
        .map_err(|_| CredentialManagerError::InvalidLengthValue)?;

    validate_password_length(length)?;

    let include_symbols = *sub_m.get_one::<bool>("include-symbols").unwrap_or(&false);
    let exclude_ambiguous = *sub_m.get_one::<bool>("exclude-ambiguous").unwrap_or(&false);
    let include_uppercase = *sub_m.get_one::<bool>("include-uppercase").unwrap_or(&false);
    let include_lowercase = *sub_m.get_one::<bool>("include-lowercase").unwrap_or(&false);
    let include_numbers = *sub_m.get_one::<bool>("include-numbers").unwrap_or(&false);

    Ok(generate_password(
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
        exclude_ambiguous,
    ))
}

fn generate_passphrase_from_args(sub_m: &clap::ArgMatches) -> Result<String, CredentialManagerError> {
    let num_words = sub_m
        .get_one::<String>("words")
        .unwrap()
        .parse::<usize>()
        .map_err(|_| CredentialManagerError::InvalidLengthValue)?;

    validate_passphrase_length(num_words)?;

    Ok(generate_passphrase(num_words))
}

fn validate_password_length(length: usize) -> Result<(), CredentialManagerError> {
    if length < 8 {
        Err(CredentialManagerError::InvalidLengthValue)
    } else if length > 128 {
        Err(CredentialManagerError::InvalidLengthValue)
    } else {
        Ok(())
    }
}

fn validate_passphrase_length(num_words: usize) -> Result<(), CredentialManagerError> {
    if num_words < 4 || num_words > 10 {
        Err(CredentialManagerError::InvalidLengthValue)
    } else {
        Ok(())
    }
}

fn validate_password_strength(password: &str) -> Result<(), CredentialManagerError> {
    loop {
        let strength = check_password_strength(password);
        println!("Password strength: {}", strength.color(strength_color(&strength)));

        if strength == "Very Weak" || strength == "Weak" {
            println!("{}", "The password is too weak.".red());
            let input = prompt_for_confirmation("Do you want to proceed anyway? (y/n): ")?;

            if input == "y" || input == "yes" {
                break Ok(());
            } else if input == "n" || input == "no" {
                let _password = prompt_password("Enter a stronger password: ")
                    .map_err(|_| CredentialManagerError::PasswordReadError)?;
                continue;
            } else {
                println!("{}", "Invalid input. Please enter 'y' or 'n'.".red());
                continue;
            }
        } else {
            break Ok(());
        }
    }
}

fn prompt_for_confirmation(prompt: &str) -> Result<String, CredentialManagerError> {
    let mut input = String::new();
    println!("{}", prompt.yellow());
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|_| CredentialManagerError::PasswordReadError)?;
    Ok(input.trim().to_lowercase())
}

fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
    exclude_ambiguous: bool,
) -> String {
    let mut rng = rand::thread_rng();

    let charset = build_charset(include_uppercase, include_lowercase, include_numbers, include_symbols, exclude_ambiguous);
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect()
}

fn build_charset(
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
    exclude_ambiguous: bool,
) -> String {
    let mut charset = String::new();

    if include_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    if include_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }

    if include_numbers {
        charset.push_str("0123456789");
    }

    if include_symbols {
        charset.push_str("!@#$%^&*()-_=+[]{}|;:,.<>?");
    }

    if exclude_ambiguous {
        charset.retain(|c| !"O0Iil1".contains(c));
    }

    if charset.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
            .to_string()
    } else {
        charset
    }
}

fn generate_passphrase(num_words: usize) -> String {
    let words = generate_words(num_words); // Generate random words using the correct function
    let word_vec: Vec<&str> = words.split_whitespace().collect(); // Split the string into words
    word_vec.join("")
}

fn get_config_path() -> Result<PathBuf, CredentialManagerError> {
    let mut config_path = config_dir().ok_or(CredentialManagerError::ConfigDirCreationError)?;
    config_path.push("smeagol-seal");
    if !config_path.exists() {
        fs::create_dir_all(&config_path).map_err(|_| CredentialManagerError::ConfigDirCreationError)?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o700))
            .map_err(|_| CredentialManagerError::ConfigDirPermissionError)?;
    }
    config_path.push("credentials.json");
    Ok(config_path)
}

fn get_master_password(confirm: bool) -> Result<SecretString, CredentialManagerError> {
    loop {
        let password = SecretString::new(
            prompt_password("Enter master password: ")
                .map_err(|_| CredentialManagerError::PasswordReadError)?
                .into_boxed_str()
        );

        if confirm {
            let password_confirm = SecretString::new(
                prompt_password("Confirm master password: ")
                    .map_err(|_| CredentialManagerError::PasswordReadError)?
                    .into_boxed_str()
            );

            if password.expose_secret() != password_confirm.expose_secret() {
                println!("{}", "Passwords do not match. Please try again.".red());
                continue;
            }
        }

        return Ok(password);
    }
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

fn load_credentials(
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

fn save_credentials(
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

fn add_credential(
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

fn get_credential(service: &str) -> Result<(), CredentialManagerError> {
    let master_password = get_master_password(false)?;
    let (credentials, _, _, _) = load_credentials(&master_password)?;

    if let Some(credential) = credentials.get(service) {
        println!("{}", format!("Service: {}", service).cyan());
        println!("{}", format!("Username: {}", credential.username).cyan());
        println!(
            "{}",
            format!("Password: {}", credential.password.expose_secret()).cyan()
        );
    } else {
        println!("{}", "No credential found for service:".red());
        println!("{}", service.red());
    }
    Ok(())
}

fn delete_credential(service: &str) -> Result<(), CredentialManagerError> {
    let master_password = get_master_password(false)?;
    let (mut credentials, encryption_level, salt, _) = load_credentials(&master_password)?;

    if credentials.remove(service).is_some() {
        save_credentials(&credentials, encryption_level, &salt, &master_password)?;
        println!("{}", format!("Credential deleted for service: {}", service).green());
    } else {
        println!("{}", "No credential found for service:".red());
        println!("{}", service.red());
    }
    Ok(())
}

fn list_credentials() -> Result<(), CredentialManagerError> {
    let master_password = get_master_password(false)?;
    let (credentials, _, _, _) = load_credentials(&master_password)?;

    if credentials.is_empty() {
        println!("{}", "No credentials stored.".yellow());
    } else {
        println!("{}", "Stored services:".cyan());
        for service in credentials.keys() {
            println!("- {}", service.blue());
        }
    }
    Ok(())
}

fn check_password_strength(password: &str) -> String {
    let mut score = 0;
    if password.len() >= 8 {
        score += 1;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_lowercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_digit(10)) {
        score += 1;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        score += 1;
    }

    match score {
        5 => "Very Strong".to_string(),
        4 => "Strong".to_string(),
        3 => "Medium".to_string(),
        2 => "Weak".to_string(),
        _ => "Very Weak".to_string(),
    }
}

// Helper function to determine color based on strength
fn strength_color(strength: &str) -> Color {
    match strength {
        "Very Strong" => Color::Green,
        "Strong" => Color::BrightGreen,
        "Medium" => Color::Yellow,
        "Weak" => Color::BrightRed,
        "Very Weak" => Color::Red,
        _ => Color::White,
    }
}
