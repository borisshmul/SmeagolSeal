use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use dirs::config_dir;
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use clap::ArgMatches;
use rand::Rng;
use rpassword::prompt_password;
use crate::errors::CredentialManagerError;

pub fn validate_password_strength(password: &str) -> Result<(), CredentialManagerError> {
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

pub fn get_password(sub_m: &ArgMatches) -> Result<String, CredentialManagerError> {
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

pub fn generate_password_from_args(sub_m: &ArgMatches) -> Result<String, CredentialManagerError> {
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

pub fn generate_passphrase_from_args(sub_m: &ArgMatches) -> Result<String, CredentialManagerError> {
    let num_words = sub_m
        .get_one::<String>("words")
        .unwrap()
        .parse::<usize>()
        .map_err(|_| CredentialManagerError::InvalidLengthValue)?;

    validate_passphrase_length(num_words)?;

    Ok(generate_passphrase(num_words))
}

pub fn get_master_password(confirm: bool) -> Result<SecretString, CredentialManagerError> {
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

pub fn get_config_path() -> Result<PathBuf, CredentialManagerError> {
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

pub fn validate_password_length(length: usize) -> Result<(), CredentialManagerError> {
    if length < 8 {
        Err(CredentialManagerError::InvalidLengthValue)
    } else if length > 128 {
        Err(CredentialManagerError::InvalidLengthValue)
    } else {
        Ok(())
    }
}

pub fn validate_passphrase_length(num_words: usize) -> Result<(), CredentialManagerError> {
    if num_words < 4 || num_words > 10 {
        Err(CredentialManagerError::InvalidLengthValue)
    } else {
        Ok(())
    }
}

pub fn check_password_strength(password: &str) -> String {
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
pub fn strength_color(strength: &str) -> colored::Color {
    match strength {
        "Very Strong" => colored::Color::Green,
        "Strong" => colored::Color::BrightGreen,
        "Medium" => colored::Color::Yellow,
        "Weak" => colored::Color::BrightRed,
        "Very Weak" => colored::Color::Red,
        _ => colored::Color::White,
    }
}

pub fn prompt_for_confirmation(prompt: &str) -> Result<String, CredentialManagerError> {
    let mut input = String::new();
    println!("{}", prompt.yellow());
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|_| CredentialManagerError::PasswordReadError)?;
    Ok(input.trim().to_lowercase())
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

pub fn generate_password(
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

pub fn generate_passphrase(num_words: usize) -> String {
    let words = rand_word::new(num_words); // Generate random words using the correct function
    let word_vec: Vec<&str> = words.split_whitespace().collect(); // Split the string into words
    word_vec.join("")
}
