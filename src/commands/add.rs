use clap::ArgMatches;
use secrecy::{ExposeSecret, SecretString};
use crate::modules::{crypto, errors::CredentialManagerError, utils::*};
use crate::modules::utils;

pub fn handle_add_command(sub_m: &ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let username = sub_m.get_one::<String>("username").unwrap();

    // Convert the String to Box<str> and then create a SecretString
    let password = SecretString::new(get_password(sub_m)?.into());

    // Securely print the generated password/passphrase (if necessary)
    println!("Generated password/passphrase: {}", password.expose_secret());

    // Validate the password strength (this method needs a &str, so we expose it)
    validate_password_strength(password.expose_secret())?;

    // Get the master password securely and convert it to SecretString
    let master_password = get_master_password(false)?;

    // Example usage of constant-time comparison:
    let stored_password = utils::get_master_password(false)?; // Load stored master password from secure storage
    if !utils::check_master_password(&stored_password, master_password.expose_secret()) {
        return Err(CredentialManagerError::InvalidPassword); // Replace with appropriate error handling
    }

    let encryption_level = sub_m
        .get_one::<String>("encryption")
        .unwrap_or(&"1".to_string())
        .parse::<u8>()
        .unwrap_or(1);

    // Add the credential using the securely stored password and master password
    crypto::add_credential(service, username, password.expose_secret(), encryption_level, &master_password)?;

    // Explicitly drop sensitive data as soon as it is no longer needed
    drop(password);
    drop(master_password);
    drop(stored_password);

    Ok(())
}
