use crate::modules::utils;
use clap::ArgMatches;
use crate::modules::{crypto, errors::CredentialManagerError};
use colored::Colorize;
use secrecy::ExposeSecret;

pub fn handle_delete_command(sub_m: &ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let master_password = utils::get_master_password(false)?;
    let (mut credentials, encryption_level, salt, _) = crypto::load_credentials(&master_password)?;

    // Example usage of constant-time comparison:
    let stored_password = utils::get_master_password(false)?; // You may need to load the stored master password from your config or secure storage
    if !utils::check_master_password(&stored_password, master_password.expose_secret()) {
        return Err(CredentialManagerError::InvalidPassword); // Replace this with an appropriate error type
    }

    if credentials.remove(service).is_some() {
        crypto::save_credentials(&credentials, encryption_level, &salt, &master_password)?;
        println!("{}", format!("Credential deleted for service: {}", service).green());
    } else {
        println!("{}", "No credential found for service:".red());
        println!("{}", service.red());
    }
    
    // Drop sensitive data explicitly
    drop(master_password);
    drop(stored_password);

    Ok(())
}
