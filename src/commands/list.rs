use crate::modules::{crypto, errors::CredentialManagerError, utils};
use colored::Colorize;
use secrecy::ExposeSecret;

pub fn handle_list_command() -> Result<(), CredentialManagerError> {
    let master_password = utils::get_master_password(false)?;
    
    // Example usage of constant-time comparison:
    let stored_password = utils::get_master_password(false)?; // Load stored master password from secure storage
    if !utils::check_master_password(&stored_password, master_password.expose_secret()) {
        return Err(CredentialManagerError::InvalidPassword); // Replace with appropriate error handling
    }

    let (credentials, _, _, _) = crypto::load_credentials(&master_password)?;

    if credentials.is_empty() {
        println!("{}", "No credentials stored.".yellow());
    } else {
        println!("{}", "Stored services:".cyan());
        for service in credentials.keys() {
            println!("- {}", service.blue());
        }
    }

    // Drop sensitive data explicitly
    drop(master_password);
    drop(stored_password);

    Ok(())
}
