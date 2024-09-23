use clap::ArgMatches;
use crate::modules::{crypto, errors::CredentialManagerError, utils};
use colored::Colorize;
use secrecy::ExposeSecret;

pub fn handle_get_command(sub_m: &ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let master_password = utils::get_master_password(false)?;
    
    // Example usage of constant-time comparison:
    let stored_password = utils::get_master_password(false)?; // Load stored master password from secure storage
    if !utils::check_master_password(&stored_password, master_password.expose_secret()) {
        return Err(CredentialManagerError::InvalidPassword); // Replace with appropriate error handling
    }

    let (credentials, _, _, _) = crypto::load_credentials(&master_password)?;

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

    // Drop sensitive data explicitly
    drop(master_password);
    drop(stored_password);

    Ok(())
}
