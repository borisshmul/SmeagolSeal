use crate::{crypto, errors::CredentialManagerError};
use colored::Colorize;

pub fn handle_list_command() -> Result<(), CredentialManagerError> {
    let master_password = crate::utils::get_master_password(false)?;
    let (credentials, _, _, _) = crypto::load_credentials(&master_password)?;

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
