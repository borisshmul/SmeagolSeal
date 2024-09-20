use clap::ArgMatches;
use crate::{crypto, errors::CredentialManagerError};
use colored::Colorize;

pub fn handle_delete_command(sub_m: &ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let master_password = crate::utils::get_master_password(false)?;
    let (mut credentials, encryption_level, salt, _) = crypto::load_credentials(&master_password)?;

    if credentials.remove(service).is_some() {
        crypto::save_credentials(&credentials, encryption_level, &salt, &master_password)?;
        println!("{}", format!("Credential deleted for service: {}", service).green());
    } else {
        println!("{}", "No credential found for service:".red());
        println!("{}", service.red());
    }
    Ok(())
}
