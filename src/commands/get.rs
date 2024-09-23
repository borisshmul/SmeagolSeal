use clap::ArgMatches;
use crate::modules::{crypto, errors::CredentialManagerError, utils};
use colored::Colorize;
use secrecy::ExposeSecret;

pub fn handle_get_command(sub_m: &ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let master_password = utils::get_master_password(false)?;
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
    Ok(())
}
