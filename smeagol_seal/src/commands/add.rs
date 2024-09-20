use clap::ArgMatches;
use crate::{crypto, errors::CredentialManagerError, utils::*};

pub fn handle_add_command(sub_m: &ArgMatches) -> Result<(), CredentialManagerError> {
    let service = sub_m.get_one::<String>("service").unwrap();
    let username = sub_m.get_one::<String>("username").unwrap();

    let password = get_password(sub_m)?;
    
    println!("Generated password/passphrase: {}", password);

    validate_password_strength(&password)?;

    let master_password = get_master_password(false)?;

    let encryption_level = sub_m
        .get_one::<String>("encryption")
        .unwrap_or(&"1".to_string())
        .parse::<u8>()
        .unwrap_or(1);

    crypto::add_credential(service, username, &password, encryption_level, &master_password)?;

    drop(master_password);

    Ok(())
}
