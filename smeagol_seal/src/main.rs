mod cli;
mod commands;
mod crypto;
mod errors;
mod models;
mod utils;

use errors::CredentialManagerError;

fn main() -> Result<(), CredentialManagerError> {
    let matches = cli::build_cli().get_matches();

    match matches.subcommand() {
        Some(("add", sub_m)) => commands::add::handle_add_command(sub_m),
        Some(("get", sub_m)) => commands::get::handle_get_command(sub_m),
        Some(("delete", sub_m)) => commands::delete::handle_delete_command(sub_m),
        Some(("list", _)) => commands::list::handle_list_command(),
        _ => unreachable!(),
    }
}
