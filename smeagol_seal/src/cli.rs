use clap::{Arg, ArgAction, Command};

pub fn build_cli() -> Command {
    Command::new("SmeagolSeal")
        .version("0.1.0")
        .author("Your Name <you@example.com>")
        .about("A fast and secure credential manager")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Add a new credential")
                .arg(Arg::new("service").required(true).help("Service name"))
                .arg(Arg::new("username").required(true).help("Username"))
                .arg(Arg::new("password").required(false).help("Password"))
                .arg(
                    Arg::new("generate-password")
                        .short('p')
                        .long("generate-password")
                        .help("Generate a strong random password")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("generate-passphrase")
                        .short('w')
                        .long("generate-passphrase")
                        .help("Generate a passphrase as the password")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("words")
                        .short('w')
                        .long("words")
                        .value_name("NUMBER_OF_WORDS")
                        .help("Number of words in the generated passphrase")
                        .default_value("4")
                        .requires("generate-passphrase"),
                )
                .arg(
                    Arg::new("length")
                        .short('l')
                        .long("length")
                        .value_name("LENGTH")
                        .help("Length of the generated password")
                        .default_value("16")
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-symbols")
                        .short('s')
                        .long("include-symbols")
                        .help("Include symbols in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("exclude-ambiguous")
                        .short('a')
                        .long("exclude-ambiguous")
                        .help("Exclude ambiguous characters (e.g., O, 0, I, l)")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-uppercase")
                        .short('u')
                        .long("include-uppercase")
                        .help("Include uppercase letters in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-lowercase")
                        .short('o')
                        .long("include-lowercase")
                        .help("Include lowercase letters in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("include-numbers")
                        .short('n')
                        .long("include-numbers")
                        .help("Include numbers in the generated password")
                        .action(ArgAction::SetTrue)
                        .requires("generate-password"),
                )
                .arg(
                    Arg::new("encryption")
                        .short('e')
                        .long("encryption")
                        .value_name("ENCRYPTION_LEVEL")
                        .help("Encryption level: 1 (AES-256-GCM), 2 (ChaCha20-Poly1305)")
                        .default_value("1"),
                ),
        )
        .subcommand(
            Command::new("get")
                .about("Retrieve a credential")
                .arg(Arg::new("service").required(true).help("Service name")),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a credential")
                .arg(Arg::new("service").required(true).help("Service name")),
        )
        .subcommand(Command::new("list").about("List all stored credentials"))
}
