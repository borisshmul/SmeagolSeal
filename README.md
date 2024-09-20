# SmeagolSeal

**SmeagolSeal** is a fast and secure credential manager written in Rust. It provides a simple and efficient way to securely store, retrieve, and manage your credentials using strong encryption standards. The tool supports generating random passwords and passphrases, making it easy to create secure credentials on the fly.

## Features

- **Add Credentials**: Securely store credentials (username and password) for different services.
- **Retrieve Credentials**: Retrieve and decrypt stored credentials with your master password.
- **Delete Credentials**: Remove credentials from your secure store.
- **List Stored Services**: List all the services for which credentials are stored.
- **Generate Strong Passwords**: Generate strong, customizable random passwords.
- **Generate Memorable Passphrases**: Generate passphrases using random words.
- **Customizable Encryption Levels**: Choose between AES-256-GCM and ChaCha20-Poly1305 encryption algorithms.
- **Strong Password Validation**: Validate the strength of passwords before storing them.

## Installation

To use **SmeagolSeal**, you'll need to have Rust installed. You can install the tool using `cargo`:

```bash
cargo install smeagol_seal
```

Alternatively, you can clone the repository and build it manually:

```
git clone https://github.com/borisshmul/smeagol_seal.git
cd smeagol_seal
cargo build --release
```

## Options

### Global Options

- `-h`, `--help`: Print help information.
- `-V`, `--version`: Print version information.

### `add` Command Options

- `<service>`: The name of the service for which to add a credential.
- `<username>`: The username for the service.
- `-p`, `--password <password>`: The password for the service (optional, will prompt if not provided).
- `-g`, `--generate-password`: Generate a strong random password.
- `-p`, `--generate-passphrase`: Generate a passphrase as the password.
- `-w`, `--words <NUMBER_OF_WORDS>`: Number of words in the generated passphrase (default: 4).
- `-l`, `--length <LENGTH>`: Length of the generated password (default: 16).
- `-s`, `--include-symbols`: Include symbols in the generated password.
- `-a`, `--exclude-ambiguous`: Exclude ambiguous characters (e.g., O, 0, I, l).
- `-u`, `--include-uppercase`: Include uppercase letters in the generated password.
- `-o`, `--include-lowercase`: Include lowercase letters in the generated password.
- `-n`, `--include-numbers`: Include numbers in the generated password.
- `-e`, `--encryption <ENCRYPTION_LEVEL>`: Encryption level: 1 (AES-256-GCM), 2 (ChaCha20-Poly1305) (default: 1).

### `get` Command Options

- `<service>`: The name of the service for which to retrieve the credential.

### `delete` Command Options

- `<service>`: The name of the service for which to delete the credential.

### `generate-password` Command Options

- `-l`, `--length <LENGTH>`: Length of the generated password (default: 16).
- `-s`, `--include-symbols`: Include symbols in the generated password.
- `-a`, `--exclude-ambiguous`: Exclude ambiguous characters (e.g., O, 0, I, l).
- `-u`, `--include-uppercase`: Include uppercase letters in the generated password.
- `-o`, `--include-lowercase`: Include lowercase letters in the generated password.
- `-n`, `--include-numbers`: Include numbers in the generated password.

### `generate-passphrase` Command Options

- `-w`, `--words <NUMBER_OF_WORDS>`: Number of words in the passphrase (default: 4).

