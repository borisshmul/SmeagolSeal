use thiserror::Error;

#[derive(Error, Debug)]
pub enum CredentialManagerError {
    #[error("Invalid length value")]
    InvalidLengthValue,
    #[error("Failed to read password")]
    PasswordReadError,
    #[error("Failed to read credentials file")]
    CredentialFileReadError,
    #[error("Failed to parse JSON")]
    JsonParseError,
    #[error("Invalid encryption level")]
    InvalidEncryptionLevel,
    #[error("Invalid salt")]
    InvalidSalt,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Failed to serialize credentials")]
    CredentialSerializationError,
    #[error("Failed to write credentials file")]
    CredentialFileWriteError,
    #[error("Failed to create configuration directory")]
    ConfigDirCreationError,
    #[error("Failed to set permissions on configuration directory")]
    ConfigDirPermissionError,
    #[error("Failed to set permissions on credentials file")]
    CredentialFilePermissionError,
}
