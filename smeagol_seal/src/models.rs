use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use secrecy::ExposeSecret;

#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub password: SecretString,
}

// Custom serialization for SecretString
fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

// Custom deserialization for SecretString
fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}
