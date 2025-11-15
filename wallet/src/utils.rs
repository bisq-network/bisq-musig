use std::fs;

use argon2::{Argon2, Block, Params};
use base64::engine::general_purpose;
use base64::Engine;
use zeroize::Zeroize;

/// Derives a 256-bit key from a password and salt using Argon2.
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> anyhow::Result<String> {
    let argon2 = Argon2::default();
    let mut memory = vec![Block::default(); Params::DEFAULT_M_COST as usize];
    let mut key_bytes = [0u8; 32];

    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut key_bytes, &mut memory)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let key_hex = hex::encode(key_bytes);

    key_bytes.zeroize();

    Ok(key_hex)
}

pub fn get_salt(db_path: &str) -> anyhow::Result<Vec<u8>> {
    let salt_path = format!("{db_path}.salt");
    let salt_str = fs::read_to_string(&salt_path)?;
    Ok(general_purpose::STANDARD.decode(salt_str.as_bytes())?)
}
