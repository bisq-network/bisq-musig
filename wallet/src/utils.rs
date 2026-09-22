use argon2::{Argon2, Block, Params};
use bdk_wallet::bitcoin::hashes::{Hash as _, sha256};
use zeroize::{Zeroize as _, Zeroizing};

/// Derives a 256-bit key from a password and salt using Argon2.
///
/// The returned hex-encoded key is wrapped in [`Zeroizing`], so it is wiped from memory on drop:
/// pass it to `PRAGMA key`/`rekey` and let it go out of scope rather than storing it. When a
/// password needs to be verifiable later, retain [`key_verifier`]'s one-way fingerprint instead
/// of the key.
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> anyhow::Result<Zeroizing<String>> {
    let argon2 = Argon2::default();
    let mut memory = vec![Block::default(); Params::DEFAULT_M_COST as usize];
    let mut key_bytes = [0u8; 32];

    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut key_bytes, &mut memory)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let key_hex = Zeroizing::new(hex::encode(key_bytes));

    key_bytes.zeroize();

    Ok(key_hex)
}

/// A one-way fingerprint of a derived database key.
///
/// Safe to keep in memory for verifying a later password attempt (re-derive, fingerprint,
/// compare): unlike the key itself, the fingerprint cannot be used to open the database.
#[must_use]
pub fn key_verifier(key_hex: &str) -> [u8; 32] {
    sha256::Hash::hash(key_hex.as_bytes()).to_byte_array()
}
