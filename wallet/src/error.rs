use bdk_wallet::bitcoin::bip32;
use bdk_wallet::bitcoin::psbt::ExtractTxError;
use bdk_wallet::descriptor::DescriptorError;
use bdk_wallet::miniscript::descriptor::ConversionError;
use bdk_wallet::signer::SignerError;
use bdk_wallet::{CreateWithPersistError, LoadWithPersistError, rusqlite};
use thiserror::Error;

use crate::persisted::PersistenceError;

pub type Result<T, E = WalletErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum WalletErrorKind {
    Miniscript(#[from] bdk_wallet::miniscript::Error),
    Persistence(#[from] PersistenceError),
    #[error("failed to derive database key: {0}")]
    KeyDerivation(String),
    #[error("Invalid Password provided")]
    InvalidPassword,
    Signer(#[from] SignerError),
    #[error("not a Taproot address")]
    NotTaprootAddress,
    #[error("malformed PSBT")]
    MalformedPsbt,
    Conversion(#[from] ConversionError),
    CreateTx(#[from] bdk_wallet::error::CreateTxError),
    #[error("imported key descriptor does not match its secret key")]
    MismatchedDescriptor,
    #[error("no wallet loaded")]
    NoWallet,
    #[error("Wallet has no stored seed phrase")]
    MissingSeedPhrase,
    ExtractTx(#[from] Box<ExtractTxError>),
    LoadWallet(#[from] LoadWithPersistError<rusqlite::Error>),
    CreateWallet(#[from] CreateWithPersistError<rusqlite::Error>),
    Bip32(#[from] bip32::Error),
    Descriptor(#[from] DescriptorError),
    Mnemonic(#[from] bdk_wallet::keys::bip39::Error),
    Generic(Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl WalletErrorKind {
    pub fn generic<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Generic(Box::new(err))
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self::Generic(message.into().into())
    }
}

impl From<ExtractTxError> for WalletErrorKind {
    fn from(value: ExtractTxError) -> Self {
        Self::ExtractTx(Box::new(value))
    }
}

impl From<argon2::Error> for WalletErrorKind {
    fn from(value: argon2::Error) -> Self {
        Self::KeyDerivation(value.to_string())
    }
}

impl From<rusqlite::Error> for WalletErrorKind {
    fn from(value: rusqlite::Error) -> Self {
        PersistenceError::Database(value).into()
    }
}
