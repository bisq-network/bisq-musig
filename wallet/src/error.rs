use bdk_wallet::bitcoin::bip32;
use bdk_wallet::bitcoin::psbt::ExtractTxError;
use bdk_wallet::chain::DescriptorId;
use bdk_wallet::descriptor::DescriptorError;
use bdk_wallet::miniscript::descriptor::ConversionError;
use bdk_wallet::signer::SignerError;
use bdk_wallet::{CreateWithPersistError, LoadWithPersistError, rusqlite};
use thiserror::Error;

use crate::persisted::PersistenceError;

pub type Result<T, E = WalletErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ChainDataSourceError {
    #[error("chain scanner error: {0}")]
    Scanner(#[from] chain::SyncError),
    #[error("chain scanner returned an update for unknown descriptor {descriptor:?}")]
    UnknownDescriptor { descriptor: DescriptorId },
    #[error("chain scanner returned an update for missing wallet index {index}")]
    MissingWallet { index: usize },
    #[error("failed to apply chain update: {0}")]
    ApplyUpdate(#[from] bdk_wallet::chain::local_chain::CannotConnectError),
    #[error("full scan failed: {0}")]
    FullScan(#[from] chain::FullScanError),
}

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum WalletErrorKind {
    Miniscript(#[from] bdk_wallet::miniscript::Error),
    Persistence(#[from] PersistenceError),
    #[error("failed to derive database key: {0}")]
    KeyDerivation(#[from] argon2::Error),
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
    #[error("wallet database already exists; refusing to overwrite it")]
    WalletAlreadyExists,
    ExtractTx(#[from] Box<ExtractTxError>),
    LoadWallet(#[from] LoadWithPersistError<rusqlite::Error>),
    CreateWallet(#[from] CreateWithPersistError<rusqlite::Error>),
    Bip32(#[from] bip32::Error),
    Descriptor(#[from] DescriptorError),
    Mnemonic(#[from] bdk_wallet::keys::bip39::Error),
    Electrum(#[from] bdk_electrum::electrum_client::Error),
    ApplyUpdate(#[from] bdk_wallet::chain::local_chain::CannotConnectError),
    ChainDataSource(#[from] ChainDataSourceError),
    Generic(Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl WalletErrorKind {
    pub fn generic<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Generic(Box::new(err))
    }
}

impl From<ExtractTxError> for WalletErrorKind {
    fn from(value: ExtractTxError) -> Self {
        Self::ExtractTx(Box::new(value))
    }
}

impl From<rusqlite::Error> for WalletErrorKind {
    fn from(value: rusqlite::Error) -> Self {
        PersistenceError::Database(value).into()
    }
}
