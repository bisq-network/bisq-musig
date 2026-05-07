use bdk_wallet::bitcoin::{Transaction, Txid};

/// Abstraction over blockchain interaction for broadcasting transactions.
/// to be extended
pub trait ChainApi: Send + Sync {
    fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid>;
}

#[cfg(feature = "test-support")]
mod testchain;

#[cfg(feature = "test-support")]
pub use testchain::Testchain;
