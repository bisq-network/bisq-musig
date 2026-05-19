use std::sync::Arc;

use bdk_wallet::bitcoin::{Transaction, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse};

/// Abstraction over blockchain interaction for broadcasting transactions.
/// to be extended
pub trait ChainApi: Send + Sync {
    fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid>;
}

/// Abstraction over the read-side of a chain backend: pre-populating a transaction cache and
/// performing a full keychain scan. Wallet-level sync routines compose these primitives instead
/// of taking a hard dependency on a specific chain client (e.g. `BdkElectrumClient`).
pub trait ChainScanner {
    /// Insert transactions into the backend's transaction cache so it will not re-fetch them.
    /// Typically used to pre-populate the cache from an existing `TxGraph` before a scan.
    fn populate_tx_cache(&self, txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>);

    /// Full scan the keychain scripts described by `request` against the chain backend and return
    /// updates suitable for applying to a `bdk_wallet` data structure.
    fn full_scan<K: Ord + Clone>(
        &self,
        request: impl Into<FullScanRequest<K>>,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
    ) -> anyhow::Result<FullScanResponse<K>>;
}
