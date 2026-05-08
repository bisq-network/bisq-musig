use std::sync::Arc;

use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::Client;
use bdk_wallet::bitcoin::{Transaction, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse};

use crate::{ChainApi, ChainScanner};

/// Electrum-backed [`ChainApi`] for use in integration tests and temporary scaffolding.
///
/// Gated behind the `test-support` feature rather than `#[cfg(test)]` because the `rpc` crate
/// currently uses it in non-test code as a placeholder chain backend. Once `rpc` switches to a
/// real implementation, this can move behind `#[cfg(test)]` and the feature flag can be dropped.
pub struct Testchain {
    client: BdkElectrumClient<Client>,
}

impl Testchain {
    pub const fn new(client: BdkElectrumClient<Client>) -> Self {
        Self { client }
    }
}

impl ChainApi for Testchain {
    fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        match self.client.transaction_broadcast(tx) {
            Ok(txid) => Ok(txid),
            Err(e) if e.to_string().contains("Transaction already in block chain") => {
                Ok(tx.compute_txid())
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl ChainScanner for Testchain {
    fn populate_tx_cache(&self, txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>) {
        self.client.populate_tx_cache(txs);
    }

    fn full_scan<K: Ord + Clone>(
        &self,
        request: impl Into<FullScanRequest<K>>,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
    ) -> anyhow::Result<FullScanResponse<K>> {
        self.client
            .full_scan(request, stop_gap, batch_size, fetch_prev_txouts)
            .map_err(Into::into)
    }
}
