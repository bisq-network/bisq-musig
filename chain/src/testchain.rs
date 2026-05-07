use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::Client;
use bdk_wallet::bitcoin::{Transaction, Txid};

use crate::ChainApi;

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
