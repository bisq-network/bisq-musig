use bdk_wallet::PersistedWallet;
use chain::ChainScanner;

use crate::bmp_wallet::BMPWalletPersister;

pub trait ChainDataSource {
    const RECOVERY_HEIGHT: usize;
    const BATCH_SIZE: usize;
    const STOP_GAP: usize;

    fn sync(&self, _persister: &mut PersistedWallet<impl BMPWalletPersister>)
    -> anyhow::Result<()>;
}

/// `ChainDataSource` implementation for the Electrum-backed test scaffold [`chain::Testchain`].
///
/// Gated behind the `test-support` feature so the wallet crate doesn't take a non-test dependency
/// on the test-only chain backend. The crate's own integration and unit tests activate this
/// feature via a self-dev-dependency in `Cargo.toml`; downstream crates that exercise the wallet
/// against a real Electrum node should depend on `wallet` with `features = ["test-support"]`.
#[cfg(feature = "test-support")]
impl ChainDataSource for chain::Testchain {
    const RECOVERY_HEIGHT: usize = 190_000;
    const BATCH_SIZE: usize = 16;
    // Mirror the values previously used by the live Electrum-backed implementation; `Testchain`
    // is a thin wrapper around a `BdkElectrumClient` used only in integration tests.
    const STOP_GAP: usize = 10;

    fn sync(&self, persister: &mut PersistedWallet<impl BMPWalletPersister>) -> anyhow::Result<()> {
        let stop_gap = Self::STOP_GAP;
        let batch_size = Self::BATCH_SIZE;
        let tx_nodes = persister.tx_graph().full_txs().map(|tx_node| tx_node.tx);
        self.populate_tx_cache(tx_nodes);
        let request = persister.start_full_scan();

        let updates = self
            .full_scan(request, stop_gap, batch_size, false)
            .expect("Should be able to start full scan request");

        persister.apply_update(updates)?;

        Ok(())
    }
}
