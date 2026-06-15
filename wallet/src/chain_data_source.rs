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

/// `ChainDataSource` implementation for the Electrum-backed [`testenv::Testchain`] handle.
///
/// `Testchain` lives in the `testenv` crate alongside `TestEnv`; this impl ties it into the
/// wallet's sync routine. It mirrors the values previously used by the live Electrum-backed
/// implementation.
impl ChainDataSource for testenv::Testchain {
    const RECOVERY_HEIGHT: usize = 190_000;
    const BATCH_SIZE: usize = 16;
    const STOP_GAP: usize = 10;

    fn sync(&self, persister: &mut PersistedWallet<impl BMPWalletPersister>) -> anyhow::Result<()> {
        let tx_nodes = persister.tx_graph().full_txs().map(|tx_node| tx_node.tx);
        self.populate_tx_cache(tx_nodes);
        let request = persister.start_full_scan();

        let updates = self
            .full_scan(request, Self::STOP_GAP, Self::BATCH_SIZE, false)?;

        persister.apply_update(updates)?;

        Ok(())
    }
}
