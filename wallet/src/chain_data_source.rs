use bdk_electrum::electrum_client::Client;
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::PersistedWallet;

use crate::bmp_wallet::BMPWalletPersister;

pub trait ChainDataSource {
    const RECOVERY_HEIGHT: usize;
    const RECOVERY_LOOKAHEAD: usize;
    const BATCH_SIZE: usize;
    const STOP_GAP: usize;

    fn sync(&self, persister: &mut PersistedWallet<impl BMPWalletPersister>) -> anyhow::Result<()>;
}

impl ChainDataSource for BdkElectrumClient<Client> {
    // @TODO: revisit these values for having suitable one
    const STOP_GAP: usize = 10;
    const BATCH_SIZE: usize = 16;
    const RECOVERY_LOOKAHEAD: usize = 50;
    const RECOVERY_HEIGHT: usize = 190_000;

    fn sync(&self, persister: &mut PersistedWallet<impl BMPWalletPersister>) -> anyhow::Result<()> {
        // Populate the electrum client's transaction cache so it doesn't redownload transaction we
        // already have.
        self.populate_tx_cache(persister.tx_graph().full_txs().map(|tx_node| tx_node.tx));
        let request = persister.start_full_scan();

        let updates = self
            .full_scan(request, Self::STOP_GAP, Self::BATCH_SIZE, false)
            .expect("Should be able to start full scan request");

        persister.apply_update(updates)?;

        Ok(())
    }
}
