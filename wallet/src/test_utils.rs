use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{Amount, BlockHash};
use bdk_wallet::chain::BlockId;
use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
use bdk_wallet::PersistedWallet;

use crate::bmp_wallet::BMPWalletPersister;
use crate::chain_data_source::ChainDataSource;
pub struct MockedBDKElectrum;

impl ChainDataSource for MockedBDKElectrum {
    const RECOVERY_HEIGHT: usize = 10;
    const RECOVERY_LOOKAHEAD: usize = 10;
    const BATCH_SIZE: usize = 10;
    const STOP_GAP: usize = 10;

    fn sync(&self, persister: &mut PersistedWallet<impl BMPWalletPersister>) -> anyhow::Result<()> {
        insert_checkpoint(
            persister,
            BlockId {
                height: 42,
                hash: BlockHash::all_zeros(),
            },
        );
        insert_checkpoint(
            persister,
            BlockId {
                height: 1_000,
                hash: BlockHash::all_zeros(),
            },
        );
        insert_checkpoint(
            persister,
            BlockId {
                height: 2_000,
                hash: BlockHash::all_zeros(),
            },
        );

        receive_output_in_latest_block(persister, Amount::ONE_BTC);

        Ok(())
    }
}
