use std::sync::Arc;

use anyhow::Result;
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bdk_wallet::bitcoin::Amount;
use bdk_wallet::Balance;
use futures_util::StreamExt as _;
use rpc::wallet::{TxConfidence, WalletService, WalletServiceImpl};
use testenv::TestEnv;
use tokio::time::{self, Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_wallet_service_mine_single_tx() -> Result<()> {
    let testenv = TestEnv::new()?;
    // testenv.start_explorer_in_container()?;

    let rpc_client = testenv.bitcoin_core_rpc_client()?;

    let wallet_service = start_wallet_service(rpc_client).await;
    let balance1 = wallet_service.balance();

    // Send 0.01 BTC from bitcoind to a fresh wallet address and wait for wallet to sync.
    let addr = wallet_service.reveal_next_address();
    let amount = Amount::from_sat(1_000_000);

    let txid = testenv.fund_address(&addr.address, amount)?;
    testenv.wait_for_tx(txid)?;

    // Open up a tx confidence stream on the (unconfirmed) paying tx.
    let mut stream = wallet_service.get_tx_confidence_stream(txid);
    let mut expect = stream.next().await;
    // dbg!(&expect);
    assert!(matches!(expect, Some(Some(TxConfidence { num_confirmations: 0, .. }))));

    let balance2 = wallet_service.balance();
    assert_eq!(balance2.total(), balance1.total() + amount);
    assert!(balance2.untrusted_pending >= amount);

    // Mine a block and wait for wallet to sync.
    testenv.mine_block()?;
    testenv.wait_for_tx(txid)?;

    let balance3 = wallet_service.balance();
    assert_eq!(balance3.total(), balance2.total());
    assert_eq!(balance3.trusted_pending, Amount::ZERO);
    assert_eq!(balance3.untrusted_pending, Amount::ZERO);

    // The tx should now be confirmed.
    loop { // chain_position.last_seen may be different all the time. stream.next() is giving always new values.
        let old = expect.clone();
        expect = stream.next().await;
        let Some(Some(TxConfidence { num_confirmations: conf_old, .. })) = old else {
            continue;
        };
        let Some(Some(TxConfidence { num_confirmations: conf_now, .. })) = expect else {
            continue;
        };
        if conf_old != conf_now {
            break;
        }
    }
    assert!(matches!(expect, Some(Some(TxConfidence { num_confirmations: 1, .. }))));
    Ok(())
}

async fn start_wallet_service(rpc_client: bitcoincore_rpc::Client) -> Arc<impl WalletService> {

    let wallet_service = Arc::new(WalletServiceImpl::create_with_rpc_params(
        rpc_client));
    assert_eq!(wallet_service.balance(), Balance::default());

    wallet_service.clone().spawn_connection();
    // Wait for RPC sync...
    // FIXME: A bit hacky -- should add logic to the service to notify when the wallet is synced.
    time::sleep(Duration::from_secs(1)).await;

    wallet_service
}
