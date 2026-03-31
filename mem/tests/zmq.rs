use std::time::Duration;

use anyhow::Result;
use bdk_wallet::bitcoin::{consensus, Amount, Transaction};
use mem::stream_unconfirmed_tx;
use testenv::TestEnv;
use tokio_stream::StreamExt as _;

#[tokio::test]
async fn test_stream_zmq_async_receives_broadcast_tx() -> Result<()> {
    let mut env = TestEnv::enable_zmq()?;
    // env.start_explorer_in_container()?;

    let connect_string = env.zmq_pub_raw_tx_socket().expect("zmq rawtx socket");
    let tx_stream = stream_unconfirmed_tx(&connect_string).await;

    let address = env.new_address()?;
    let amount = Amount::from_sat(50_000);
    let txid = env.fund_address(&address, amount)?;
    env.debug_tx(txid); // output link to inspect the transaction iff esplorer is running.

    let zmq_tx = tokio::time::timeout(
        Duration::from_secs(5),
        tx_stream.filter(|tx| tx.compute_txid() == txid).next(),
    )
    .await
            .expect("timed out waiting for our tx via stream_zmq_async")
            .expect("stream ended unexpectedly");

    let rpc_tx_info = env.bitcoind_client().get_transaction(txid)?;
    let rpc_tx_bytes = hex::decode(&rpc_tx_info.hex)?;
    let rpc_tx: Transaction = consensus::deserialize(&rpc_tx_bytes)?;
    assert_eq!(zmq_tx, rpc_tx, "stream and RPC transactions should be identical");

    Ok(())
}
