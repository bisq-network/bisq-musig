use std::time::Duration;

use anyhow::Result;
use bdk_wallet::bitcoin::{consensus, Amount, Transaction};
use testenv::TestEnv;
use zeromq::{Socket as _, SocketRecv as _, SubSocket};

#[tokio::test]
async fn test_zmq_receives_broadcast_tx() -> Result<()> {
    let mut env = TestEnv::enable_zmq()?;
    env.start_explorer_in_container()?;

    let tx_socket = env.zmq_pub_raw_tx_socket().expect("zmq rawtx socket");

    // Subscribe to raw transactions via ZMQ
    let mut sub = SubSocket::new();
    sub.connect(&format!("tcp://{tx_socket}"))
        .await
        .expect("zmq connect");
    sub.subscribe("rawtx").await.expect("zmq subscribe");

    // Small delay to let the subscription propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    let address = env.new_address()?;
    let amount = Amount::from_sat(50_000);
    let txid = env.fund_address(&address, amount)?;
    env.debug_tx(txid); // output link to inspect the transaction iff esplorer is running.

    // Receive messages from ZMQ until we find our transaction (coinbase txs arrive too)
    let zmq_tx = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let zmq_msg = sub.recv().await.expect("zmq recv failed");
            let frames = zmq_msg.into_vec();
            assert_eq!(frames[0].as_ref(), b"rawtx", "first frame should be the topic");

            let tx: Transaction =
                consensus::deserialize(&frames[1]).expect("deserialize zmq tx");
            if tx.compute_txid() == txid {
                return tx;
            }
        }
    })
    .await
    .expect("timed out waiting for our tx on ZMQ");

    // Fetch via RPC and verify the two transactions are equal
    let rpc_tx_info = env.bitcoind_client().get_transaction(txid)?;
    let rpc_tx_bytes = hex::decode(&rpc_tx_info.hex)?;
    let rpc_tx: Transaction = consensus::deserialize(&rpc_tx_bytes)?;
    assert_eq!(zmq_tx, rpc_tx, "ZMQ and RPC transactions should be identical");

    Ok(())
}