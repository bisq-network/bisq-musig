use std::time::Duration;

use bdk_wallet::bitcoin::{Transaction, consensus};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use zeromq::{Socket as _, SocketRecv as _, SubSocket};

pub async fn stream_unconfirmed_tx(zmq_connect: &str) -> ReceiverStream<Transaction> {
    // Subscribe to raw transactions via ZMQ
    let mut sub = SubSocket::new();
    sub.connect(zmq_connect).await.expect("zmq connect");
    sub.subscribe("rawtx").await.expect("zmq subscribe");

    // Small delay to let the subscription propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a channel to send messages from the ZMQ socket
    let (tx, rx) = mpsc::channel(32);

    // Spawn a task to receive messages from the ZMQ socket and send them through the channel
    tokio::spawn(async move {
        while let Ok(zmq_msg) = sub.recv().await {
            let frames = zmq_msg.into_vec();
            assert_eq!(frames[0].as_ref(), b"rawtx", "first frame should be the topic");

            let transaction: Transaction =
                consensus::deserialize(&frames[1]).expect("deserialize zmq tx");
            tx.send(transaction).await.unwrap();
        }
    });

    // Return a ReceiverStream from the channel's receiver
    ReceiverStream::new(rx)
}
