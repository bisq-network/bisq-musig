### Rust gRPC interface for the Bisq2 MuSig trade protocol

This is an experimental Rust-based gRPC interface being developed for Bisq's upcoming single-tx trade protocol. A Java
test client conducting a dummy two-party trade is currently also included.

The Rust code uses the `musig2` crate to construct aggregated signatures for the traders' warning and redirect
transactions, with pubkey & nonce shares and partial signatures exchanged with the Java client, to pass them back in as
fields of the simulated peer's RPC requests, setting up the trade.

The adaptor logic, multiparty signing and simulated steps for the whole of the trade (both normal and force-closure via
the swap tx) are now implemented for the mockup, but none of the mediation, arbitration or claim paths are implemented
or mocked yet. Dummy messages to represent the txs to sign are currently being used in place of real txs built with the
aid of BDK or a similar wallet dependency.

See [MuSig trade protocol messages](musig-trade-protocol-messages.txt) for my current (incomplete) picture of what the
trade messages between the peers would look like, and thus the necessary data to exchange in an RPC interface between
the Bisq2 client and the Rust server managing the wallet and key material.

### Experimental wallet gRPC interface and test CLI

To help test and develop the wallet and chain notification API that will be needed by Bisq, a small Rust gRPC client
with a command-line interface is also included as a binary target (`musig-cli`). Currently, this is providing access to
a handful of experimental wallet RPC endpoints that will talk to BDK to get account balance, UTXO set, block reorg
notifications, etc. (only partially implemented).

The wallet is currently just hardwired to use _regtest_, without persistence. It uses the `bdk_bitcoind_rpc`
crate to talk to a local `bitcoind` instance via JSON-RPC on port 18443, authenticated with cookies and with
data-dir `$PWD/.localnet/bitcoind`. It does a full scan once upon startup, with continual syncing yet to be implemented.
A `bitcoind` regtest instance may be started up as follows, from the PWD:

```sh
bitcoind -regtest -prune=0 -txindex=1 -blockfilterindex=1 -server -datadir=.localnet/bitcoind
```

The `-txindex` and `-blockfilterindex` (compact filters) options aren't presently needed but may be at some point, to
make an RPC backend scalable enough to use with a full node on _mainnet_.

### Building and running the code

The Rust gRPC server listens on localhost port 50051.

1. To successfully build the Rust server, the `protoc` compiler must be installed separately. Make sure it is on the
   current path, or the `PROTOC` environment variable is set to the path of the binary. It can be downloaded from:

> https://github.com/protocolbuffers/protobuf/releases

2. To build and run the Rust server, run:

```sh
cargo run --bin musigd
```

3. To build and run the Rust wallet CLI client (default-run), just run:

```sh
cargo run
```

4. To build and run the Java gRPC test client to carry out a mock trade, run:

```sh
mvn install exec:java
```
