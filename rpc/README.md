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

### Experimental wallet gRPC interface and test CLI + Java client

To help test and develop the wallet and chain notification API that will be needed by Bisq, a small Rust gRPC client
with a command-line interface is also included as a binary target (`musig-cli`). Currently, this is providing access to
a handful of experimental wallet RPC endpoints that will talk to BDK to get account balance, UTXO set, block reorg
notifications, etc. (only partially implemented).

A non-interactive Java test gRPC client has also been written to query the UTXO set, then open an RPC stream for each
UTXO and listen for confidence updates (confirmations, reorgs, etc.), running for a few seconds.

The wallet is currently just hardwired to use _regtest_, without persistence. It uses the `bdk_bitcoind_rpc`
crate to talk to a local `bitcoind` instance via JSON-RPC on port 18443, authenticated with cookies and with
data-dir `$PWD/.localnet/bitcoind`. It does a full scan once upon startup, then polls once per second. A `bitcoind`
regtest instance may be started up as follows, from the PWD:

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

5. To subsequently run the Java test client for the wallet gRPC interface, run:

```sh
nigiri start && \
mvn exec:java -Pwallet
```

6. To run the `BmpClient`:

```bash
mvn exec:java -P bmp
```

### Integration tests using Nigiri

Some of the integration tests require [Nigiri](https://github.com/vulpemventures/nigiri) to run, which is a command-line
interface managing a selection of `docker-compose` containers providing a local regtest network. A custom datadir
relative to the root of the `rpc` crate is assumed, with currently only the `bitcoin` component being used by the tests,
though later `electrs` will be likely also be used to test and develop an Electrum wallet backend.

To start Nigiri with the project-local datadir, run:

```sh
nigiri --datadir "$PWD/.nigiri" start
```

This will also fetch and install the containers and their configuration in `$PWD/.nigiri` if run for the first time. The
Rust integration and unit tests may be run by:

```sh
cargo test
```

as usual, which will automatically start Nigiri (with the `--ci` flag to exclude Esplora) if it isn't running already.

It continues to run after the tests finish, so to stop Nigiri, subsequently run:

```sh
nigiri --datadir "$PWD/.nigiri" stop
```

### Java Integration Test

To run the full Java integration test suite (`BmpServiceIntegrationTest.java`), which simulates a complete trade and
verifies it on-chain, follow these steps. This requires `nigiri`, `cargo`, and `mvn` to be installed.

1. **Start Nigiri:**

   This provides the local Bitcoin regtest network.

   ```sh
   nigiri start
   ```

2. **Start two `musigd` gRPC servers:**

The test requires two server instances to represent the two parties in the trade (Alice and Bob). Run these commands
from the project's root directory. It's best to run them in separate terminal windows so you can monitor their output.

    *   Server for Bob (port 50051):
        ```sh
        cargo run --bin musigd --manifest-path rpc/Cargo.toml -- --port 50051
        ```
    *   Server for Alice (port 50052):
        ```sh
        cargo run --bin musigd --manifest-path rpc/Cargo.toml -- --port 50052
        ```

3. **Run the Maven test command:**

   This command will compile the Java code and execute the integration test. Run it from the project's root directory.

   ```sh
   mvn -f rpc/pom.xml clean verify
   ```
