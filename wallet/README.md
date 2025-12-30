# MuSig Wallet module

Wallet module of the Bisq-musig protocol. This crate has the primitives for interacting with a wallet. 

It currently provides the following features: 

- Importing of secrets
- Syncing with BDK Electrum
- Syncing using Compact Block Filters (CBF)
- Uses Sqlite to store additional information outside of the BDK structure

# Running tests

`cd wallet`

`cargo test`

# Running integration tests

In order to run the integrations tests:

`cargo test --test wallet_integration_test`

If you want to display the tests stdout, add the option `--show-output` as follow:

`cargo test --test wallet_integration_test -- --show-output`
