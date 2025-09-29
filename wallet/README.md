# MuSig Wallet module

Wallet module of the Bisq-musig protocol. This crate has the primitives for interacting with a wallet. 

It currently provides the following features: 

- Importing of secrets
- Syncing with BDK Electrum
- Uses Sqlite to store additional information outside of the BDK structure

# Running tests

`cd wallet`

`cargo test`
