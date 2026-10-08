# MuSig Wallet module

Wallet module of the Bisq-musig protocol. This crate has the primitives for interacting with a wallet.

It currently provides the following features:

- `ProtocolWalletApi`: the trait through which the `protocol` crate uses a wallet, implemented by a plain
  `bdk_wallet::Wallet`, the in-memory `MemWallet` and the persistent `BMPWallet`
- `BMPWallet`: a persistent HD wallet on top of BDK
  - always password-protected: stored in an encrypted SQLite database (SQLCipher) whose key is derived from the wallet
    password with Argon2; the salt is stored next to the database as `<dbname>.salt`
  - the wallet password is a `Password` (`wallet::password`), which can only be built from a string that follows the
    password rules (at least 8 characters, with a lowercase letter, an uppercase letter, a number and a special
    character); a rejected password's error states the rules in plain English
  - the wallet password can be checked and changed, but not removed
  - importing of external private keys (e.g. for the swap tx), which are signed with alongside the HD keys
  - sending to an address, listing addresses, UTXOs and transactions
- `MemWallet`: an in-memory wallet synced via BDK Electrum, mainly used in tests
- Syncing using Compact Block Filters (CBF) through `bdk_kyoto`, behind the `ChainDataSource` trait

# Running tests

`cargo test -p wallet`

The tests spin up `bitcoind` + `electrs` via the [`testenv`](../testenv/README.md) crate.

# Running integration tests

In order to run the integration tests:

`cargo test -p wallet --test wallet_integration_test`

If you want to display the tests stdout, add the option `--show-output` as follows:

`cargo test -p wallet --test wallet_integration_test -- --show-output`
