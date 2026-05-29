# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Rust implementation of the cryptographic core of the **Bisq2 MuSig trade protocol** — a non-custodial, scriptless P2P bitcoin trade protocol built on Taproot, MuSig2 aggregated signatures, and adaptor signatures. The happy path is a single transaction; warning, redirect, claim, and swap paths handle uncooperative peers. Background and design notes live in `concept/` (start with `concept/SingleTxOverview.md`).

## Workspace layout

Cargo workspace with seven members. The dependency direction is roughly: `bmp_tracing`/`chain`/`testenv` → `wallet` → `protocol` → `rpc`.

| Crate | Role |
|---|---|
| `protocol` | The protocol's cryptographic core. PSBT building (`psbt.rs`), trade transaction builders (`transaction.rs` — deposit/warning/redirect/claim/swap/custom-payout), MuSig2 + adaptor signing (`protocol_musig_adaptor.rs`, `multisig.rs`), Taproot script paths (`script_paths.rs`), receiver/output handling (`receiver.rs`). Library crate; no binaries. |
| `wallet` | BDK-backed wallet abstractions. Defines the `ProtocolWalletApi` trait that the protocol code consumes; three impls — `bdk_wallet::Wallet` (raw), `MemWallet` (in-memory + Electrum), `BMPWallet<Connection>` (persistent + SQLCipher + Compact Block Filters via `bdk_kyoto`). Imports external private keys (for swap-tx flows) on top of the HD wallet. |
| `chain` | Tiny abstraction crate: `ChainApi` (broadcast) and `ChainScanner` (cache-populate + full-scan) traits, so wallets aren't hard-wired to a specific chain backend. |
| `rpc` | gRPC server (`musigd` binary) and CLI client (`musig-cli`, the **default-run** binary). Hosts both the trade-protocol RPC and the wallet RPC. **`rpc` is still on Rust edition 2021** while every other crate is on edition 2024 — see the comment in `rpc/Cargo.toml`. Generated protobuf code lives in `rpc/src/pb/` and is built from `.proto` files in `rpc/src/main/proto/` via `rpc/build.rs` (requires `protoc`). A Java test client lives alongside in `rpc/pom.xml`. |
| `mem` | ZMQ helper for streaming unconfirmed transactions. |
| `testenv` | Spins up real `bitcoind` + `electrs` (auto-downloaded) for integration tests. Optional `btc-rpc-explorer` web UI via Podman (debug only). Most tests in `wallet`/`protocol`/`rpc` build on this. |
| `bmp_tracing` | Single-call tracing init: `bmp_tracing::init("info")`. Reads `RUST_LOG`. Set `RUST_LOG=off` to silence (CI does this). |

## Commands

```sh
cargo build                                  # whole workspace
cargo clippy --all-targets                   # what CI gates on
cargo test                                   # whole workspace; serial by default
TEST_MULTITHREADED=true cargo test           # faster but flaky (timing issues)
cargo fmt --all                              # rustfmt.toml is authoritative

# Single test / single crate / single binary:
cargo test -p wallet test_cbf_persistence    # one test by name
cargo test -p protocol --lib                 # protocol unit tests only
cargo test -p protocol --test protocol_integration_tests
cargo test -p wallet --test wallet_integration_test -- --show-output
cargo run --bin musigd -- --port 50051       # gRPC server
cargo run                                    # = cargo run --bin musig-cli (default-run)
```

Tests spin up `bitcoind` + `electrs` per environment, so memory and patience are required. The single-thread default exists because parallel runs are flaky. `./test-runner.sh` reruns the whole suite at thread counts 32→1 for stress testing.

`protoc` must be on `PATH` (or `PROTOC` set) to build the `rpc` crate. On Debian/Ubuntu: `apt-get install -y protobuf-compiler`.

## Formatting & lint config

- `rustfmt.toml`: Rust 2024 style edition, `comment_width = 100`, `wrap_comments = true`, `format_code_in_doc_comments = true`, `imports_granularity = "Module"`, `group_imports = "StdExternalCrate"` (three blank-line-separated import blocks: std → external crates → `crate::`).
- `Cargo.toml` enables **`clippy::pedantic = "warn"` workspace-wide**, plus selected nursery/restriction lints (`use_self`, `missing_const_for_fn`, `str_to_string`, `try_err`, `unused_trait_names`, `branches_sharing_code`, `exhaustive_enums`, `iter_on_empty_collections`, `iter_on_single_items`, `renamed_function_params`, `allow_attributes`). `missing_errors_doc`, `missing_panics_doc`, `must_use_candidate` are explicitly allowed.
- `rust-2024-compatibility = "warn"`, with `tail_expr_drop_order` and `edition_2024_expr_fragment_specifier` allowed.
- Pre-commit hook (opt-in via `bash install-hooks.sh`, requires `jq` + a nightly rustfmt): runs `cargo clippy --all-targets` and only **blocks** on warnings whose source spans match changed lines in staged `*.rs` files; then runs `rustfmt +nightly --file-lines` on the changed line ranges only (so unrelated reformatting doesn't sneak in).

## CI

`.github/workflows/cont_integration.yml` runs **per-crate**: only the `wallet` job runs if `wallet/**` changed, only the `protocol` job runs if `protocol/**` changed (via `dorny/paths-filter`). Both jobs do `cargo build` + `cargo clippy --all-targets` + `RUST_LOG=off cargo test`. There's no explicit `cargo fmt --check` gate — formatting is enforced by the pre-commit hook, not CI.

## Architecture notes worth knowing before editing

- **`ProtocolWalletApi` is the seam between `wallet` and `protocol`.** The protocol crate never names a concrete wallet type — it operates on `&mut dyn TradeWallet` (in `protocol::psbt`) which extends `ProtocolWalletApi`. To add a method that all three wallet flavors must support, put it on `ProtocolWalletApi`; for things only the protocol needs, extend `TradeWallet` with a default method (see `create_half_deposit_psbt`). Shared default-method logic that varies only in a primitive operation per impl is factored into `pub(crate)` free helpers in `wallet/src/protocol_wallet_api.rs` (`internal_key_at_index`, `finish_standard_psbt`, `sign_selected_inputs_with`) — follow that pattern when consolidating duplication across impls.
- **`BMPWallet<Connection>` derefs to `PersistedWallet<Connection>`** (BDK), so most BDK calls work directly on it. Its custom `sign` (in the `WalletApi` trait, *not* the trait `bdk_wallet::Wallet::sign`) layers imported-key signing on top of the HD-wallet sign.
- **Trade transactions** (`protocol/src/transaction.rs`) are constructed via per-tx builders (deposit, warning, redirect, claim, swap, custom-payout) that share PSBT helpers in `protocol/src/psbt.rs` (`merge_psbt_halves`, `set_payouts_and_shuffle`, `extract_signed_tx`, `prevout_set`).
- **MuSig2 + adaptor signing** lives in `protocol/src/protocol_musig_adaptor.rs` and `protocol/src/multisig.rs`. Aggregated pubkeys, nonce shares, and partial signatures are exchanged with the peer (in production via the `rpc` layer; in tests via direct in-process calls).
- **`rpc::pb`** modules are the generated tonic+prost code. The `build.rs` adds `serde` derives selectively (per-field hex/reverse-hex/base64 transcoding) so that protobuf request/response types can be (de)serialized for the test CLI and Java test client. Don't hand-edit anything under `rpc/src/pb/` — change `.proto` files or `build.rs` instead.
- **Wallet keys & DB**: SQLCipher via `rusqlite` with `bundled-sqlcipher`. The DB path is derived from a user-supplied password using Argon2 (`wallet/src/utils.rs`); the salt is stored alongside the DB as `<dbname>.salt`.

## Logging

All binaries and test setups should call `bmp_tracing::init("info")` once. CI runs tests with `RUST_LOG=off`; do the same locally if test logs are noisy. The `tracing` and `tracing_subscriber` re-exports from `bmp_tracing` are used so the whole workspace shares one version.
