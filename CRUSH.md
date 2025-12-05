# Bisq MuSig2 Protocol - Agent Guide

## Overview

This is the Bisq2 MuSig2 Protocol implementation - a Rust-based cryptocurrency protocol for decentralized Bitcoin trading using advanced cryptographic schemes (MuSig2, adaptor signatures, Taproot). The project implements a trustless P2P trading protocol without intermediaries.

**Key Technologies**: Rust, Bitcoin Taproot, MuSig2, Adaptor Signatures, gRPC, BDK Wallet, Tokio

## Project Structure

```
bisq-musig/
├── protocol/          # Core MuSig2 protocol implementation
├── rpc/              # gRPC server and Java test clients  
├── wallet/           # Wallet operations using BDK
├── testenv/          # Bitcoin regtest environment with Esplora UI
├── concept/          # Protocol documentation and diagrams
├── poc/              # Proof of concept (excluded from workspace)
├── bdktest/          # Additional testing components
└── [config files]
```

### Crate Details

- **protocol**: Core cryptographic protocol logic, trade state machines
- **rpc**: Tonic-based gRPC server (`musigd`) + CLI client + Java test clients
- **wallet**: BDK-based wallet operations, chain data sources
- **testenv**: Self-contained Bitcoin regtest environment using electrsd

## Essential Commands

### Development Setup

```bash
# Install pre-commit hooks (REQUIRED for contributions)
bash install-hooks.sh

# Install protoc compiler for gRPC
# Download from: https://github.com/protocolbuffers/protobuf/releases
export PROTOC=/path/to/protoc  # If not in PATH
```

### Building & Running

```bash
# Build entire workspace
cargo build

# Run gRPC server (from project root)
cargo run --bin musigd --manifest-path rpc/Cargo.toml -- --port 50051

# Run CLI wallet client (default binary in rpc crate)
cargo run --manifest-path rpc/Cargo.toml

# Run specific protocol tests (requires Nigiri)
cd protocol
cargo test --package protocol --lib --tests -- --nocapture
```

### Testing

#### Using Built-in TestEnv (Recommended)

```bash
# Run tests with automatic test environment
cargo test --package testenv

# Run specific test
cargo test --package testenv test_address_operations
```

#### Using Nigiri (Legacy)

```bash
# Start Nigiri regtest environment
nigiri start

# Run protocol integration tests  
cd protocol
cargo test --package protocol --lib --tests -- --nocapture

# Stop Nigiri when done
nigiri stop
```

### Java Components

```bash
# Build and run Java gRPC test client
cd rpc
mvn install exec:java

# Run wallet-specific Java test
mvn exec:java -Pwallet

# Run BMP (Bisq Market Protocol) Java test  
mvn exec:java -P bmp

# Full integration test (requires 2 musigd servers running)
mvn -f rpc/pom.xml clean verify
```

### Code Quality

```bash
# Run linting (handled by pre-commit hook)
cargo clippy --all-targets

# Format code (handled by pre-commit hook)  
cargo fmt

# Run all tests
cargo test
```

## Code Organization & Patterns

### Module Structure

```
protocol/src/
├── lib.rs                    # Module exports
├── protocol_musig_adaptor.rs # Core protocol state machine
├── transaction.rs            # Transaction building/signing
├── wallet_service.rs         # Wallet integration layer
├── nigiri.rs                # Test environment utilities
├── psbt.rs                  # PSBT handling
├── receiver.rs              # Protocol receiver logic
└── swap.rs                  # Force-closure swap logic
```

### Error Handling

- Use `anyhow::Result` for application-level errors
- Use `thiserror` for library/public API errors
- Pattern: `anyhow!("descriptive error message")`
- Avoid unwraps in production code

### Async Patterns

- All async code uses `tokio` runtime
- Protocol operations are async to support concurrent trading
- Use `anyhow::Result<T>` for async error handling
- Example: `async fn round1() -> anyhow::Result<Round1Response>`

### Protocol State Machine

The protocol follows a round-based pattern:

```rust
// Typical protocol flow
let alice_response = alice.round1()?;     // Share commitments
let alice_r2 = alice.round2(bob_response)?; // Share nonces  
let alice_r3 = alice.round3(alice_r2)?;    // Share partial signatures
```

## Testing Approach

### Test Categories

1. **Unit Tests**: Individual component testing in respective crates
2. **Integration Tests**: Full protocol flow testing in `protocol/tests/`
3. **TestEnv Tests**: Blockchain environment testing in `testenv/tests/`
4. **Java Integration**: End-to-end testing with real gRPC clients

### Test Environment Requirements

#### Option A: Built-in TestEnv (Preferred)
- Automatically downloads `bitcoind` and `electrs` executables
- No external dependencies
- Includes Esplora UI for blockchain inspection
- Supports environment variable overrides:
  - `BITCOIND_EXEC`: Custom bitcoind path
  - `ELECTRS_EXEC`: Custom electrs path

#### Option B: Nigiri (Legacy)
- Requires Docker and Nigiri installation
- Command: `nigiri --datadir "$PWD/.nigiri" start`
- More complex but matches production Bitcoin setup

### Writing Tests

```rust
#[test]
fn test_protocol_flow() -> anyhow::Result<()> {
    let env = TestEnv::new()?;  // Auto-downloads executables
    let alice_funds = nigiri::funded_wallet();
    let bob_funds = nigiri::funded_wallet();
    
    // Test protocol logic...
    
    Ok(())
}
```

## Configuration & Dependencies

### Workspace Dependencies

Key workspace dependencies in `Cargo.toml`:
- `bdk_wallet = "~2.1.0"`: Wallet operations (note version constraint)
- `musig2 = "0.3.1"`: MuSig2 cryptographic operations
- `tokio = "1.48.0"`: Async runtime
- `anyhow = "1.0.100"`: Error handling
- `serde`: Serialization for RPC

### Edition Compatibility

- **protocol**: Rust 2024 edition
- **rpc**: Rust 2021 edition (due to IDE plugin limitations)
- **wallet**, **testenv**: Rust 2021 edition

### Lint Configuration

Strict clippy configuration in workspace `Cargo.toml`:
- `pedantic` lint level enabled
- Custom overrides for `missing_errors_doc`, `missing_panics_doc`
- Workspace-wide lint enforcement

## gRPC Interface

### Protocol Buffer Files

```
rpc/src/main/proto/
├── bmp_protocol.proto    # Bisq Market Protocol messages
├── bmp_wallet.proto      # Wallet operation messages  
├── rpc.proto            # General RPC messages
└── wallet.proto         # Wallet-specific messages
```

### Server Implementation

- **Binary**: `musigd` - gRPC server listening on configurable port
- **Default Port**: 50051
- **Transport**: Tonic (HTTP/2)
- **Language**: Rust server, Java/CLI clients

### Java Client Examples

```bash
# Single server interaction
mvn exec:java

# Full integration test (requires 2 servers)
# Terminal 1: cargo run --bin musigd -- --port 50051  
# Terminal 2: cargo run --bin musigd -- --port 50052
# Terminal 3: mvn -f rpc/pom.xml clean verify
```

## Esplora UI Integration

The `testenv` crate includes a web UI for blockchain inspection:

- **URL**: http://localhost:8989
- **Auto-starts**: When test environment is created
- **Backend**: Proxies to Esplora REST API
- **Purpose**: Visual debugging of blockchain state during tests

## Critical Gotchas

### 1. Test Environment Lifecycle

⚠️ **IMPORTANT**: Keep `TestEnv` instance alive during testing. Dropping it terminates `bitcoind` and `electrs` processes.

```rust
// ✅ GOOD
let env = TestEnv::new()?;
// Do work...
std::thread::sleep(Duration::from_secs(30)); // Keep alive

// ❌ BAD  
let env = TestEnv::new()?;
drop(env); // Terminates Bitcoin services!
```

### 2. Edition Compatibility

- `rpc` crate uses Rust 2021 due to IDEA plugin limitations
- Don't upgrade without testing IDE compatibility
- Other crates use Rust 2024

### 3. BDK Version Constraints

- `bdk_wallet = "~2.1.0"`: Must stay on this version
- Comment in workspace Cargo.toml explains v2.2.0 compatibility issues
- Don't upgrade without thorough testing

### 4. Pre-commit Hook Requirements

- **jq is required**: Install before running `install-hooks.sh`
- **Nightly Rust**: Required for `rustfmt --skip-children` functionality
- **Hooks are optional**: But recommended for clean commits

### 5. Nigiri vs TestEnv

- **New development**: Use built-in `testenv` (faster, no Docker)
- **Legacy/compatibility**: Nigiri still supported
- **Don't mix**: Choose one approach per test run

### 6. Java Integration Tests

- Require 2 `musigd` servers running on different ports
- Must start servers before running Maven test
- Ports hardcoded in test configuration

### 7. Protocol Buffer Compilation

- `protoc` compiler must be installed separately
- Download from Protocol Buffers releases page
- Set `PROTOC` environment variable if not in PATH

### 8. Esplora UI Error Handling

⚠️ **FIXED**: The `start_esplora_ui()` function previously used multiple `.unwrap()` calls that could panic. These have been replaced with proper error handling using `anyhow::Context` for:
- TCP listener binding
- Getting local address  
- Axum server execution

The function now returns `Result<()>` instead of panicking on errors.

## Development Workflow

1. **Setup**: Run `bash install-hooks.sh` and install `protoc`
2. **Develop**: Write code with proper error handling and async patterns  
3. **Test**: Use `testenv` for unit/integration tests
4. **Quality**: Pre-commit hooks enforce linting and formatting
5. **Integration**: Test Java clients if changing RPC interface
6. **Debug**: Use Esplora UI at http://localhost:8989 for blockchain inspection

## Documentation References

- **Protocol Overview**: `concept/SingleTxOverview.md`
- **API Documentation**: `concept/API.md`  
- **MuSig2 Details**: `concept/MuSig2adaptor-rust.md`
- **RPC Usage**: `rpc/README.md`
- **Test Environment**: `testenv/README.md`

## Contact & Contribution

- **Development Chat**: [Matrix](https://matrix.to/#/#bisq-muSig-dev:matrix.org)
- **Compensation**: Accepted contributions are eligible for payment
- **Getting Started**: Run `tests::test_musig` for initial understanding

## Environment Variables

```bash
# Custom executables for testenv
export BITCOIND_EXEC="/custom/path/to/bitcoind"
export ELECTRS_EXEC="/custom/path/to/electrs"

# Protocol buffer compiler (if not in PATH)  
export PROTOC="/path/to/protoc"
```
