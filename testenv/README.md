# Bitcoin Regtest Environment

A clean Bitcoin regtest environment using electrsd with automatic executable downloads.

## Features

- **Automatic Downloads**: Downloads required executables (bitcoind, electrs) automatically
- **Zero Dependencies**: No Docker or external setup required
- **Modern Rust API**: Clean, ergonomic interface inspired by BDK
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Web UI**: Built-in Esplora blockchain explorer for visual debugging

## Quick Start

### Basic Usage

```rust
// Create environment (automatically downloads executables)
let env = TestEnv::new()?;
env.mine_block()?;

// Create and fund an address
let address = env.new_address()?;
let txid = env.fund_address(&address, Amount::from_sat(100000))?;

// Wait for confirmation
env.wait_for_tx(txid, Duration::from_secs(10))?;
env.wait_for_block(Duration::from_secs(5))?;

println!("Transaction confirmed: {}", txid);
```

### Web UI (Esplora)

The test environment provides a web-based blockchain explorer for visual debugging. This requires running both a backend API proxy and a frontend container.

#### Step 1: Start the Backend API Proxy

```rust
// Create environment
let mut env = TestEnv::new() ?;

// Start Esplora UI API proxy (non-blocking, runs in separate process)
env.start_esplora_ui(8989) ?;
```

#### Step 2: Start the Frontend Container

In a separate terminal, run the Esplora frontend container:

```bash
# Using Podman
podman run -d --rm \
  --name esplora \
  -p 8888:80 \
  docker.io/blockstream/esplora:latest \
  bash -c "/srv/explorer/run.sh bitcoin-mainnet explorer"

# Using Docker (if preferred)
docker run -d --rm \
  --name esplora \
  -p 8888:80 \
  docker.io/blockstream/esplora:latest \
  bash -c "/srv/explorer/run.sh bitcoin-mainnet explorer"
```

#### Step 3: Access the Web Interface

- http://localhost:8989

> **Note**: Keep the Rust environment running while using the web interface. The frontend container connects to the API proxy provided by the `start_esplora_ui()` function.

### Custom Configuration Usage

```rust
// Create custom configuration
let mut config = Config::default();

// Customize bitcoind settings
config.bitcoind.args.push("-rpcuser=customuser");
config.bitcoind.args.push("-rpcpassword=custompass");
config.bitcoind.args.push("-maxmempool=100");

// Customize electrsd settings
config.electrsd.http_enabled = true;
// config.electrsd.view_stderr = true;  // Uncomment to see electrsd logs

// Create environment with custom configuration
let env = TestEnv::new_with_conf(config)?;

env.mine_blocks(5)?;

// UI will be available at http://localhost:8989
```

### Environment Variables

```bash
# Override executables via environment variables
export BITCOIND_EXEC="/custom/path/to/bitcoind"
export ELECTRS_EXEC="/custom/path/to/electrs"

cargo run  # Will use custom executables
```

## API Reference

### TestEnv

The main environment manager that handles both bitcoind and electrs instances.

> **⚠️ Important**: Keep the `TestEnv` instance alive (don't drop it) while you need the services running. When the instance is dropped, both bitcoind and electrs processes will be terminated.

#### Creation Methods

- `TestEnv::new()` - Creates environment with automatic downloads
- `TestEnv::new_with_conf(config)` - Creates environment with custom configuration

#### Client Access

- `electrum_client()` - Access to electrum client for blockchain operations
- `electrum_url()` - Get electrum server URL
- `esplora_url()` - Get Esplora REST URL

#### Web UI

- `start_esplora_ui(port)` - Start Esplora blockchain explorer API proxy in a separate child process.

#### Blockchain Operations

- `mine_block()` - Mine a single block
- `mine_blocks(count)` - Mine multiple blocks
- `fund_address(address, amount)` - Send BTC to address
- `new_address()` - Generate new test address

#### Synchronization

- `wait_for_block(timeout)` - Wait for electrum to see new block
- `wait_for_tx(txid, timeout)` - Wait for electrum to see transaction

#### Information

- `block_count()` - Get current blockchain height
- `best_block_hash()` - Get current tip block hash
- `genesis_hash()` - Get genesis block hash

### Utility Methods

- `trigger_sync()` - Trigger electrs sync (Unix only)
- `workdir()` - Get working directory path

## Testing

The library includes comprehensive tests that automatically skip when executables aren't available:

```bash
# Run tests (will skip if executables unavailable)
cargo test
```

### Platform Notes

- **Linux/macOS**: Full support including signal handling
- **Windows**: Limited signal support, core functionality works
