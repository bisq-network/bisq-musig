# Bitcoin Regtest Environment

A clean Bitcoin regtest environment using electrsd with automatic executable downloads.

## Features

- **Automatic Downloads**: Downloads required executables (bitcoind, electrs) automatically
- **Zero Dependencies**: No Docker or external setup required
- **Modern Rust API**: Clean, ergonomic interface inspired by BDK
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Quick Start

### Basic Usage

```rust
use regtest_env::TestEnv;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Create environment (automatically downloads executables)
    let env = TestEnv::new()?;
    
    // Mine some blocks
    env.mine_block()?;
    
    // Create and fund an address
    let address = env.new_address()?;
    let txid = env.fund_address(&address, Amount::from_sat(100000))?;
    
    // Wait for confirmation
    env.wait_for_tx(txid, Duration::from_secs(10))?;
    env.wait_for_block(Duration::from_secs(5))?;
    
    println!("Transaction confirmed: {}", txid);
    Ok(())
}
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

#### Creation Methods

- `TestEnv::new()` - Creates environment with automatic downloads

#### Client Access

- `electrum_client()` - Access to electrum client for blockchain operations
- `electrum_url()` - Get electrum server URL

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
