//! Usage:
//!   cargo run --bin testenv-server -- --data-dir /path/to/persistent/dir
//!   cargo run --bin testenv-server  # Uses TempDir (auto-deleted on exit)

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use testenv::TestEnvBuilder;

#[derive(Parser, Debug)]
#[command(name = "testenv-server")]
#[command(about = "Bitcoin regtest environment server for integration testing")]
#[command(version)]
struct Args {
    /// Optional persistent data directory. If not provided, uses a temporary directory
    /// that will be auto-deleted when the server stops.
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Create TestEnv with optional data directory
    let env = TestEnvBuilder::new(Some("bitcoin".to_string()))
        .with_data_dir(args.data_dir.clone())
        .build()?;

    // Output connection information in a parseable format
    let rpc_port = env.bitcoin_rpc_port();
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);
    let electrum_url = env.electrum_url();
    let workdir = env.workdir();

    // Output as key=value pairs for easy parsing
    println!("TESTENV_READY=true");
    println!("TESTENV_RPC_URL={}", rpc_url);
    println!("TESTENV_RPC_PORT={}", rpc_port);
    println!("TESTENV_RPC_USER=bitcoin");
    println!("TESTENV_RPC_PASS={}", env.bitcoin_rpc_password());
    println!("TESTENV_ELECTRUM_URL={}", electrum_url);
    println!("TESTENV_WORKDIR={}", workdir.display());
    if let Some(data_dir) = &args.data_dir {
        println!("TESTENV_PERSISTENT=true");
        println!("TESTENV_DATA_DIR={}", data_dir.display());
    } else {
        println!("TESTENV_PERSISTENT=false");
    }

    eprintln!("TestEnv server started successfully");
    eprintln!("Bitcoin RPC: {} (user: bitcoin)", rpc_url);
    eprintln!("Electrum: {}", electrum_url);
    eprintln!("Working directory: {}", workdir.display());
    if let Some(data_dir) = &args.data_dir {
        eprintln!("Persistent data directory: {}", data_dir.display());
    }

    // Keep running until we receive Ctrl+C (SIGINT)
    // We'll use a simple blocking loop with signal handling
    eprintln!("Server running. Press Ctrl+C to stop.");

    // Set up Ctrl+C handler to gracefully shutdown
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // Keep running until signal received
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    eprintln!("Shutting down TestEnv server...");
    Ok(())
}
