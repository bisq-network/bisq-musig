//! Common test utilities for Bitcoin-related testing
//! 
//! This crate provides common utilities for setting up test environments,
//! particularly for Bitcoin-related testing using Nigiri.

use std::process::Command;
use std::thread;
use std::time::Duration;

/// Sets up a test environment with Nigiri (Bitcoin test environment)
/// 
/// This function:
/// 1. Checks if Docker is running
/// 2. Stops any existing Nigiri instance
/// 3. Cleans up existing Bitcoin container and data
/// 4. Starts a fresh Nigiri instance
/// 5. Waits for services to be ready
/// 
/// # Panics
/// 
/// This function will panic if:
/// - Docker is not running or not installed
/// - Nigiri fails to start
pub fn setup() {
    println!("Starting the setup...");

    // Check if Docker is running
    let docker_check = Command::new("docker")
        .arg("info")
        .output();

    match docker_check {
        Ok(output) => {
            if !output.status.success() {
                eprintln!("Docker is not running. Please start Docker first.");
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("Docker is not installed or not in PATH. Please install Docker first.");
            std::process::exit(1);
        }
    }

    // Stop Nigiri first
    println!("Stopping Nigiri...");
    let _ = Command::new("nigiri")
        .arg("stop")
        .output();

    // Force remove any existing Bitcoin container
    println!("Removing existing Bitcoin container...");
    let _ = Command::new("docker")
        .args(["rm", "-f", "nigiri-bitcoin"])
        .output();

    // Remove Bitcoin data volume
    println!("Removing Bitcoin data volume...");
    let _ = Command::new("docker")
        .args(["volume", "rm", "-f", "nigiri-bitcoin-data"])
        .output();

    // Create a temporary container to clean up wallet data
    println!("Cleaning up wallet data...");
    let _ = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            "nigiri-bitcoin-data:/data",
            "alpine",
            "sh",
            "-c",
            "rm -rf /data/.bitcoin/regtest/wallets/*"
        ])
        .output();

    // Start fresh Nigiri instance
    println!("Starting fresh Nigiri instance...");
    let nigiri_output = Command::new("nigiri")
        .arg("start")
        .output();

    match nigiri_output {
        Ok(output) => {
            if output.status.success() {
                println!("Nigiri started successfully.");
            } else {
                eprintln!(
                    "Failed to start Nigiri. Error: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error while starting Nigiri: {}", e);
            std::process::exit(1);
        }
    }

    // Wait for Nigiri's Bitcoin node to be fully ready
    println!("Waiting for Nigiri services to be ready...");
    wait_for_nigiri_ready();

    println!("Setup completed successfully.");
}

/// Checks if Nigiri's Bitcoin node is ready by performing multiple verification steps
/// 
/// This function performs a series of increasingly complex operations to verify
/// that the Bitcoin node is fully operational, with proper error handling and
/// retry logic.
fn wait_for_nigiri_ready() {
    println!("Checking if Nigiri Bitcoin node is ready...");
    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(180); // 3 minute timeout
    
    // Step 1: Wait for bitcoind to be fully started with retry
    let mut bitcoind_ready = false;
    while !bitcoind_ready {
        if start_time.elapsed() > timeout {
            eprintln!("Timed out waiting for Nigiri bitcoind to be ready");
            std::process::exit(1);
        }
        
        // Check if bitcoind is accepting connections
        let ping_result = Command::new("nigiri")
            .args(["rpc", "ping"])
            .output();
            
        match ping_result {
            Ok(output) if output.status.success() => {
                println!("Bitcoin daemon is accepting basic commands");
                bitcoind_ready = true;
            }
            _ => {
                println!("Waiting for Bitcoin daemon to accept connections...");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
    
    // Step 2: Verify blockchain info is available
    let mut blockchain_ready = false;
    while !blockchain_ready {
        if start_time.elapsed() > timeout {
            eprintln!("Timed out waiting for blockchain to be available");
            std::process::exit(1);
        }
        
        let blockchain_result = Command::new("nigiri")
            .args(["rpc", "getblockchaininfo"])
            .output();
            
        match blockchain_result {
            Ok(output) if output.status.success() => {
                println!("Blockchain information is available");
                blockchain_ready = true;
            }
            _ => {
                println!("Waiting for blockchain to be available...");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
    
    // Step 3: Generate a test address and mine blocks - ultimate test of readiness
    let mut mining_successful = false;
    let mut retries = 0;
    const MAX_RETRIES: u8 = 5;
    
    // Use the default wallet instead of creating a new one
    while !mining_successful && retries < MAX_RETRIES {
        retries += 1;
        println!("Verification attempt #{}: Testing mining capability", retries);
        
        // Get a new address using the default wallet
        let address_result = Command::new("nigiri")
            .args(["rpc", "getnewaddress"])
            .output();
            
        match address_result {
            Ok(output) if output.status.success() => {
                let address = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if address.is_empty() {
                    println!("Got empty address, retrying...");
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
                
                println!("Generated test address: {}", address);
                
                // Try to mine a block to this address
                let mine_result = Command::new("nigiri")
                    .args(["rpc", "generatetoaddress", "1", &address])
                    .output();
                    
                match mine_result {
                    Ok(mine_output) if mine_output.status.success() => {
                        // Verify the block was actually mined
                        let block_count_result = Command::new("nigiri")
                            .args(["rpc", "getblockcount"])
                            .output();
                            
                        if let Ok(block_output) = block_count_result {
                            if block_output.status.success() {
                                println!("Block mining successful!");
                                mining_successful = true;
                                break;
                            }
                        }
                    }
                    _ => {
                        println!("Mining failed, waiting before retry...");
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            _ => {
                println!("Failed to get address, waiting before retry...");
                thread::sleep(Duration::from_secs(3));
            }
        }
    }
    
    if mining_successful {
        println!("Nigiri Bitcoin node is fully operational!");
    } else {
        eprintln!("Failed to verify Nigiri after {} attempts", MAX_RETRIES);
        eprintln!("Tests may fail.");
        // Continue anyway to let tests attempt to run
    }
    
    // Allow the system to stabilize before proceeding
    thread::sleep(Duration::from_secs(3));
}

/// Funds a Bitcoin address using Nigiri's faucet and mines a block
/// 
/// # Arguments
/// 
/// * `address` - The Bitcoin address to fund
pub fn fund_address(address: &str) {
    let faucet_response = Command::new("nigiri")
        .args(["faucet", address])
        .output()
        .expect("Failed to fund wallet");
    eprintln!("{}", String::from_utf8_lossy(&faucet_response.stdout));

    eprintln!("Mining to {}", address);
    let resp = mine(address, 1);
    eprintln!("response {}", String::from_utf8_lossy(&resp.stdout));
}

/// Mines a specified number of blocks to a given address using Nigiri
/// 
/// # Arguments
/// 
/// * `address` - The Bitcoin address to mine to
/// * `num_blocks` - Number of blocks to mine
pub fn mine(address: &str, num_blocks: u16) -> std::process::Output {
    Command::new("nigiri")
        .args(["rpc", "generatetoaddress", &num_blocks.to_string(), address])
        .output()
        .expect("Failed to mine block")
} 