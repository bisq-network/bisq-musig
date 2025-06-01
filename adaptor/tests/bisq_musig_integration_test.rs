use regtest_env::setup;
use std::{process::Command, thread, time};
use std::time::SystemTime;

const EPSILON: f64 = 0.00001; // Allowable margin of error for balance checks

fn approx_eq(left: f64, right: f64) -> bool {
    (left - right).abs() < EPSILON
}

// Helper function to run nigiri commands and handle errors
fn run_nigiri_command(args: &[&str]) -> Result<String, String> {
    println!("Running command: nigiri {}", args.join(" "));
    let output = Command::new("nigiri")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute nigiri command: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Command 'nigiri {}' failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn create_wallet(name: &str) -> Result<String, String> {
    run_nigiri_command(&["rpc", "createwallet", name])?;
    run_nigiri_command(&["rpc", &format!("-rpcwallet={}", name), "getnewaddress"])
}

/// Integration test that simulates a basic transaction between two wallets.
/// 
/// This test:
/// 1. Sets up a test environment using Nigiri (Bitcoin regtest)
/// 2. Creates unique timestamped wallets for Alice and Bob
/// 3. Funds Alice's wallet using the Nigiri faucet
/// 4. Simulates a transaction from Alice to Bob (0.01 BTC)
/// 5. Verifies the transaction by checking Bob's final balance
/// 
/// Requirements:
/// - Nigiri must be installed and running
/// - Test runs on Bitcoin regtest network
#[test]
fn test_bisq_musig() -> Result<(), String> {
    setup();

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let alice_wallet = format!("alice_{}", timestamp);
    let bob_wallet = format!("bob_{}", timestamp);

    // Create wallets and get addresses
    let alice_address = create_wallet(&alice_wallet)?;
    let bob_address = create_wallet(&bob_wallet)?;

    // Fund Alice's wallet and mine a block
    run_nigiri_command(&["faucet", &alice_address])?;
    thread::sleep(time::Duration::from_secs(2));
    run_nigiri_command(&["rpc", "generatetoaddress", "1", &alice_address])?;

    // Send funds from Alice to Bob
    let tx_id = run_nigiri_command(&[
        "rpc",
        &format!("-rpcwallet={}", alice_wallet),
        "sendtoaddress",
        &bob_address,
        "0.01",
    ])?;
    println!("Transaction ID: {}", tx_id);

    // Mine a block and verify Bob's balance
    run_nigiri_command(&["rpc", "generatetoaddress", "1", &alice_address])?;
    thread::sleep(time::Duration::from_secs(2));

    let bob_balance: f64 = run_nigiri_command(&["rpc", &format!("-rpcwallet={}", bob_wallet), "getbalance"])?
        .parse()
        .map_err(|e| format!("Failed to parse Bob's balance: {}", e))?;

    if !approx_eq(bob_balance, 0.01) {
        return Err(format!(
            "Bob's balance should be approximately 0.01 BTC! Found: {}",
            bob_balance
        ));
    }

    Ok(())
}