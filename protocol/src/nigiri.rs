// FIXME: Temporarily suppressed warnings in order to get a clean build:
#![allow(warnings)]

// Bitcoin and BDK-related imports

use crate::protocol_musig_adaptor::MemWallet;
use bdk_wallet::bitcoin::Amount;
use std::process::Output;
use std::{process::Command, thread, time};

pub fn funded_wallet() -> MemWallet {
    println!("loading wallet...");
    let mut wallet = MemWallet::new().unwrap();
    fund_wallet(&mut wallet);
    wallet
}
pub fn fund_wallet(wallet: &mut MemWallet) {
    let initial_balance = wallet.balance();
    // load some more coin to wallet
    let adr = wallet.next_unused_address().to_string();
    println!("address = {}", adr);
    fund_address(&*adr);
    loop {
        thread::sleep(time::Duration::from_secs(1));
        wallet.sync().unwrap();
        let balance = wallet.balance();
        println!("\nCurrent wallet amount: {}", balance);

        if balance > initial_balance {
            break;
        }
    }
    assert!(wallet.balance() >= Amount::from_btc(1.0).unwrap());
}

fn fund_address(address: &str) {
    let faucet_response = Command::new("nigiri")
        .args(["faucet", address])
        .output()
        .expect("Failed to fund Alice's wallet");
    eprintln!("{}", String::from_utf8_lossy(&faucet_response.stdout));
    // thread::sleep(time::Duration::from_secs(2)); // Add delays between steps

    eprintln!("Mining mining to {}", address);
    let resp = mine(address, 1);
    eprintln!("reponse {}", String::from_utf8_lossy(&resp.stdout));
}

const FUND_ADDRESS: &str = "bcrt1plrmcqc9pwf4zjcej5n7ynre5k8lkn0xcz0c7y3dw37e8nqew2utq5l06jv";

pub(crate) fn tiktok() -> Output {
    mine(FUND_ADDRESS, 1)
}
fn mine(address: &str, num_blocks: u16) -> Output {
    Command::new("nigiri")
        .args(["rpc", "generatetoaddress", &num_blocks.to_string(), address])
        .output()
        .expect("Failed to mine block")
}

#[test]
pub(crate) fn check_start() {
    // Step 2: Run 'nigiri start' to start Nigiri
    let nigiri_output = Command::new("nigiri").arg("start").output().unwrap();

    if nigiri_output.status.success() {
        eprintln!("Nigiri starting...");
        thread::sleep(time::Duration::from_secs(3));
        eprintln!("Nigiri started successfully.");
    } else {
        let msg = String::from_utf8_lossy(&nigiri_output.stderr);
        if !msg.contains("already running") {
            panic!(
                "Failed to start Nigiri. Please install Docker and Nigiri manually. Error: {}",
                String::from_utf8_lossy(&nigiri_output.stderr)
            );
        }
    }
}
