// Bitcoin and BDK-related imports

use crate::protocol_musig_adaptor::MemWallet;
use bdk_wallet::bitcoin::Amount;
use std::process::Output;
use std::{thread, time};
use regtest_env::{fund_address, mine};

pub(crate) fn funded_wallet() -> MemWallet {
    println!("loading wallet...");
    let mut wallet = MemWallet::new().unwrap();
    fund_wallet(&mut wallet);
    wallet
}
pub(crate) fn fund_wallet(wallet: &mut MemWallet) {
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

const FUND_ADDRESS: &str = "bcrt1plrmcqc9pwf4zjcej5n7ynre5k8lkn0xcz0c7y3dw37e8nqew2utq5l06jv";

pub(crate) fn tiktok() -> Output {
    mine(FUND_ADDRESS, 1)
} 