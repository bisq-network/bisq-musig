use anyhow::Ok;
use bdk_electrum::electrum_client::{Client, Config};
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::{Address, Amount, Network};
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{KeychainKind, SignOptions};
use rand::RngCore;
use secp::Scalar;
use std::str::FromStr;
use testenv::TestEnv;
use wallet::bmp_wallet::*;

fn new_private_key() -> Scalar {
    let mut seed: [u8; 32] = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    Scalar::from_slice(&seed).unwrap()
}

#[test]
fn init_test() -> anyhow::Result<()> {
    let env = TestEnv::new()?;

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    let receive_amount = Amount::from_sat(100000);

    let client = Client::from_config(&env.electrum_url(), Config::default())?;
    let data_source = BdkElectrumClient::new(client);

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(&data_source)?;

    assert_eq!(wallet.balance(), receive_amount);
    Ok(())
}

#[test]
fn test_sync_with_imported_keys() -> anyhow::Result<()> {
    let env = TestEnv::new()?;

    let prv_key = new_private_key();

    let receive_amount = Amount::from_sat(100000);

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    wallet.import_private_key(prv_key);

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(env.bdk_electrum_client())?;
    assert_eq!(wallet.balance(), receive_amount + receive_amount);

    Ok(())
}

#[test]

fn test_broadcast_transaction() -> anyhow::Result<()> {
    // This test broadcast a transaction created from main wallet balance only
    let env = TestEnv::new()?;
    let data_source = env.bdk_electrum_client();

    let prv_key = new_private_key();

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    wallet.import_private_key(prv_key);

    let receive_amount = Amount::from_sat(100000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(data_source)?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(1000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();
    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(data_source)?;

    let new_balance = receive_amount - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let enc_wallet = wallet.encrypt("hello")?;
    assert_eq!(enc_wallet.balance(), new_balance);

    Ok(())
}

#[test]
fn test_broadcast_transaction_two() -> anyhow::Result<()> {
    // This test broadcast a transaction created from imported wallets only
    let env = TestEnv::new()?;

    let client = Client::from_config(&env.electrum_url(), Config::default())?;
    let data_source = BdkElectrumClient::new(client);

    let prv_key = new_private_key();

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    wallet.import_private_key(prv_key);

    let receive_amount = Amount::from_sat(100000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(&data_source)?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(1000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();
    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(&data_source)?;

    let new_balance = receive_amount - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let enc_wallet = wallet.encrypt("hello")?;
    assert_eq!(enc_wallet.balance(), new_balance);

    Ok(())
}

#[test]
fn test_broadcast_transaction_three() -> anyhow::Result<()> {
    // This test will attempt send a transaction created from both main wallet and imported keys
    // balance
    let env = TestEnv::new()?;

    let client = Client::from_config(&env.electrum_url(), Config::default())?;
    let data_source = BdkElectrumClient::new(client);

    let prv_key = new_private_key();

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    wallet.import_private_key(prv_key);

    let main_wallet_addr = wallet.next_unused_address(KeychainKind::External);

    let receive_amount = Amount::from_sat(100000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.fund_address(&main_wallet_addr, receive_amount)?;

    env.mine_block()?;

    wallet.sync_all(&data_source)?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(100000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();

    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(&data_source)?;

    let new_balance = (receive_amount + receive_amount) - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let enc_wallet = wallet.encrypt("hello")?;
    assert_eq!(enc_wallet.balance(), new_balance);

    Ok(())
}
