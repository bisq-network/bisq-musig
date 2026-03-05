use std::str::FromStr as _;
use bdk_kyoto::bip157::tokio;
use bdk_kyoto::{FeeRate, TrustedPeer};
use bdk_wallet::bitcoin::{Address, Amount, Network};
use bdk_wallet::psbt::PsbtUtils as _;
use bdk_wallet::{KeychainKind, SignOptions};
use rand::RngCore as _;
use secp::Scalar;
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
    let receive_amount = Amount::from_sat(100_000);

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(env.bdk_electrum_client())?;

    assert_eq!(wallet.balance(), receive_amount);
    Ok(())
}

#[test]
fn test_sync_with_imported_keys() -> anyhow::Result<()> {
    let env = TestEnv::new()?;

    let prv_key = new_private_key();

    let receive_amount = Amount::from_sat(100_000);

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

    let receive_amount = Amount::from_sat(100_000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    let receiving_addr = wallet.next_unused_address(KeychainKind::External);

    env.fund_address(&receiving_addr, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(data_source)?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(1_000);
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
    let data_source = env.bdk_electrum_client();

    let prv_key = new_private_key();

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    wallet.import_private_key(prv_key);

    let receive_amount = Amount::from_sat(100_000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.mine_block()?;

    wallet.sync_all(data_source)?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(1_000);
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
fn test_broadcast_transaction_three() -> anyhow::Result<()> {
    // This test will attempt send a transaction created from both main wallet and imported keys
    // balance
    let env = TestEnv::new()?;
    let data_source = env.bdk_electrum_client();

    let prv_key = new_private_key();

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    wallet.import_private_key(prv_key);

    let main_wallet_addr = wallet.next_unused_address(KeychainKind::External);

    let receive_amount = Amount::from_sat(100_000);
    let to_address =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;

    env.fund_from_prv_key(&prv_key, receive_amount)?;
    env.fund_address(&main_wallet_addr, receive_amount)?;

    env.mine_block()?;

    wallet.sync_all(data_source)?;

    let mut tx_builder = wallet.build_tx();
    let send_amount = Amount::from_sat(100_000);
    tx_builder.add_recipient(to_address.assume_checked(), send_amount);

    let mut psbt = tx_builder.finish()?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();

    // Broadcast the transaction
    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    // Rescan the wallet to apply balance changes
    wallet.sync_all(data_source)?;

    let new_balance = (receive_amount + receive_amount) - send_amount - fee;
    assert_eq!(wallet.balance(), new_balance);

    // Reload the wallet by encrypting it to make sure the state changes are persisted
    let enc_wallet = wallet.encrypt("hello")?;
    let mut enc_wallet = enc_wallet.decrypt("hello")?;
    env.fund_address(&main_wallet_addr, Amount::from_sat(10_000))?;
    env.mine_block()?;
    enc_wallet.sync_all(data_source)?;
    assert_eq!(enc_wallet.balance(), new_balance + Amount::from_sat(10_000));

    Ok(())
}

#[tokio::test]
async fn test_cbf_main_wallet() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    env.mine_blocks(2)?;
    let mut wallet = BMPWallet::new(Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);
    env.fund_address(&addr, Amount::from_sat(100_000))?;

    assert_eq!(wallet.balance(), Amount::from_sat(0));

    env.mine_blocks(4)?;

    let scan_type = bdk_kyoto::ScanType::Sync;
    let peers = vec![TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];
    wallet.sync_cbf(scan_type, peers).await?;
    assert_eq!(wallet.balance(), Amount::from_sat(100_000));
    Ok(())
}

#[tokio::test]
async fn test_cbf_imported() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    env.mine_block()?;

    let mut wallet = BMPWallet::new(Network::Regtest)?;

    let prv_keys = [new_private_key(), new_private_key(), new_private_key()];
    prv_keys.iter().for_each(|e| wallet.import_private_key(*e));
    prv_keys.iter().for_each(|e| {
        env.fund_from_prv_key(e, Amount::from_sat(10_000)).unwrap();
    });

    assert_eq!(wallet.balance(), Amount::from_sat(0));

    env.mine_blocks(4)?;

    let scan_type = bdk_kyoto::ScanType::Sync;
    let peers = vec![TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];
    wallet.sync_cbf_imported(scan_type, peers).await?;
    assert_eq!(wallet.balance(), Amount::from_sat(30_000));
    Ok(())
}

#[tokio::test]
async fn test_cbf_imported_and_main() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    env.mine_block()?;

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);
    env.fund_address(&addr, Amount::from_sat(100_000))?;

    let prv_keys = [new_private_key(), new_private_key(), new_private_key()];
    prv_keys.iter().for_each(|e| wallet.import_private_key(*e));
    prv_keys.iter().for_each(|e| {
        env.fund_from_prv_key(e, Amount::from_sat(10_000)).unwrap();
    });

    assert_eq!(wallet.balance(), Amount::from_sat(0));

    env.mine_blocks(4)?;

    let scan_type = bdk_kyoto::ScanType::Sync;
    let peers = vec![TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];

    wallet.sync_cbf_imported(scan_type, peers.clone()).await?;
    wallet.sync_cbf(scan_type, peers).await?;

    assert_eq!(wallet.balance(), Amount::from_sat(130_000));

    Ok(())
}

#[tokio::test]
async fn test_cbf_persistence() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    env.mine_block()?;

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);
    env.fund_address(&addr, Amount::from_sat(230_000))?;

    let scan_type = bdk_kyoto::ScanType::Sync;
    let peers = vec![TrustedPeer::from_socket_addr(
        env.p2p_socket_addr().unwrap(),
    )];
    env.mine_block()?;
    wallet.sync_cbf(scan_type, peers.clone()).await?;
    assert_eq!(wallet.balance(), Amount::from_sat(230_000));

    // Reload the wallet from persisted state
    let loaded_wallet = BMPWallet::load_wallet(Network::Regtest, None)?;
    assert_eq!(loaded_wallet.balance(), Amount::from_sat(230_000));

    // Encrypt the wallet then reload it and check for balance state
    let encrypted_wallet = loaded_wallet.encrypt("secret123")?;
    let mut encrypted_wallet = encrypted_wallet.decrypt("secret123")?;

    env.fund_address(&addr, Amount::from_sat(70_000))?;
    env.mine_block()?;
    encrypted_wallet.sync_cbf(scan_type, peers.clone()).await?;
    assert_eq!(encrypted_wallet.balance(), Amount::from_sat(300_000));

    // Create a transaction and broadcast it to the connected peer
    let receiving_addr =
        Address::from_str("tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz")?;
    let mut tx_builder = encrypted_wallet.build_tx();
    tx_builder.add_recipient(receiving_addr.assume_checked(), Amount::from_sat(70_000));

    let mut psbt = tx_builder.finish()?;

    encrypted_wallet.sign(&mut psbt, SignOptions::default())?;

    let fee = psbt.fee_amount().unwrap();

    env.broadcast(&psbt.extract_tx()?)?;
    env.mine_block()?;

    encrypted_wallet.sync_cbf(scan_type, peers).await?;
    assert_eq!(encrypted_wallet.balance(), Amount::from_sat(230_000) - fee);

    Ok(())
}

#[tokio::test]
async fn test_drain_wallet_with_main_balance() -> anyhow::Result<()> {
    // This test will attempt to drain the imported wallets UTXOs
    // With the main wallet having some balance it won't be touched.
    let env = TestEnv::new()?;
    env.mine_block()?;

    let mut wallet = BMPWallet::new(Network::Regtest)?;
    let addr = wallet.next_unused_address(KeychainKind::External);

    let amount_to_send_main_wallet = Amount::from_sat(100_000);
    let amount_to_send_imported = Amount::from_sat(10_000);
    env.fund_address(&addr, amount_to_send_main_wallet)?;

    let prv_keys = [new_private_key(), new_private_key()];
    prv_keys.iter().for_each(|e| wallet.import_private_key(*e));
    prv_keys.iter().for_each(|e| {
        env.fund_from_prv_key(e, amount_to_send_imported).unwrap();
    });

    env.mine_block()?;
    wallet.sync_all(env.bdk_electrum_client())?;

    // Doing *2 because we have two imported keys with the same amount received 10_000
    let current_balance = amount_to_send_main_wallet + amount_to_send_imported * 2;
    assert_eq!(wallet.balance(), current_balance);

    let mut psbt = wallet.drain_imported_balance(FeeRate::from_sat_per_vb(10).unwrap())?;

    wallet.sign(&mut psbt, SignOptions::default())?;

    let drained_amount = amount_to_send_imported * 2 - psbt.fee()?;

    let tx = psbt.extract_tx()?;

    env.broadcast(&tx)?;
    env.mine_block()?;

    wallet.sync_all(env.bdk_electrum_client())?;

    let main_wallet_balance = drained_amount + amount_to_send_main_wallet;

    assert_eq!(wallet.balance(), main_wallet_balance);

    Ok(())
}

#[tokio::test]
#[should_panic(expected = "value: Output below the dust limit: 0")]
async fn test_drain_wallet_no_balance() {
    // In this test drain is called but the wallet doesn't have any imported key
    // insuffucient balance should be thrown
    let env = TestEnv::new().unwrap();
    env.mine_block().unwrap();

    let mut wallet = BMPWallet::new(Network::Regtest).unwrap();
    let addr = wallet.next_unused_address(KeychainKind::External);

    let amount_to_send_main_wallet = Amount::from_sat(100_000);

    env.fund_address(&addr, amount_to_send_main_wallet).unwrap();
    env.mine_block().unwrap();

    wallet
        .drain_imported_balance(FeeRate::from_sat_per_vb(10).unwrap())
        .unwrap();
}
