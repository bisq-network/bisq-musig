use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::Arc;

use anyhow::{bail, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use bdk_wallet::bitcoin::{Address, Amount, BlockHash, Txid};
use bdk_wallet::{serde_json, Balance};
use futures_util::StreamExt as _;
use rpc::wallet::{TxConfidence, WalletService, WalletServiceImpl};
use serde::Deserialize;
use tokio::sync::{OnceCell, Semaphore, SemaphorePermit};
use tokio::task;
use tokio::time::{self, Duration};

const BITCOIND_RPC_URL: &str = "http://localhost:18443";
const BITCOIND_POLLING_PERIOD: Duration = Duration::from_millis(100);

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_wallet_service_mine_single_tx() {
    let (wallet_service, _permit) = start_wallet_service_with_nigiri_permit().await;
    let balance1 = wallet_service.balance();

    // Send 0.01 BTC from bitcoind to a fresh wallet address and wait for wallet to sync.
    let addr = wallet_service.reveal_next_address();
    let amount = Amount::from_sat(1_000_000);
    let txid = send_to_address(&addr.address, Amount::from_sat(1_000_000));
    time::sleep(BITCOIND_POLLING_PERIOD * 2).await;

    // Open up a tx confidence stream on the (unconfirmed) paying tx.
    let mut stream = wallet_service.get_tx_confidence_stream(txid);
    assert!(matches!(stream.next().await, Some(Some(TxConfidence { num_confirmations: 0, .. }))));

    let balance2 = wallet_service.balance();
    assert_eq!(balance2.total(), balance1.total() + amount);
    assert!(balance2.untrusted_pending >= amount);

    // Mine a block and wait for wallet to sync.
    mine_single();
    time::sleep(BITCOIND_POLLING_PERIOD * 2).await;

    let balance3 = wallet_service.balance();
    assert_eq!(balance3.total(), balance2.total());
    assert_eq!(balance3.trusted_pending, Amount::ZERO);
    assert_eq!(balance3.untrusted_pending, Amount::ZERO);

    // The tx should now be confirmed.
    assert!(matches!(stream.next().await, Some(Some(TxConfidence { num_confirmations: 1, .. }))));
}

fn send_to_address(address: &Address, amount: Amount) -> Txid {
    Result::<_>::unwrap(task::block_in_place(|| {
        let client = Client::new(BITCOIND_RPC_URL, nigiri_rpc_auth())?;
        Ok(client.send_to_address(address, amount, None, None, None, Some(true),
            None, Some(EstimateMode::Economical))?)
    }))
}

fn mine_single() -> BlockHash {
    mine(1, None)[0]
}

fn mine(block_num: u64, to_address: Option<&Address>) -> Vec<BlockHash> {
    Result::<_>::unwrap(task::block_in_place(|| {
        let client = Client::new(BITCOIND_RPC_URL, nigiri_rpc_auth())?;
        let address = match to_address {
            Some(address) => address,
            None => &client.get_new_address(None, None)?.assume_checked()
        };
        Ok(client.generate_to_address(block_num, address)?)
    }))
}

async fn start_wallet_service_with_nigiri_permit() -> (Arc<impl WalletService>, NigiriPermit) {
    let permit = start_nigiri_with_permit().await.unwrap();

    let wallet_service = Arc::new(WalletServiceImpl::create_with_rpc_params(
        nigiri_rpc_auth(), BITCOIND_POLLING_PERIOD));
    assert_eq!(wallet_service.balance(), Balance::default());

    wallet_service.clone().spawn_connection();
    // Wait for RPC sync...
    // FIXME: A bit hacky -- should add logic to the service to notify when the wallet is synced.
    time::sleep(Duration::from_secs(1)).await;

    (wallet_service, permit)
}

fn nigiri_rpc_auth() -> Auth { Auth::UserPass("admin1".into(), "123".into()) }

type NigiriPermit = (&'static NigiriConfig, SemaphorePermit<'static>);

async fn start_nigiri_with_permit() -> Result<NigiriPermit> {
    static PERMIT: Semaphore = Semaphore::const_new(1);

    Ok((start_nigiri().await?, PERMIT.acquire().await?))
}

async fn start_nigiri() -> Result<&'static NigiriConfig> {
    static ONCE: OnceCell<NigiriConfig> = OnceCell::const_new();

    ONCE.get_or_try_init(|| async {
        task::spawn_blocking(|| {
            if let Ok(config) = read_started_nigiri_config() {
                // Nigiri is already started, possibly externally -- assume all its components are
                // actually fully started and not in the process of shutting down.
                return Ok(config);
            }
            let output = Command::new("nigiri")
                .arg("--datadir").arg(fs::canonicalize(".nigiri")?)
                .args(["start", "--ci"])
                .output()?;
            if !output.status.success() {
                bail!("Could not start nigiri: {output:#?}");
            }
            let config = read_started_nigiri_config()?;
            // We have to wait for bitcoind to finish starting up, even though Nigiri is already
            // started, as otherwise JSON-RPC calls to it will fail with a "Loading wallet…" error.
            // FIXME: A bit hacky - can we poll for a 'ready' status?
            std::thread::sleep(Duration::from_secs(2));
            Ok(config)
        }).await?
    }).await
}

fn read_nigiri_config() -> Result<NigiriConfig> {
    let config_result = fs::read_to_string(".nigiri/nigiri.config.json");
    Ok(serde_json::from_str(&config_result?)?)
}

fn read_started_nigiri_config() -> Result<NigiriConfig> {
    read_nigiri_config()?.check_started()
}

#[derive(Debug, Deserialize)]
struct NigiriConfig(HashMap<String, String>);

impl NigiriConfig {
    fn is_started(&self) -> bool {
        self.0.get("ready").map(String::as_str) == Some("true") &&
            self.0.get("running").map(String::as_str) == Some("true")
    }

    fn check_started(self) -> Result<Self> {
        if !self.is_started() {
            bail!("Unstarted nigiri config: {self:#?}");
        }
        Ok(self)
    }
}
