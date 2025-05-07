#![cfg_attr(feature = "unimock", expect(clippy::ignored_unit_patterns, reason = "macro-generated code"))]

use bdk_bitcoind_rpc::Emitter;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use bdk_wallet::{AddressInfo, Balance, KeychainKind, LocalOutput, Wallet};
use bdk_wallet::bitcoin::{Network, Transaction, Txid};
use bdk_wallet::chain::{CheckPoint, ChainPosition, ConfirmationBlockTime};
use drop_stream::DropStream;
use futures::never::Never;
use futures::stream::{BoxStream, StreamExt as _};
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;
use tokio::task::{self, JoinHandle};
use tokio::time::{self, Duration, MissedTickBehavior};

use crate::observable::ObservableHashMap;

const COOKIE_FILE_PATH: &str = ".localnet/bitcoind/regtest/.cookie";
//noinspection SpellCheckingInspection
const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAj\
    WytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";
//noinspection SpellCheckingInspection
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAj\
    WytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";

#[cfg_attr(feature = "unimock", unimock::unimock(api = WalletServiceMock))]
#[tonic::async_trait]
pub trait WalletService {
    /// # Errors
    /// Will return `Err` if connection or continual sync fails at any point
    async fn connect(&self) -> Result<Never>;

    fn balance(&self) -> Balance;
    fn reveal_next_address(&self) -> AddressInfo;
    fn list_unspent(&self) -> Vec<LocalOutput>;
    fn get_tx_confidence_stream(&self, txid: Txid) -> BoxStream<'static, Option<TxConfidence>>;

    /// # Panics
    /// Will panic if called outside the context of a Tokio runtime
    fn spawn_connection(self: Arc<Self>) -> JoinHandle<Result<Never>> where Self: Send + Sync + 'static {
        task::spawn(async move {
            let Err(e) = self.connect().await;
            eprintln!("Wallet connection error: {e}");
            Err(e)
        })
    }
}

pub struct WalletServiceImpl {
    // NOTE: To avoid deadlocks, must be careful to acquire these locks in consistent order. At
    //  present, the lock on 'wallet' is acquired first, then the lock on 'tx_confidence_map'.
    // TODO: Consider using async locks here, as wallet operations have nontrivial cost:
    wallet: RwLock<Wallet>,
    tx_confidence_map: Mutex<ObservableHashMap<Txid, TxConfidence>>,
}

impl WalletServiceImpl {
    // TODO: Make wallet setup configurable.
    pub fn new() -> Self {
        let wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("hardcoded descriptors should be valid");

        let mut tx_confidence_map = ObservableHashMap::new();
        tx_confidence_map.sync(tx_confidence_entries(&wallet));

        Self { wallet: RwLock::new(wallet), tx_confidence_map: Mutex::new(tx_confidence_map) }
    }

    fn sync_tx_confidence_map(&self) {
        let wallet = self.wallet.read().unwrap();
        self.tx_confidence_map.lock().unwrap().sync(tx_confidence_entries(&wallet));
    }
}

impl Default for WalletServiceImpl {
    fn default() -> Self { Self::new() }
}

fn tx_confidence_entries(wallet: &Wallet) -> impl Iterator<Item=(Txid, TxConfidence)> + '_ {
    let next_height = wallet.latest_checkpoint().height() + 1;
    wallet.transactions()
        .map(move |wallet_tx| {
            let wallet_tx: WalletTx = wallet_tx.into();
            let conf_height = wallet_tx.chain_position.confirmation_height_upper_bound().unwrap_or(next_height);
            let num_confirmations = next_height - conf_height;
            (wallet_tx.txid, TxConfidence { wallet_tx, num_confirmations })
        })
}

#[tonic::async_trait]
impl WalletService for WalletServiceImpl {
    async fn connect(&self) -> Result<Never> {
        let rpc_client: Client = task::block_in_place(|| Client::new(
            "https://127.0.0.1:18443",
            Auth::CookieFile(COOKIE_FILE_PATH.into()),
        ))?;

        let blockchain_info = task::block_in_place(|| rpc_client.get_blockchain_info())?;
        println!("Connected to Bitcoin Core RPC.\n  Chain: {}\n  Latest block: {} at height {}",
            blockchain_info.chain, blockchain_info.best_block_hash, blockchain_info.blocks);

        let wallet_tip: CheckPoint = self.wallet.read().unwrap().latest_checkpoint();
        let start_height = wallet_tip.height();
        println!("Current wallet tip is: {} at height {}", wallet_tip.hash(), start_height);

        let mut emitter = Emitter::new(&rpc_client, wallet_tip, start_height);
        while let Some(block) = task::block_in_place(|| emitter.next_block())? {
            print!(" {}", block.block_height());
            self.wallet.write().unwrap()
                .apply_block_connected_to(&block.block, block.block_height(), block.connected_to())?;
        }
        println!();

        println!("Syncing mempool...");
        let mempool_emissions = task::block_in_place(|| emitter.mempool())?;
        self.wallet.write().unwrap().apply_unconfirmed_txs(mempool_emissions);

        println!("Syncing tx confidence map with wallet.");
        self.sync_tx_confidence_map();

        println!("Wallet balance after syncing: {}", self.balance().total());

        println!("Polling for further blocks and mempool txs...");
        let mut interval = time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;

            while let Some(block) = task::block_in_place(|| emitter.next_block())? {
                println!("New block {} at height {}.", block.block_hash(), block.block_height());
                self.wallet.write().unwrap()
                    .apply_block_connected_to(&block.block, block.block_height(), block.connected_to())?;
            }

            let mempool_emissions = task::block_in_place(|| emitter.mempool())?;
            self.wallet.write().unwrap().apply_unconfirmed_txs(mempool_emissions);

            // TODO: Skip needless cache/map updates if the wallet hasn't actually changed:
            self.sync_tx_confidence_map();
        }
    }

    fn balance(&self) -> Balance {
        self.wallet.read().unwrap().balance()
    }

    fn reveal_next_address(&self) -> AddressInfo {
        self.wallet.write().unwrap().reveal_next_address(KeychainKind::External)
    }

    fn list_unspent(&self) -> Vec<LocalOutput> {
        self.wallet.read().unwrap().list_unspent().collect()
    }

    fn get_tx_confidence_stream(&self, txid: Txid) -> BoxStream<'static, Option<TxConfidence>> {
        DropStream::new(self.tx_confidence_map.lock().unwrap().observe(txid), move || {
            println!("Confidence stream has been dropped for txid: {txid}");
        }).boxed()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TxConfidence {
    pub wallet_tx: WalletTx,
    pub num_confirmations: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct WalletTx {
    pub txid: Txid,
    pub tx: Arc<Transaction>,
    pub chain_position: ChainPosition<ConfirmationBlockTime>,
}

impl From<bdk_wallet::WalletTx<'_>> for WalletTx {
    fn from(value: bdk_wallet::WalletTx) -> Self {
        Self { txid: value.tx_node.txid, tx: value.tx_node.tx, chain_position: value.chain_position }
    }
}

pub type Result<T, E = WalletErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
pub enum WalletErrorKind {
    BitcoindRpc(#[from] bdk_bitcoind_rpc::bitcoincore_rpc::Error),
    ApplyHeader(#[from] bdk_wallet::chain::local_chain::ApplyHeaderError),
}
