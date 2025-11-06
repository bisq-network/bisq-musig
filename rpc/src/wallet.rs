#![cfg_attr(feature = "unimock", expect(clippy::ignored_unit_patterns, reason = "macro-generated code"))]

use std::sync::{Arc, Mutex, RwLock};

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::bitcoin::{Network, Transaction, Txid};
use bdk_wallet::chain::{ChainPosition, CheckPoint, ConfirmationBlockTime};
use bdk_wallet::{AddressInfo, Balance, KeychainKind, LocalOutput, Wallet};
use drop_stream::DropStreamExt as _;
use futures_util::never::Never;
use futures_util::stream::{BoxStream, StreamExt as _};
use thiserror::Error;
use tokio::task::{self, JoinHandle};
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{debug, error, info, trace};

use crate::observable::ObservableHashMap;

const LOCALNET_COOKIE_FILE_PATH: &str = ".localnet/bitcoind/regtest/.cookie";
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
            self.connect().await
                .inspect_err(|e| error!("Wallet connection error: {e}"))
        })
    }
}

pub struct WalletServiceImpl {
    // NOTE: To avoid deadlocks, must be careful to acquire these locks in consistent order. At
    //  present, the lock on 'wallet' is acquired first, then the lock on 'tx_confidence_map'.
    // TODO: Consider using async locks here, as wallet operations have nontrivial cost:
    wallet: RwLock<Wallet>,
    tx_confidence_map: Mutex<ObservableHashMap<Txid, TxConfidence>>,

    // Make the following RPC parameters configurable for testing:
    rpc_auth: Auth,
    poll_period: Duration,
}

impl WalletServiceImpl {
    pub fn new() -> Self {
        Self::create_with_rpc_params(
            Auth::CookieFile(LOCALNET_COOKIE_FILE_PATH.into()),
            Duration::from_secs(1))
    }

    // TODO: Make wallet setup properly configurable, not just the RPC authentication method and polling period.
    pub fn create_with_rpc_params(rpc_auth: Auth, poll_period: Duration) -> Self {
        let wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("hardcoded descriptors should be valid");

        let mut tx_confidence_map = ObservableHashMap::new();
        tx_confidence_map.sync(tx_confidence_entries(&wallet));

        Self { wallet: RwLock::new(wallet), tx_confidence_map: Mutex::new(tx_confidence_map), rpc_auth, poll_period }
    }

    fn sync_tx_confidence_map(&self) {
        let wallet = self.wallet.read().unwrap();
        self.tx_confidence_map.lock().unwrap().sync(tx_confidence_entries(&wallet));
    }

    fn sync_from_rpc_emitter(&self, emitter: &mut Emitter<&Client>) -> Result<()> {
        trace!("Syncing blocks...");
        while let Some(block) = task::block_in_place(|| emitter.next_block())? {
            let height = block.block_height();
            debug!(hash = %block.block_hash(), height, "New block.");
            self.wallet.write().unwrap()
                .apply_block_connected_to(&block.block, height, block.connected_to())?;
        }

        trace!("Syncing mempool...");
        {
            let mempool_emissions = task::block_in_place(|| emitter.mempool())?;
            let mut wallet = self.wallet.write().unwrap();
            wallet.apply_evicted_txs(mempool_emissions.evicted);
            wallet.apply_unconfirmed_txs(mempool_emissions.update);
        }

        trace!("Syncing tx confidence map with wallet.");
        // TODO: Skip needless cache/map updates if the wallet hasn't actually changed:
        self.sync_tx_confidence_map();

        Ok(())
    }
}

impl Default for WalletServiceImpl {
    fn default() -> Self { Self::new() }
}

fn unconfirmed_txs(wallet: &Wallet) -> impl Iterator<Item=Arc<Transaction>> + '_ {
    tx_confidence_entries(wallet)
        .filter_map(|(_, conf)| (conf.num_confirmations == 0).then_some(conf.wallet_tx.tx))
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
            self.rpc_auth.clone(),
        ))?;

        let blockchain_info = task::block_in_place(|| rpc_client.get_blockchain_info())?;
        info!(chain = %blockchain_info.chain, best_block_hash = %blockchain_info.best_block_hash,
            blocks = blockchain_info.blocks, "Connected to Bitcoin Core RPC.");

        let wallet_tip: CheckPoint = self.wallet.read().unwrap().latest_checkpoint();
        let start_height = wallet_tip.height();
        info!(start_hash = %wallet_tip.hash(), start_height, "Fetched latest wallet checkpoint.");

        let mut emitter = Emitter::new(&rpc_client, wallet_tip, start_height,
            unconfirmed_txs(&self.wallet.read().unwrap()));
        self.sync_from_rpc_emitter(&mut emitter)?;
        info!(wallet_balance_total = %self.balance().total(), "Finished initial sync.");

        info!("Polling for further blocks and mempool txs...");
        let mut interval = time::interval(self.poll_period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            self.sync_from_rpc_emitter(&mut emitter)?;
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
        self.tx_confidence_map.lock().unwrap().observe(txid)
            .on_drop(move || debug!(%txid, "Confidence stream has been dropped."))
            .boxed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxConfidence {
    pub wallet_tx: WalletTx,
    pub num_confirmations: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
#[non_exhaustive]
pub enum WalletErrorKind {
    BitcoindRpc(#[from] bdk_bitcoind_rpc::bitcoincore_rpc::Error),
    ApplyHeader(#[from] bdk_wallet::chain::local_chain::ApplyHeaderError),
}
