//! The user-facing wallet service, backed by [`BMPWallet`].
//!
//! Layering mirrors [`crate::wallet`]/[`crate::server`]:
//!
//! * [`BMPWalletServiceImpl`] owns the wallet — once the `OpenOrCreateWallet` RPC has opened or
//!   created it — and forwards every operation to [`BMPWallet`]. It implements
//!   [`BmpWalletService`], the GUI-oriented operations bisq2 needs, which deliberately does not
//!   depend on the bitcoind-oriented [`crate::wallet::WalletService`] trait.
//! * [`BmpWalletImpl`] is the thin gRPC adapter over `BmpWalletService`, serving the
//!   `wallet.Wallet` service defined in `bmp_wallet.proto` — the same contract bisq2's
//!   `bisq.wallet.WalletGrpcClient` speaks.
//!
//! Unlike `WalletServiceImpl`, which drives a `bdk_bitcoind_rpc` emitter, this service syncs by
//! periodically calling [`WalletApi::sync_all`] against a [`ChainDataSource`] (compact block
//! filters by default), which is how `BMPWallet` is designed to see the chain.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// Leading `::` disambiguates the `wallet` *crate* from this crate's own `wallet` module.
use ::wallet::bmp_wallet::{BMPWallet, WalletApi as _};
use ::wallet::chain_data_source::ChainDataSource;
use ::wallet::wallet_info::{TxInfo, TxOutputInfo, UtxoInfo};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi as _};
use bdk_wallet::Balance;
use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Transaction, Txid};
use bdk_wallet::rusqlite::Connection;
use chain::ChainApi;
use futures_util::never::Never;
use futures_util::stream::{BoxStream, StreamExt as _};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{self, JoinHandle};
use tokio::time::{self, Duration, MissedTickBehavior};
use tonic::{Request, Response, Result, Status};
use tracing::{debug, error, info, instrument};

use crate::observable::ObservableHashMap;
pub use crate::pb::bmp_wallet::wallet_server::WalletServer as BmpWalletServer;
use crate::pb::bmp_wallet::{
    self, ChangePasswordRequest, ChangePasswordResponse, GetBalanceRequest, GetBalanceResponse,
    GetNewAddressRequest, GetNewAddressResponse, GetSeedWordsRequest, GetSeedWordsResponse,
    GetUnusedAddressRequest, GetUnusedAddressResponse, GetWalletAddressesRequest,
    GetWalletAddressesResponse, IsWalletEncryptedRequest, IsWalletEncryptedResponse,
    IsWalletReadyRequest, IsWalletReadyResponse, ListTransactionsRequest, ListTransactionsResponse,
    ListUtxosRequest, ListUtxosResponse, OpenOrCreateWalletRequest, OpenOrCreateWalletResponse,
    SendToAddressRequest, SendToAddressResponse, wallet_server,
};
use crate::server::handle_request_async;
use crate::wallet::{Result as WalletResult, TxConfidence, tx_confidence_entries};

/// How often the wallet is re-synced against the chain data source.
const DEFAULT_POLL_PERIOD: Duration = Duration::from_secs(30);

/// How often the sync loop re-checks whether the wallet has been opened yet (the wallet is
/// opened over RPC, so the loop may start before there is anything to sync).
const WALLET_OPEN_POLL_PERIOD: Duration = Duration::from_millis(500);

/// Fee rate used when the client doesn't specify one. 2 sat/vB == 500 sat/kwu.
const DEFAULT_FEE_RATE: FeeRate = FeeRate::from_sat_per_kwu(500);

/// A wallet operation was attempted before `OpenOrCreateWallet` opened the wallet. Reported to
/// gRPC clients as `FAILED_PRECONDITION`.
#[derive(Debug, Error)]
#[error("wallet is not open; call OpenOrCreateWallet first")]
pub struct WalletNotOpen;

/// The caller failed to present the password currently protecting the wallet. Reported to gRPC
/// clients as `PERMISSION_DENIED`.
#[derive(Debug, Error)]
#[error("invalid wallet password")]
pub struct InvalidPassword;

/// The GUI-facing wallet operations.
///
/// Every method maps one-to-one onto an RPC of the `wallet.Wallet` service and, in turn, onto a
/// method of [`BMPWallet`]. Kept as a trait (rather than inherent methods) so the gRPC adapter
/// can hold `Arc<dyn BmpWalletService>` and be exercised against a stub in tests. Deliberately
/// *not* a subtrait of [`crate::wallet::WalletService`]: that trait models the bitcoind-backed
/// trade wallet, which this user-facing wallet no longer depends on.
#[tonic::async_trait]
pub trait BmpWalletService {
    /// Whether the wallet is open and, if a chain data source is configured, has completed at
    /// least one sync.
    fn is_ready(&self) -> bool;

    /// Opens the wallet database, creating a fresh wallet only if none exists yet.
    ///
    /// `password` is the password protecting the database (empty for an unprotected wallet).
    /// Re-opening an already-open wallet succeeds as long as the password matches; a wrong
    /// password fails with [`InvalidPassword`]. Every other wallet operation requires this to
    /// have been called first.
    async fn open_or_create_wallet(&self, password: &str) -> anyhow::Result<()>;

    /// Re-keys the wallet from `old_password` to `new_password`.
    ///
    /// `old_password` must be the password currently in force (empty for an unprotected
    /// wallet); an empty `new_password` removes password protection.
    async fn change_password(&self, old_password: &str, new_password: &str) -> anyhow::Result<()>;

    /// Reveals a fresh receive address.
    ///
    /// Like [`Self::unused_address`], this routes through the gap-capped
    /// [`BMPWallet::next_address`], so a click-happy client cycles through the existing unused
    /// addresses once the gap limit is reached instead of growing it without bound. Either way a
    /// different address is returned on every call.
    async fn new_address(&self) -> anyhow::Result<String>;

    async fn unused_address(&self) -> anyhow::Result<String>;

    async fn wallet_addresses(&self) -> anyhow::Result<Vec<String>>;

    async fn transactions(&self) -> anyhow::Result<Vec<TxInfo>>;

    async fn utxos(&self) -> anyhow::Result<Vec<UtxoInfo>>;

    /// Builds, signs, persists and broadcasts a payment.
    ///
    /// `passphrase` is checked against the wallet password when one is set; it is ignored for an
    /// unencrypted wallet.
    async fn send_to_address(
        &self,
        passphrase: Option<&str>,
        address: &str,
        amount: Amount,
        fee_rate: Option<FeeRate>,
    ) -> anyhow::Result<Txid>;

    async fn is_encrypted(&self) -> anyhow::Result<bool>;

    async fn full_balance(&self) -> anyhow::Result<Balance>;

    async fn seed_words(&self) -> anyhow::Result<Vec<String>>;
}

/// A [`BmpWalletService`] whose every operation is forwarded to [`BMPWallet`].
///
/// The wallet itself starts out absent: it is opened (or created) in the configured directory by
/// [`BmpWalletService::open_or_create_wallet`], driven by the `OpenOrCreateWallet` RPC, so the
/// database password never has to reach the server's command line.
///
/// `S` is the chain backend used for syncing. It is a type parameter rather than a trait object
/// because [`ChainDataSource::sync`] is generic over the persister and so isn't object safe;
/// callers that don't want syncing at all can leave it unset (see [`Self::new`]).
pub struct BMPWalletServiceImpl<S> {
    /// Async mutex, because [`WalletApi::sync_all`] is an `async fn` taking `&mut self` and so
    /// must be awaited while the lock is held. `None` until `OpenOrCreateWallet` has been
    /// called.
    ///
    /// NOTE: to avoid deadlocks, acquire this before `tx_confidence_map`, never the other way
    /// round — the same ordering `WalletServiceImpl` uses.
    wallet: AsyncMutex<Option<BMPWallet<Connection>>>,
    /// Directory holding (or to hold) the wallet database.
    wallet_dir: PathBuf,
    network: Network,
    tx_confidence_map: Mutex<ObservableHashMap<Txid, TxConfidence>>,
    chain_data_source: Option<S>,
    broadcaster: Option<Arc<dyn ChainApi>>,
    ready: AtomicBool,
    poll_period: Duration,
}

/// The open wallet behind `guard`, or [`WalletNotOpen`] if `OpenOrCreateWallet` hasn't
/// succeeded yet.
fn require_open(
    guard: &mut Option<BMPWallet<Connection>>,
) -> anyhow::Result<&mut BMPWallet<Connection>> {
    guard
        .as_mut()
        .ok_or_else(|| anyhow::Error::new(WalletNotOpen))
}

impl<S> BMPWalletServiceImpl<S> {
    /// Creates the service with no wallet open yet; `OpenOrCreateWallet` supplies the password
    /// and opens (or creates) the wallet in `wallet_dir`. Without a chain data source the
    /// wallet never syncs: it still serves addresses, seed words and password changes, but will
    /// not see any funds.
    pub fn new(wallet_dir: impl Into<PathBuf>, network: Network) -> Self {
        Self {
            wallet: AsyncMutex::new(None),
            wallet_dir: wallet_dir.into(),
            network,
            tx_confidence_map: Mutex::new(ObservableHashMap::new()),
            chain_data_source: None,
            broadcaster: None,
            ready: AtomicBool::new(false),
            poll_period: DEFAULT_POLL_PERIOD,
        }
    }

    #[must_use]
    pub fn with_chain_data_source(self, chain_data_source: S) -> Self {
        Self {
            chain_data_source: Some(chain_data_source),
            ..self
        }
    }

    /// Supplies the backend used to publish transactions built by
    /// [`BmpWalletService::send_to_address`]. Without one, `SendToAddress` fails rather than
    /// silently returning an unbroadcast txid.
    #[must_use]
    pub fn with_broadcaster(self, broadcaster: Arc<dyn ChainApi>) -> Self {
        Self {
            broadcaster: Some(broadcaster),
            ..self
        }
    }

    #[must_use]
    pub fn with_poll_period(self, poll_period: Duration) -> Self {
        Self {
            poll_period,
            ..self
        }
    }

    pub fn get_tx_confidence_stream(&self, txid: Txid) -> BoxStream<'static, Option<TxConfidence>> {
        self.tx_confidence_map.lock().unwrap().observe(txid).boxed()
    }
}

impl<S: ChainDataSource + Sync> BMPWalletServiceImpl<S> {
    /// Syncs the wallet once, returning whether there was an open wallet to sync at all.
    async fn sync_once(&self, chain_data_source: &S) -> anyhow::Result<bool> {
        let mut guard = self.wallet.lock().await;
        let Some(wallet) = guard.as_mut() else {
            return Ok(false);
        };
        wallet.sync_all(chain_data_source).await?;

        // TODO: Skip needless map updates if the wallet hasn't actually changed.
        self.tx_confidence_map
            .lock()
            .unwrap()
            .sync(tx_confidence_entries(wallet));
        Ok(true)
    }
}

impl<S: ChainDataSource + Send + Sync + 'static> BMPWalletServiceImpl<S> {
    /// Periodically re-syncs the wallet through its [`ChainDataSource`], mirroring what
    /// [`crate::wallet::WalletService::connect`] does for the bitcoind-backed wallet without
    /// this type having to implement that trait.
    ///
    /// The `rpc` argument is used only to log which node we're pointed at — `BMPWallet` reaches
    /// the chain over compact block filters, not Bitcoin Core RPC, so it plays no part in
    /// syncing here.
    ///
    /// The wallet itself is opened by the `OpenOrCreateWallet` RPC, so syncing (and with it the
    /// ready flag) waits until that has happened.
    ///
    /// # Errors
    /// Will return `Err` if the initial or any subsequent sync fails.
    pub async fn connect(&self, rpc: Arc<Client>) -> WalletResult<Never> {
        match task::block_in_place(|| rpc.get_blockchain_info()) {
            Ok(info) => info!(chain = %info.chain, blocks = info.blocks,
                "Bitcoin Core reachable (informational only; syncing uses the chain data source)."),
            Err(e) => debug!("Bitcoin Core RPC not reachable ({e}); continuing regardless."),
        }

        let Some(chain_data_source) = self.chain_data_source.as_ref() else {
            info!("No chain data source configured; wallet will not sync.");
            // `open_or_create_wallet` flips the ready flag as soon as the wallet is open, since
            // everything that doesn't depend on chain state is available immediately.
            return Ok(std::future::pending().await);
        };

        info!("Waiting for the wallet to be opened, to perform the initial sync...");
        while !self.sync_once(chain_data_source).await? {
            time::sleep(WALLET_OPEN_POLL_PERIOD).await;
        }
        self.ready.store(true, Ordering::Release);
        let total = self
            .wallet
            .lock()
            .await
            .as_ref()
            .map(|wallet| wallet.full_balance().total())
            .unwrap_or_default();
        info!(wallet_balance_total = %total, "Finished initial sync.");

        let mut interval = time::interval(self.poll_period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            self.sync_once(chain_data_source).await?;
        }
    }

    /// Spawns [`Self::connect`] onto the Tokio runtime, mirroring
    /// [`crate::wallet::WalletService::spawn_connection`].
    ///
    /// # Panics
    /// Will panic if called outside the context of a Tokio runtime.
    pub fn spawn_connection(
        self: Arc<Self>,
        client: Arc<Client>,
    ) -> JoinHandle<WalletResult<Never>> {
        task::spawn(async move {
            self.connect(client)
                .await
                .inspect_err(|e| error!("Wallet connection error: {e}"))
        })
    }
}

#[tonic::async_trait]
impl<S: ChainDataSource + Send + Sync + 'static> BmpWalletService for BMPWalletServiceImpl<S> {
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    async fn open_or_create_wallet(&self, password: &str) -> anyhow::Result<()> {
        let mut guard = self.wallet.lock().await;

        if let Some(wallet) = guard.as_ref() {
            // Idempotent for a client that reconnects: re-opening an open wallet succeeds, but
            // only for a caller who can present the password currently in force.
            if wallet.check_password(password)? {
                return Ok(());
            }
            return Err(InvalidPassword.into());
        }

        // Creating is chosen on the *absence* of the database file, never on a failed load. A
        // load failure most likely means a wrong password was given, and creating a wallet
        // rewrites the Argon2 salt the existing database's key was derived from — which would
        // render that wallet, and any funds in it, permanently unrecoverable.
        fs::create_dir_all(&self.wallet_dir)?;
        let db_path = self.wallet_dir.join(BMPWallet::<Connection>::DB_NAME);
        let wallet = if db_path.exists() {
            let wallet =
                BMPWallet::load_wallet(&self.wallet_dir, self.network, password).map_err(|e| {
                    e.context(InvalidPassword).context(format!(
                        "failed to open the existing wallet at {} (wrong password?)",
                        db_path.display()
                    ))
                })?;
            info!(dir = %self.wallet_dir.display(), "Loaded the existing BMP wallet.");
            wallet
        } else {
            info!(dir = %self.wallet_dir.display(), "No BMP wallet found; creating a new one.");
            BMPWallet::new(&self.wallet_dir, password, self.network)?
        };

        self.tx_confidence_map
            .lock()
            .unwrap()
            .sync(tx_confidence_entries(&wallet));
        *guard = Some(wallet);

        // With no chain data source there is nothing to sync, so the wallet is ready as soon as
        // it is open; otherwise the sync loop flips the flag after the first successful sync.
        if self.chain_data_source.is_none() {
            self.ready.store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn change_password(&self, old_password: &str, new_password: &str) -> anyhow::Result<()> {
        let mut guard = self.wallet.lock().await;
        let wallet = require_open(&mut guard)?;
        if !wallet.check_password(old_password)? {
            return Err(InvalidPassword.into());
        }
        wallet.change_password(old_password, new_password)
    }

    async fn new_address(&self) -> anyhow::Result<String> {
        let mut guard = self.wallet.lock().await;
        Ok(require_open(&mut guard)?
            .get_new_address()?
            .address
            .to_string())
    }

    async fn unused_address(&self) -> anyhow::Result<String> {
        // Currently behaves like `new_address`: both hand out the next (gap-capped) unused
        // address, matching what bisq2 expects from either RPC.
        self.new_address().await
    }

    async fn wallet_addresses(&self) -> anyhow::Result<Vec<String>> {
        let mut guard = self.wallet.lock().await;
        Ok(require_open(&mut guard)?.list_wallet_addresses())
    }

    async fn transactions(&self) -> anyhow::Result<Vec<TxInfo>> {
        let mut guard = self.wallet.lock().await;
        Ok(require_open(&mut guard)?.list_transactions())
    }

    async fn utxos(&self) -> anyhow::Result<Vec<UtxoInfo>> {
        let mut guard = self.wallet.lock().await;
        Ok(require_open(&mut guard)?.list_utxos())
    }

    async fn send_to_address(
        &self,
        passphrase: Option<&str>,
        address: &str,
        amount: Amount,
        fee_rate: Option<FeeRate>,
    ) -> anyhow::Result<Txid> {
        let broadcaster = self.broadcaster.as_ref().ok_or_else(|| {
            anyhow::anyhow!("no chain backend configured for broadcasting transactions")
        })?;

        let mut guard = self.wallet.lock().await;
        let wallet = require_open(&mut guard)?;

        if wallet.is_encrypted() && !wallet.check_password(passphrase.unwrap_or_default())? {
            return Err(InvalidPassword.into());
        }

        let address = address
            .parse::<Address<NetworkUnchecked>>()?
            .require_network(wallet.network())?;

        let tx: Transaction =
            wallet.send_to_address(&address, amount, fee_rate.unwrap_or(DEFAULT_FEE_RATE))?;

        // Broadcast while still holding the lock, so a concurrent send can't build a conflicting
        // transaction from the same UTXO set before this one is out. `transaction_broadcast` is
        // a blocking network call, so it must not run directly on an async worker thread.
        let txid = task::block_in_place(|| broadcaster.transaction_broadcast(&tx))?;
        info!(%txid, "Broadcast wallet payment.");
        Ok(txid)
    }

    async fn is_encrypted(&self) -> anyhow::Result<bool> {
        let mut guard = self.wallet.lock().await;
        Ok(require_open(&mut guard)?.is_encrypted())
    }

    async fn full_balance(&self) -> anyhow::Result<Balance> {
        let mut guard = self.wallet.lock().await;
        Ok(require_open(&mut guard)?.full_balance())
    }

    async fn seed_words(&self) -> anyhow::Result<Vec<String>> {
        let mut guard = self.wallet.lock().await;
        let phrase = require_open(&mut guard)?.get_seed_phrase()?;
        Ok(phrase.split_whitespace().map(ToOwned::to_owned).collect())
    }
}

/// Publishes transactions through a Bitcoin Core node.
pub struct BitcoinCoreChainApi(Arc<Client>);

impl BitcoinCoreChainApi {
    pub const fn new(client: Arc<Client>) -> Self {
        Self(client)
    }
}

impl ChainApi for BitcoinCoreChainApi {
    fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        Ok(self.0.send_raw_transaction(tx)?)
    }
}

/// gRPC adapter serving `wallet.Wallet`, the contract bisq2's `WalletGrpcClient` speaks.
pub struct BmpWalletImpl {
    pub wallet_service: Arc<dyn BmpWalletService + Send + Sync>,
}

#[tonic::async_trait]
impl wallet_server::Wallet for BmpWalletImpl {
    #[instrument(skip_all)]
    async fn open_or_create_wallet(
        &self,
        request: Request<OpenOrCreateWalletRequest>,
    ) -> Result<Response<OpenOrCreateWalletResponse>> {
        handle_request_async(request, |request| async move {
            self.wallet_service
                .open_or_create_wallet(&request.password)
                .await
                .map_err(|e| status_from(&e))?;

            Ok(OpenOrCreateWalletResponse { success: true })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn is_wallet_ready(
        &self,
        request: Request<IsWalletReadyRequest>,
    ) -> Result<Response<IsWalletReadyResponse>> {
        handle_request_async(request, |_request| async {
            Ok(IsWalletReadyResponse {
                ready: self.wallet_service.is_ready(),
            })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn get_new_address(
        &self,
        request: Request<GetNewAddressRequest>,
    ) -> Result<Response<GetNewAddressResponse>> {
        handle_request_async(request, |_request| async {
            let address = self
                .wallet_service
                .new_address()
                .await
                .map_err(|e| status_from(&e))?;

            Ok(GetNewAddressResponse { address })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn get_unused_address(
        &self,
        request: Request<GetUnusedAddressRequest>,
    ) -> Result<Response<GetUnusedAddressResponse>> {
        handle_request_async(request, |_request| async {
            let address = self
                .wallet_service
                .unused_address()
                .await
                .map_err(|e| status_from(&e))?;

            Ok(GetUnusedAddressResponse { address })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn get_wallet_addresses(
        &self,
        request: Request<GetWalletAddressesRequest>,
    ) -> Result<Response<GetWalletAddressesResponse>> {
        handle_request_async(request, |_request| async {
            let addresses = self
                .wallet_service
                .wallet_addresses()
                .await
                .map_err(|e| status_from(&e))?;

            Ok(GetWalletAddressesResponse { addresses })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn list_transactions(
        &self,
        request: Request<ListTransactionsRequest>,
    ) -> Result<Response<ListTransactionsResponse>> {
        handle_request_async(request, |_request| async {
            let transactions = self
                .wallet_service
                .transactions()
                .await
                .map_err(|e| status_from(&e))?
                .into_iter()
                .map(Into::into)
                .collect();

            Ok(ListTransactionsResponse { transactions })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn list_utxos(
        &self,
        request: Request<ListUtxosRequest>,
    ) -> Result<Response<ListUtxosResponse>> {
        handle_request_async(request, |_request| async {
            let utxos = self
                .wallet_service
                .utxos()
                .await
                .map_err(|e| status_from(&e))?
                .into_iter()
                .map(Into::into)
                .collect();

            Ok(ListUtxosResponse { utxos })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn send_to_address(
        &self,
        request: Request<SendToAddressRequest>,
    ) -> Result<Response<SendToAddressResponse>> {
        handle_request_async(request, |request| async move {
            let tx_id = self
                .wallet_service
                .send_to_address(
                    request.passphrase.as_deref(),
                    &request.address,
                    Amount::from_sat(request.amount),
                    request.fee_rate_per_kwu.map(FeeRate::from_sat_per_kwu),
                )
                .await
                .map_err(|e| status_from(&e))?;

            Ok(SendToAddressResponse {
                tx_id: tx_id.to_string(),
            })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn is_wallet_encrypted(
        &self,
        request: Request<IsWalletEncryptedRequest>,
    ) -> Result<Response<IsWalletEncryptedResponse>> {
        handle_request_async(request, |_request| async {
            let encrypted = self
                .wallet_service
                .is_encrypted()
                .await
                .map_err(|e| status_from(&e))?;

            Ok(IsWalletEncryptedResponse { encrypted })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>> {
        handle_request_async(request, |_request| async {
            let balance = self
                .wallet_service
                .full_balance()
                .await
                .map_err(|e| status_from(&e))?;

            Ok(balance.into())
        })
        .await
    }

    #[instrument(skip_all)]
    async fn get_seed_words(
        &self,
        request: Request<GetSeedWordsRequest>,
    ) -> Result<Response<GetSeedWordsResponse>> {
        handle_request_async(request, |_request| async {
            let seed_words = self
                .wallet_service
                .seed_words()
                .await
                .map_err(|e| status_from(&e))?;

            Ok(GetSeedWordsResponse { seed_words })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>> {
        handle_request_async(request, |request| async move {
            self.wallet_service
                .change_password(&request.old_password, &request.new_password)
                .await
                .map_err(|e| status_from(&e))?;

            Ok(ChangePasswordResponse { success: true })
        })
        .await
    }
}

/// Maps a wallet-layer error onto the gRPC status codes a client can distinguish: using the
/// wallet before opening it is a state error the caller can fix (`FAILED_PRECONDITION`), a
/// wrong password is the caller's mistake (`PERMISSION_DENIED`), and everything else is a
/// server fault (`INTERNAL`).
fn status_from(error: &anyhow::Error) -> Status {
    if error.downcast_ref::<WalletNotOpen>().is_some() {
        Status::failed_precondition(error.to_string())
    } else if error.downcast_ref::<InvalidPassword>().is_some() {
        Status::permission_denied(error.to_string())
    } else {
        error!("Wallet operation failed: {error:#}");
        Status::internal(error.to_string())
    }
}

// Conversions from the `wallet` crate's transport-agnostic views to the generated protobuf types.

impl From<Balance> for GetBalanceResponse {
    fn from(value: Balance) -> Self {
        Self {
            // bisq2 reads only `balance`; keep it the trusted-spendable total it expects.
            balance: value.trusted_spendable().to_sat(),
            confirmed: value.confirmed.to_sat(),
            trusted_pending: value.trusted_pending.to_sat(),
            untrusted_pending: value.untrusted_pending.to_sat(),
            immature: value.immature.to_sat(),
        }
    }
}

impl From<UtxoInfo> for bmp_wallet::Utxo {
    fn from(value: UtxoInfo) -> Self {
        Self {
            tx_id: value.tx_id.to_string(),
            vout: value.vout,
            amount: value.amount.to_sat(),
            address: value.address.unwrap_or_default(),
            num_confirmations: value.num_confirmations,
        }
    }
}

impl From<TxOutputInfo> for bmp_wallet::TransactionOutput {
    fn from(value: TxOutputInfo) -> Self {
        Self {
            value: value.value.to_sat(),
            address: value.address.unwrap_or_default(),
            script_pub_key: value.script_pubkey.into_bytes(),
        }
    }
}

impl From<TxInfo> for bmp_wallet::Transaction {
    fn from(value: TxInfo) -> Self {
        Self {
            tx_id: value.tx_id.to_string(),
            inputs: value
                .inputs
                .into_iter()
                .map(|input| bmp_wallet::TransactionInput {
                    prev_out_tx_id: input.prev_out_tx_id.to_string(),
                    // Proto uses int32/int64 here (bisq2's choice, to match Java's signed
                    // types), so widen rather than truncate.
                    prev_out_index: i32::try_from(input.prev_out_index).unwrap_or(-1),
                    sequence_number: i64::from(input.sequence),
                    script_sig: input.script_sig.into_bytes(),
                    witness: input.witness,
                })
                .collect(),
            outputs: value.outputs.into_iter().map(Into::into).collect(),
            lock_time: u64::from(value.lock_time),
            block_height: value.block_height.unwrap_or_default(),
            // Seconds since the epoch, which is how bisq2's `Transaction.fromProto` decodes it.
            date: value.timestamp.unwrap_or_default(),
            num_confirmations: value.num_confirmations,
            amount: value.amount.to_sat(),
            incoming: value.incoming,
        }
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::PersistedWallet;
    use bdk_wallet::bitcoin::Network;
    use tempfile::tempdir;

    use super::*;

    /// A `ChainDataSource` that does nothing, so tests can exercise the service without a chain.
    struct NoopChainDataSource;

    impl ChainDataSource for NoopChainDataSource {
        const RECOVERY_HEIGHT: usize = 0;
        const BATCH_SIZE: usize = 1;
        const STOP_GAP: usize = 1;

        async fn sync(
            &self,
            _persister: Vec<&mut PersistedWallet<impl ::wallet::bmp_wallet::BMPWalletPersister>>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn service() -> (tempfile::TempDir, BMPWalletServiceImpl<NoopChainDataSource>) {
        let dir = tempdir().unwrap();
        let service = BMPWalletServiceImpl::new(dir.path(), Network::Regtest);
        (dir, service)
    }

    async fn open_service() -> (tempfile::TempDir, BMPWalletServiceImpl<NoopChainDataSource>) {
        let (dir, service) = service();
        service.open_or_create_wallet("").await.unwrap();
        (dir, service)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn operations_before_open_are_refused() {
        let (_dir, service) = service();

        assert!(!service.is_ready(), "no wallet open, so not ready");

        let err = service.new_address().await.unwrap_err();
        assert!(
            err.downcast_ref::<WalletNotOpen>().is_some(),
            "expected WalletNotOpen, got: {err}"
        );
        assert!(service.full_balance().await.is_err());
        assert!(service.is_encrypted().await.is_err());
        assert!(service.seed_words().await.is_err());
        assert!(service.transactions().await.is_err());
        assert!(service.utxos().await.is_err());
        assert!(service.wallet_addresses().await.is_err());
        assert!(service.change_password("", "pw").await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forwards_queries_to_the_wallet() {
        let (_dir, service) = open_service().await;

        assert!(
            service.is_ready(),
            "no chain data source, so the wallet is ready as soon as it is open"
        );
        assert!(
            !service.is_encrypted().await.unwrap(),
            "opened with an empty password"
        );
        assert_eq!(service.full_balance().await.unwrap().total().to_sat(), 0);
        assert_eq!(service.seed_words().await.unwrap().len(), 24);
        assert!(service.transactions().await.unwrap().is_empty());
        assert!(service.utxos().await.unwrap().is_empty());

        // Revealing an address must show up in the address list.
        assert!(service.wallet_addresses().await.unwrap().is_empty());
        let address = service.unused_address().await.unwrap();
        assert!(service.wallet_addresses().await.unwrap().contains(&address));

        // `new_address` reveals a fresh address, distinct from the one just handed out.
        let new_address = service.new_address().await.unwrap();
        assert_ne!(new_address, address);
        assert!(
            service
                .wallet_addresses()
                .await
                .unwrap()
                .contains(&new_address)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_is_idempotent_but_checks_the_password() {
        let (dir, service) = service();

        service.open_or_create_wallet("s3cret").await.unwrap();
        let seed = service.seed_words().await.unwrap();

        // Re-opening with the right password is a no-op; a wrong one is rejected.
        service.open_or_create_wallet("s3cret").await.unwrap();
        let err = service.open_or_create_wallet("wrong").await.unwrap_err();
        assert!(
            err.downcast_ref::<InvalidPassword>().is_some(),
            "expected InvalidPassword, got: {err}"
        );

        // A fresh service on the same directory must load the persisted wallet, not create a
        // new one — and only for the holder of the password.
        let reloaded =
            BMPWalletServiceImpl::<NoopChainDataSource>::new(dir.path(), Network::Regtest);
        let err = reloaded.open_or_create_wallet("wrong").await.unwrap_err();
        assert!(
            err.downcast_ref::<InvalidPassword>().is_some(),
            "a wrong password must not open (or overwrite!) the existing wallet, got: {err}"
        );
        reloaded.open_or_create_wallet("s3cret").await.unwrap();
        assert_eq!(reloaded.seed_words().await.unwrap(), seed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn change_password_round_trips() {
        let (_dir, service) = open_service().await;

        service.change_password("", "hunter2").await.unwrap();
        assert!(service.is_encrypted().await.unwrap());
        // The seed must still be readable through the rotated key.
        assert_eq!(service.seed_words().await.unwrap().len(), 24);

        let err = service.change_password("wrong", "other").await.unwrap_err();
        assert!(
            err.downcast_ref::<InvalidPassword>().is_some(),
            "wrong password must be rejected, got: {err}"
        );
        assert!(
            service.is_encrypted().await.unwrap(),
            "a failed change must not clear the flag"
        );

        service.change_password("hunter2", "").await.unwrap();
        assert!(!service.is_encrypted().await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_to_address_without_a_broadcaster_is_an_error() {
        let (_dir, service) = open_service().await;

        let err = service
            .send_to_address(
                None,
                "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                Amount::from_sat(1_000),
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no chain backend"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn syncing_keeps_the_confidence_map_in_step() {
        let (_dir, service) = service();
        let service = service.with_chain_data_source(NoopChainDataSource);

        assert!(
            !service.sync_once(&NoopChainDataSource).await.unwrap(),
            "nothing to sync before the wallet is opened"
        );

        service.open_or_create_wallet("").await.unwrap();
        assert!(
            !service.is_ready(),
            "with a chain data source, only a completed sync makes the wallet ready"
        );

        // Nothing on chain, so the map stays empty, but the call must not deadlock — it takes
        // the wallet lock and then the confidence-map lock in that order.
        assert!(service.sync_once(&NoopChainDataSource).await.unwrap());
        assert!(service.utxos().await.unwrap().is_empty());
    }

    // --- protobuf mapping ---------------------------------------------------------------------
    //
    // These are the seams where a units or signedness mistake would reach bisq2 silently, so
    // they get direct coverage rather than relying on the wallet-level tests.

    use std::str::FromStr as _;

    use ::wallet::wallet_info::{TxInputInfo, TxOutputInfo};
    use bdk_wallet::bitcoin::ScriptBuf;

    fn a_txid() -> Txid {
        Txid::from_str("69111c8de670d7a12b8c4db85c67485889b30335cdd3fd7f18924104e88e9fc3").unwrap()
    }

    #[test]
    fn balance_maps_to_proto_without_losing_the_breakdown() {
        let balance = Balance {
            immature: Amount::from_sat(1),
            trusted_pending: Amount::from_sat(20),
            untrusted_pending: Amount::from_sat(300),
            confirmed: Amount::from_sat(4_000),
        };

        let proto: GetBalanceResponse = balance.clone().into();

        // bisq2 reads only `balance`, and expects the spendable total.
        assert_eq!(proto.balance, balance.trusted_spendable().to_sat());
        assert_eq!(
            proto.balance, 4_020,
            "spendable = confirmed + trusted pending"
        );
        assert_eq!(proto.confirmed, 4_000);
        assert_eq!(proto.trusted_pending, 20);
        assert_eq!(proto.untrusted_pending, 300);
        assert_eq!(proto.immature, 1);
        // Untrusted/immature funds must never be presented as spendable.
        assert!(proto.balance < balance.total().to_sat());
    }

    #[test]
    fn utxo_maps_to_proto_and_tolerates_an_undecodable_script() {
        let utxo = UtxoInfo {
            tx_id: a_txid(),
            vout: 2,
            amount: Amount::from_sat(50_000),
            address: Some("bcrt1qtest".to_owned()),
            num_confirmations: 6,
            imported: true,
        };
        let proto: bmp_wallet::Utxo = utxo.into();

        assert_eq!(proto.tx_id, a_txid().to_string());
        assert_eq!(proto.vout, 2);
        assert_eq!(proto.amount, 50_000);
        assert_eq!(proto.address, "bcrt1qtest");
        assert_eq!(proto.num_confirmations, 6);

        // proto3 has no null: a non-standard script must degrade to an empty string, not panic.
        let nameless = UtxoInfo {
            address: None,
            ..UtxoInfo {
                tx_id: a_txid(),
                vout: 0,
                amount: Amount::ZERO,
                address: None,
                num_confirmations: 0,
                imported: false,
            }
        };
        assert_eq!(bmp_wallet::Utxo::from(nameless).address, "");
    }

    #[test]
    fn transaction_maps_to_proto_with_a_seconds_timestamp() {
        let tx = TxInfo {
            tx_id: a_txid(),
            inputs: vec![TxInputInfo {
                prev_out_tx_id: a_txid(),
                prev_out_index: 1,
                // Max sequence: must survive the widening to a signed proto field.
                sequence: u32::MAX,
                script_sig: ScriptBuf::from_bytes(vec![0x51]),
                witness: "0201ab".to_owned(),
            }],
            outputs: vec![TxOutputInfo {
                value: Amount::from_sat(100_000),
                address: Some("bcrt1qtest".to_owned()),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            lock_time: 800_000,
            block_height: Some(800_001),
            timestamp: Some(1_700_000_000),
            num_confirmations: 3,
            amount: Amount::from_sat(100_000),
            incoming: true,
        };

        let proto: bmp_wallet::Transaction = tx.into();

        assert_eq!(proto.tx_id, a_txid().to_string());
        assert_eq!(proto.block_height, 800_001);
        assert_eq!(proto.num_confirmations, 3);
        assert_eq!(proto.amount, 100_000);
        assert!(proto.incoming);
        assert_eq!(proto.lock_time, 800_000);

        // The field bisq2 feeds to Instant.ofEpochSecond. Milliseconds here would put the tx
        // ~50,000 years in the future in the UI.
        assert_eq!(proto.date, 1_700_000_000);
        assert!(
            proto.date < 4_000_000_000,
            "date must be seconds, not millis"
        );

        assert_eq!(proto.inputs.len(), 1);
        assert_eq!(proto.inputs[0].prev_out_index, 1);
        assert_eq!(
            proto.inputs[0].sequence_number,
            i64::from(u32::MAX),
            "sequence must widen, not wrap negative"
        );
        assert_eq!(proto.inputs[0].witness, "0201ab");
        assert_eq!(proto.inputs[0].script_sig, vec![0x51]);

        assert_eq!(proto.outputs.len(), 1);
        assert_eq!(proto.outputs[0].value, 100_000);
        assert_eq!(proto.outputs[0].address, "bcrt1qtest");
        assert_eq!(proto.outputs[0].script_pub_key, vec![0x76, 0xa9]);
    }

    #[test]
    fn an_unconfirmed_transaction_maps_to_zeroed_confirmation_fields() {
        let tx = TxInfo {
            tx_id: a_txid(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            block_height: None,
            timestamp: None,
            num_confirmations: 0,
            amount: Amount::from_sat(42),
            incoming: false,
        };

        let proto: bmp_wallet::Transaction = tx.into();

        // proto3 can't express "absent" for scalars; bisq2 renders 0 as "pending".
        assert_eq!(proto.block_height, 0);
        assert_eq!(proto.date, 0);
        assert_eq!(proto.num_confirmations, 0);
        assert!(!proto.incoming);
    }
}
