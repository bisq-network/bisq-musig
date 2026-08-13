//! The user-facing wallet service, backed by [`BMPWallet`].
//!
//! Layering mirrors [`crate::wallet`]/[`crate::server`]:
//!
//! * [`BMPWalletServiceImpl`] owns the wallet and forwards every operation to [`BMPWallet`]. It
//!   implements the shared [`WalletService`] trait (so it can stand in wherever the bitcoind-
//!   backed [`crate::wallet::WalletServiceImpl`] does) plus [`BmpWalletService`], which covers the
//!   richer, GUI-oriented operations bisq2 needs.
//! * [`BmpWalletImpl`] is the thin gRPC adapter over `BmpWalletService`, serving the
//!   `wallet.Wallet` service defined in `bmp_wallet.proto` — the same contract bisq2's
//!   `bisq.wallet.WalletGrpcClient` speaks.
//!
//! Unlike `WalletServiceImpl`, which drives a `bdk_bitcoind_rpc` emitter, this service syncs by
//! periodically calling [`WalletApi::sync_all`] against a [`ChainDataSource`] (compact block
//! filters by default), which is how `BMPWallet` is designed to see the chain.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// Leading `::` disambiguates the `wallet` *crate* from this crate's own `wallet` module.
use ::wallet::bmp_wallet::{BMPWallet, WalletApi as _};
use ::wallet::chain_data_source::ChainDataSource;
use ::wallet::wallet_info::{TxInfo, TxOutputInfo, UtxoInfo};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Client, RpcApi as _};
use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Transaction, Txid};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{AddressInfo, Balance, KeychainKind, LocalOutput};
use chain::ChainApi;
use futures_util::never::Never;
use futures_util::stream::{BoxStream, StreamExt as _};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tokio::task;
use tokio::time::{self, Duration, MissedTickBehavior};
use tonic::{Request, Response, Result, Status};
use tracing::{debug, error, info, instrument, warn};

use crate::observable::ObservableHashMap;
pub use crate::pb::bmp_wallet::wallet_server::WalletServer as BmpWalletServer;
use crate::pb::bmp_wallet::{
    self, DecryptWalletRequest, DecryptWalletResponse, EncryptWalletRequest, EncryptWalletResponse,
    GetBalanceRequest, GetBalanceResponse, GetSeedWordsRequest, GetSeedWordsResponse,
    GetUnusedAddressRequest, GetUnusedAddressResponse, GetWalletAddressesRequest,
    GetWalletAddressesResponse, IsWalletEncryptedRequest, IsWalletEncryptedResponse,
    IsWalletReadyRequest, IsWalletReadyResponse, ListTransactionsRequest, ListTransactionsResponse,
    ListUtxosRequest, ListUtxosResponse, SendToAddressRequest, SendToAddressResponse,
    wallet_server,
};
use crate::server::handle_request_async;
use crate::wallet::{Result as WalletResult, TxConfidence, WalletService, tx_confidence_entries};

/// How often the wallet is re-synced against the chain data source.
const DEFAULT_POLL_PERIOD: Duration = Duration::from_secs(30);

/// Fee rate used when the client doesn't specify one. 2 sat/vB == 500 sat/kwu.
const DEFAULT_FEE_RATE: FeeRate = FeeRate::from_sat_per_kwu(500);

/// The GUI-facing wallet operations, on top of the shared [`WalletService`] contract.
///
/// Every method maps one-to-one onto an RPC of the `wallet.Wallet` service and, in turn, onto a
/// method of [`BMPWallet`]. Kept as a trait (rather than inherent methods) so the gRPC adapter
/// can hold `Arc<dyn BmpWalletService>` and be exercised against a stub in tests.
#[tonic::async_trait]
pub trait BmpWalletService: WalletService {
    /// Whether the wallet is loaded and, if a chain data source is configured, has completed at
    /// least one sync.
    fn is_ready(&self) -> bool;

    async fn unused_address(&self) -> anyhow::Result<String>;

    async fn wallet_addresses(&self) -> Vec<String>;

    async fn transactions(&self) -> Vec<TxInfo>;

    async fn utxos(&self) -> Vec<UtxoInfo>;

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

    async fn is_encrypted(&self) -> bool;

    async fn full_balance(&self) -> Balance;

    async fn seed_words(&self) -> anyhow::Result<Vec<String>>;

    async fn encrypt_wallet(&self, password: &str) -> anyhow::Result<()>;

    async fn decrypt_wallet(&self, password: &str) -> anyhow::Result<()>;
}

/// A [`WalletService`]/[`BmpWalletService`] whose every operation is forwarded to [`BMPWallet`].
///
/// `S` is the chain backend used for syncing. It is a type parameter rather than a trait object
/// because [`ChainDataSource::sync`] is generic over the persister and so isn't object safe;
/// callers that don't want syncing at all can leave it unset (see [`Self::new`]).
pub struct BMPWalletServiceImpl<S> {
    /// Async mutex, because [`WalletApi::sync_all`] is an `async fn` taking `&mut self` and so
    /// must be awaited while the lock is held.
    ///
    /// NOTE: to avoid deadlocks, acquire this before `tx_confidence_map`, never the other way
    /// round — the same ordering `WalletServiceImpl` uses.
    wallet: AsyncMutex<BMPWallet<Connection>>,
    tx_confidence_map: Mutex<ObservableHashMap<Txid, TxConfidence>>,
    chain_data_source: Option<S>,
    broadcaster: Option<Arc<dyn ChainApi>>,
    ready: AtomicBool,
    poll_period: Duration,
}

impl<S> BMPWalletServiceImpl<S> {
    /// Wraps an already-opened wallet. Without a chain data source the wallet never syncs: it
    /// still serves addresses, seed words and encryption, but will not see any funds.
    pub fn new(wallet: BMPWallet<Connection>) -> Self {
        let mut tx_confidence_map = ObservableHashMap::new();
        tx_confidence_map.sync(tx_confidence_entries(&wallet));

        Self {
            wallet: AsyncMutex::new(wallet),
            tx_confidence_map: Mutex::new(tx_confidence_map),
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

    /// Supplies the backend used to publish transactions built by [`Self::send_to_address`].
    /// Without one, `SendToAddress` fails rather than silently returning an unbroadcast txid.
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

    /// Locks the wallet from a synchronous context.
    ///
    /// # Panics
    /// Will panic if called outside a multi-threaded Tokio runtime, since it parks a worker
    /// thread while waiting on the async mutex.
    fn blocking_wallet(&self) -> AsyncMutexGuard<'_, BMPWallet<Connection>> {
        task::block_in_place(|| self.wallet.blocking_lock())
    }
}

impl<S: ChainDataSource + Sync> BMPWalletServiceImpl<S> {
    async fn sync_once(&self, chain_data_source: &S) -> anyhow::Result<()> {
        let mut wallet = self.wallet.lock().await;
        wallet.sync_all(chain_data_source).await?;

        // TODO: Skip needless map updates if the wallet hasn't actually changed.
        self.tx_confidence_map
            .lock()
            .unwrap()
            .sync(tx_confidence_entries(&wallet));
        Ok(())
    }
}

#[tonic::async_trait]
impl<S: ChainDataSource + Send + Sync + 'static> WalletService for BMPWalletServiceImpl<S> {
    /// Periodically re-syncs the wallet through its [`ChainDataSource`].
    ///
    /// The `rpc` argument is part of the shared [`WalletService`] contract and is used only to
    /// log which node we're pointed at — `BMPWallet` reaches the chain over compact block
    /// filters, not Bitcoin Core RPC, so it plays no part in syncing here.
    async fn connect(&self, rpc: Arc<Client>) -> WalletResult<Never> {
        match task::block_in_place(|| rpc.get_blockchain_info()) {
            Ok(info) => info!(chain = %info.chain, blocks = info.blocks,
                "Bitcoin Core reachable (informational only; syncing uses the chain data source)."),
            Err(e) => debug!("Bitcoin Core RPC not reachable ({e}); continuing regardless."),
        }

        let Some(chain_data_source) = self.chain_data_source.as_ref() else {
            info!("No chain data source configured; wallet will not sync.");
            // Everything that doesn't depend on chain state is available immediately.
            self.ready.store(true, Ordering::Release);
            return Ok(std::future::pending().await);
        };

        info!("Performing initial wallet sync...");
        self.sync_once(chain_data_source).await?;
        self.ready.store(true, Ordering::Release);
        info!(wallet_balance_total = %self.balance().total(), "Finished initial sync.");

        let mut interval = time::interval(self.poll_period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            self.sync_once(chain_data_source).await?;
        }
    }

    fn balance(&self) -> Balance {
        self.blocking_wallet().full_balance()
    }

    fn reveal_next_address(&self) -> AddressInfo {
        let mut wallet = self.blocking_wallet();
        wallet.get_new_address().unwrap_or_else(|e| {
            // The trait can't report failure here. `get_new_address` only fails when persisting
            // the revealed index does, so fall back to revealing without persisting rather than
            // taking down the caller — at the cost of possibly re-issuing it after a restart.
            warn!("Failed to persist newly revealed address ({e}); revealing without persisting.");
            wallet.reveal_next_address(KeychainKind::External)
        })
    }

    /// Only the HD wallet's own outputs. Coins held by imported keys live in the tx graph as
    /// floating txouts and have no [`LocalOutput`]; use [`BmpWalletService::utxos`] for those.
    fn list_unspent(&self) -> Vec<LocalOutput> {
        self.blocking_wallet().list_unspent().collect()
    }

    fn get_tx_confidence_stream(&self, txid: Txid) -> BoxStream<'static, Option<TxConfidence>> {
        self.tx_confidence_map.lock().unwrap().observe(txid).boxed()
    }
}

#[tonic::async_trait]
impl<S: ChainDataSource + Send + Sync + 'static> BmpWalletService for BMPWalletServiceImpl<S> {
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    async fn unused_address(&self) -> anyhow::Result<String> {
        Ok(self
            .wallet
            .lock()
            .await
            .get_new_address()?
            .address
            .to_string())
    }

    async fn wallet_addresses(&self) -> Vec<String> {
        self.wallet.lock().await.list_wallet_addresses()
    }

    async fn transactions(&self) -> Vec<TxInfo> {
        self.wallet.lock().await.list_transactions()
    }

    async fn utxos(&self) -> Vec<UtxoInfo> {
        self.wallet.lock().await.list_utxos()
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

        let mut wallet = self.wallet.lock().await;

        if wallet.is_encrypted() && !wallet.check_password(passphrase.unwrap_or_default())? {
            anyhow::bail!("invalid wallet passphrase");
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

    async fn is_encrypted(&self) -> bool {
        self.wallet.lock().await.is_encrypted()
    }

    async fn full_balance(&self) -> Balance {
        self.wallet.lock().await.full_balance()
    }

    async fn seed_words(&self) -> anyhow::Result<Vec<String>> {
        let phrase = self.wallet.lock().await.get_seed_phrase()?;
        Ok(phrase.split_whitespace().map(ToOwned::to_owned).collect())
    }

    async fn encrypt_wallet(&self, password: &str) -> anyhow::Result<()> {
        self.wallet.lock().await.encrypt_wallet(password)
    }

    async fn decrypt_wallet(&self, password: &str) -> anyhow::Result<()> {
        self.wallet.lock().await.decrypt_wallet(password)
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
    async fn get_unused_address(
        &self,
        request: Request<GetUnusedAddressRequest>,
    ) -> Result<Response<GetUnusedAddressResponse>> {
        handle_request_async(request, |_request| async {
            let address = self
                .wallet_service
                .unused_address()
                .await
                .map_err(|e| internal(&e))?;

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
            Ok(GetWalletAddressesResponse {
                addresses: self.wallet_service.wallet_addresses().await,
            })
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
                .map_err(|e| internal(&e))?;

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
            Ok(IsWalletEncryptedResponse {
                encrypted: self.wallet_service.is_encrypted().await,
            })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>> {
        handle_request_async(request, |_request| async {
            Ok(self.wallet_service.full_balance().await.into())
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
                .map_err(|e| internal(&e))?;

            Ok(GetSeedWordsResponse { seed_words })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn encrypt_wallet(
        &self,
        request: Request<EncryptWalletRequest>,
    ) -> Result<Response<EncryptWalletResponse>> {
        handle_request_async(request, |request| async move {
            // Re-keying an already-protected wallet would lock its owner out, and this request
            // carries no old password to authenticate the caller with. Report it as a state
            // error rather than a server fault, so the client can tell the two apart.
            if self.wallet_service.is_encrypted().await {
                return Err(Status::failed_precondition(
                    "wallet is already encrypted; decrypt it first to change the password",
                ));
            }

            self.wallet_service
                .encrypt_wallet(&request.password)
                .await
                .map_err(|e| internal(&e))?;

            Ok(EncryptWalletResponse { success: true })
        })
        .await
    }

    #[instrument(skip_all)]
    async fn decrypt_wallet(
        &self,
        request: Request<DecryptWalletRequest>,
    ) -> Result<Response<DecryptWalletResponse>> {
        handle_request_async(request, |request| async move {
            self.wallet_service
                .decrypt_wallet(&request.password)
                .await
                // A wrong password is the caller's mistake, not a server fault.
                .map_err(|e| Status::permission_denied(e.to_string()))?;

            Ok(DecryptWalletResponse { success: true })
        })
        .await
    }
}

fn internal(error: &anyhow::Error) -> Status {
    error!("Wallet operation failed: {error:#}");
    Status::internal(error.to_string())
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
        let wallet = BMPWallet::new(dir.path(), "", Network::Regtest).unwrap();
        (dir, BMPWalletServiceImpl::new(wallet))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forwards_queries_to_the_wallet() {
        let (_dir, service) = service();

        assert!(!service.is_ready(), "not ready until connect() has run");
        assert!(
            !service.is_encrypted().await,
            "created with an empty password"
        );
        assert_eq!(service.full_balance().await.total().to_sat(), 0);
        assert_eq!(service.seed_words().await.unwrap().len(), 24);
        assert!(service.transactions().await.is_empty());
        assert!(service.utxos().await.is_empty());

        // Revealing an address must show up in the address list.
        assert!(service.wallet_addresses().await.is_empty());
        let address = service.unused_address().await.unwrap();
        assert!(service.wallet_addresses().await.contains(&address));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypt_then_decrypt_round_trips() {
        let (_dir, service) = service();

        service.encrypt_wallet("hunter2").await.unwrap();
        assert!(service.is_encrypted().await);
        // The seed must still be readable through the rotated key.
        assert_eq!(service.seed_words().await.unwrap().len(), 24);

        assert!(
            service.decrypt_wallet("wrong").await.is_err(),
            "wrong password must be rejected"
        );
        assert!(
            service.is_encrypted().await,
            "a failed decrypt must not clear the flag"
        );

        service.decrypt_wallet("hunter2").await.unwrap();
        assert!(!service.is_encrypted().await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypting_an_encrypted_wallet_is_refused() {
        let (_dir, service) = service();

        service.encrypt_wallet("hunter2").await.unwrap();

        let err = service
            .encrypt_wallet("attacker")
            .await
            .expect_err("re-keying an encrypted wallet must fail");
        assert!(
            err.to_string().contains("already encrypted"),
            "unexpected error: {err}"
        );

        // The original password is still the one that works.
        service.decrypt_wallet("hunter2").await.unwrap();
        assert!(!service.is_encrypted().await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_to_address_without_a_broadcaster_is_an_error() {
        let (_dir, service) = service();

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

        service.sync_once(&NoopChainDataSource).await.unwrap();
        // Nothing on chain, so the map stays empty, but the call must not deadlock — it takes
        // the wallet lock and then the confidence-map lock in that order.
        assert!(service.list_unspent().is_empty());
    }

    /// The `WalletService` half of the impl is synchronous and parks a worker thread to take the
    /// async wallet lock, so it needs its own coverage under a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_wallet_service_methods_work() {
        let (_dir, service) = service();

        assert_eq!(service.balance().total().to_sat(), 0);
        assert!(service.list_unspent().is_empty());

        let first = service.reveal_next_address();
        let second = service.reveal_next_address();
        assert_ne!(
            first.address, second.address,
            "each call must reveal a fresh address"
        );
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
