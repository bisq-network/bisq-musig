//! Integration test of the bisq2-facing `wallet.Wallet` gRPC service, focused on the wallet
//! lifecycle RPCs: `OpenOrCreateWallet` (which replaces the daemon's former `--wallet-password`
//! command-line argument) and `ChangePassword` (which replaces `EncryptWallet`/`DecryptWallet`).
//!
//! The full gRPC stack is exercised — a real tonic server on a loopback port, driven through the
//! generated client — but no chain backend is needed: everything under test is pure wallet-
//! database state, which is exactly what `OpenOrCreateWallet` manages.

use std::path::Path;
use std::sync::Arc;

use bdk_wallet::bitcoin::Network;
use chain::CBFScanner;
use rpc::bmp_wallet_service::{BMPWalletServiceImpl, BmpWalletImpl, BmpWalletServer};
use rpc::pb::bmp_wallet::wallet_client::WalletClient;
use rpc::pb::bmp_wallet::{
    ChangePasswordRequest, GetBalanceRequest, GetSeedWordsRequest, GetUnusedAddressRequest,
    GetWalletAddressesRequest, IsWalletReadyRequest, OpenOrCreateWalletRequest, PubAddressInfo,
    SendToAddressRequest,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::Code;
use tonic::transport::Channel;
use tonic::transport::server::TcpIncoming;

/// A running `wallet.Wallet` gRPC server over a fresh [`BMPWalletServiceImpl`] (no chain data
/// source, no broadcaster) on `wallet_dir`, plus a connected client.
struct WalletServiceFixture {
    client: WalletClient<Channel>,
    server: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl WalletServiceFixture {
    async fn start(wallet_dir: &Path) -> anyhow::Result<Self> {
        // `CBFScanner` only pins the (unused) chain-source type parameter; none is configured.
        let service = Arc::new(BMPWalletServiceImpl::<CBFScanner>::new(
            wallet_dir,
            Network::Regtest,
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(BmpWalletServer::new(BmpWalletImpl {
                    wallet_service: service,
                }))
                .serve_with_incoming(TcpIncoming::from(listener)),
        );

        let client = WalletClient::connect(format!("http://{addr}")).await?;
        Ok(Self { client, server })
    }

    async fn open(
        &mut self,
        password: &str,
    ) -> Result<tonic::Response<rpc::pb::bmp_wallet::OpenOrCreateWalletResponse>, tonic::Status>
    {
        self.client
            .open_or_create_wallet(OpenOrCreateWalletRequest {
                password: password.to_owned(),
            })
            .await
    }

    async fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<tonic::Response<rpc::pb::bmp_wallet::ChangePasswordResponse>, tonic::Status> {
        self.client
            .change_password(ChangePasswordRequest {
                old_password: old_password.to_owned(),
                new_password: new_password.to_owned(),
            })
            .await
    }

    /// Whether `password` is the one currently protecting the wallet, probed by re-opening the
    /// (already open) wallet with it.
    async fn opens_with(&mut self, password: &str) -> Result<bool, tonic::Status> {
        match self.open(password).await {
            Ok(response) => Ok(response.into_inner().success),
            Err(status) if status.code() == Code::PermissionDenied => Ok(false),
            Err(status) => Err(status),
        }
    }

    async fn seed_words(&mut self, password: &str) -> Result<Vec<String>, tonic::Status> {
        Ok(self
            .client
            .get_seed_words(GetSeedWordsRequest {
                password: password.to_owned(),
            })
            .await?
            .into_inner()
            .seed_words)
    }

    fn stop(self) {
        self.server.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_lifecycle_over_grpc() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut fixture = WalletServiceFixture::start(dir.path()).await?;

    // --- Before OpenOrCreateWallet, wallet operations are refused as a precondition failure ---
    let err = fixture
        .client
        .get_balance(GetBalanceRequest {})
        .await
        .expect_err("wallet operations must be refused before the wallet is opened");
    assert_eq!(err.code(), Code::FailedPrecondition, "got: {err}");

    let err = fixture
        .client
        .get_unused_address(GetUnusedAddressRequest {})
        .await
        .expect_err("no addresses before the wallet is opened");
    assert_eq!(err.code(), Code::FailedPrecondition, "got: {err}");

    let ready = fixture
        .client
        .is_wallet_ready(IsWalletReadyRequest {})
        .await?
        .into_inner()
        .ready;
    assert!(!ready, "an unopened wallet must not report itself ready");

    // --- OpenOrCreateWallet creates a fresh, password-protected wallet ---
    assert!(fixture.open("s3cret").await?.into_inner().success);
    let ready = fixture
        .client
        .is_wallet_ready(IsWalletReadyRequest {})
        .await?
        .into_inner()
        .ready;
    assert!(
        ready,
        "with no chain data source the wallet is ready as soon as it is open"
    );
    assert!(!fixture.opens_with("").await?, "created with a password");

    let seed = fixture.seed_words("s3cret").await?;
    assert_eq!(seed.len(), 24);
    let err = fixture.seed_words("wrong").await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "got: {err}");

    let balance = fixture
        .client
        .get_balance(GetBalanceRequest {})
        .await?
        .into_inner();
    assert_eq!(balance.balance, 0, "a fresh wallet starts empty");

    // --- Re-opening is idempotent, but only with the right password ---
    assert!(fixture.open("s3cret").await?.into_inner().success);
    let err = fixture
        .open("wrong")
        .await
        .expect_err("a wrong password must not re-open the wallet");
    assert_eq!(err.code(), Code::PermissionDenied, "got: {err}");

    // --- ChangePassword requires the current password... ---
    let err = fixture
        .change_password("wrong", "irrelevant")
        .await
        .expect_err("a wrong old password must be rejected");
    assert_eq!(err.code(), Code::PermissionDenied, "got: {err}");
    assert!(
        fixture.opens_with("s3cret").await?,
        "a rejected change must leave the wallet as it was"
    );

    // --- ...and with it, re-keys the wallet ---
    assert!(
        fixture
            .change_password("s3cret", "n3w")
            .await?
            .into_inner()
            .success
    );
    assert!(fixture.opens_with("n3w").await?);
    assert_eq!(
        fixture.seed_words("n3w").await?,
        seed,
        "the seed must survive the re-key"
    );

    // An empty new password removes protection.
    assert!(
        fixture
            .change_password("n3w", "")
            .await?
            .into_inner()
            .success
    );
    assert!(fixture.opens_with("").await?);

    // --- The wallet (and its final password state) persists across a server restart ---
    fixture.stop();
    let mut fixture = WalletServiceFixture::start(dir.path()).await?;

    let err = fixture
        .open("bogus")
        .await
        .expect_err("a wrong password must not open the persisted wallet");
    assert_eq!(err.code(), Code::PermissionDenied, "got: {err}");

    assert!(fixture.open("").await?.into_inner().success);
    assert_eq!(
        fixture.seed_words("").await?,
        seed,
        "reloading must yield the same wallet, not a fresh one"
    );
    fixture.stop();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn addresses_travel_as_address_infos_over_grpc() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut fixture = WalletServiceFixture::start(dir.path()).await?;
    assert!(fixture.open("").await?.into_inner().success);

    let address = fixture
        .client
        .get_unused_address(GetUnusedAddressRequest {})
        .await?
        .into_inner()
        .address
        .expect("GetUnusedAddress must return an address");
    assert!(
        address.address.starts_with("bcrt1"),
        "got: {}",
        address.address
    );

    let addresses = fixture
        .client
        .get_wallet_addresses(GetWalletAddressesRequest {})
        .await?
        .into_inner()
        .addresses;
    assert_eq!(addresses, [address], "the one address revealed so far");

    // An address that doesn't parse is refused before it reaches the wallet.
    let err = fixture
        .client
        .send_to_address(SendToAddressRequest {
            passphrase: None,
            address: Some(PubAddressInfo {
                address: "not-an-address".to_owned(),
            }),
            amount: 1_000,
            fee_rate_per_kwu: None,
        })
        .await
        .expect_err("a malformed address must be rejected");
    assert_eq!(err.code(), Code::InvalidArgument, "got: {err}");

    // So is a request with no address at all.
    let err = fixture
        .client
        .send_to_address(SendToAddressRequest {
            passphrase: None,
            address: None,
            amount: 1_000,
            fee_rate_per_kwu: None,
        })
        .await
        .expect_err("a missing address must be rejected");
    assert_eq!(err.code(), Code::InvalidArgument, "got: {err}");
    fixture.stop();

    Ok(())
}
