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
    ChangePasswordRequest, GetBalanceRequest, GetNewAddressRequest, GetSeedWordsRequest,
    IsWalletEncryptedRequest, IsWalletReadyRequest, OpenOrCreateWalletRequest,
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

    async fn is_encrypted(&mut self) -> Result<bool, tonic::Status> {
        Ok(self
            .client
            .is_wallet_encrypted(IsWalletEncryptedRequest {})
            .await?
            .into_inner()
            .encrypted)
    }

    async fn seed_words(&mut self) -> Result<Vec<String>, tonic::Status> {
        Ok(self
            .client
            .get_seed_words(GetSeedWordsRequest {})
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
        .get_new_address(GetNewAddressRequest {})
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
    assert!(fixture.is_encrypted().await?, "created with a password");

    let seed = fixture.seed_words().await?;
    assert_eq!(seed.len(), 24);

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
        fixture.is_encrypted().await?,
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
    assert!(fixture.is_encrypted().await?);
    assert_eq!(
        fixture.seed_words().await?,
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
    assert!(!fixture.is_encrypted().await?);

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
        fixture.seed_words().await?,
        seed,
        "reloading must yield the same wallet, not a fresh one"
    );
    fixture.stop();

    Ok(())
}
