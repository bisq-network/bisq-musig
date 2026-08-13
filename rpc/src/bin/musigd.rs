use std::error::Error;
use std::net::{AddrParseError, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as BitcoinCoreClient};
use bdk_wallet::bitcoin::Network;
use bdk_wallet::rusqlite::Connection;
use bmp_tracing::tracing::{info, warn};
use chain::CBFScanner;
use clap::Parser;
use rpc::bmp_wallet_service::{
    BMPWalletServiceImpl, BitcoinCoreChainApi, BmpWalletImpl, BmpWalletServer,
};
use rpc::server::{MusigImpl, MusigServer, WalletImpl, WalletServer};
use rpc::wallet::{WalletService as _, WalletServiceImpl};
use tonic::transport::Server;
use wallet::bmp_wallet::{BMPWallet, WalletApi as _};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
#[expect(
    clippy::doc_markdown,
    reason = "doc comments are used verbatim by Clap and not intended to be markdown"
)]
struct Cli {
    /// The port of the MuSig daemon
    #[arg(short, long, default_value_t = 50051)]
    port: u16,

    /// Bitcoin Core RPC URL.
    #[arg(long, default_value = "http://localhost:18443")]
    bitcoin_rpc_url: String,

    /// Bitcoin Core RPC username
    #[arg(long)]
    bitcoin_rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    #[arg(long)]
    bitcoin_rpc_pass: Option<String>,

    /// Directory holding the BMP wallet database. When set, the bisq2-facing wallet.Wallet
    /// service is served from a BMPWallet in this directory, creating it if absent.
    #[arg(long)]
    wallet_dir: Option<PathBuf>,

    /// Password protecting the BMP wallet database. Empty means unencrypted.
    #[arg(long, default_value = "")]
    wallet_password: String,

    /// Bitcoin network the BMP wallet operates on.
    #[arg(long, default_value = "regtest")]
    wallet_network: Network,

    /// Peer (host:port) for compact-block-filter syncing of the BMP wallet. Repeatable. With no
    /// peer given the wallet does not sync, but every non-chain operation still works.
    #[arg(long = "wallet-peer")]
    wallet_peers: Vec<String>,

    /// Seconds between BMP wallet re-syncs. Integration tests lower this so they don't have to
    /// wait out the default.
    #[arg(long)]
    wallet_poll_secs: Option<u64>,
}

/// Opens the BMP wallet at `dir`, creating a fresh one only if none exists there yet.
///
/// Creating is chosen on the *absence* of the database file, never on a failed load. A load
/// failure most likely means the wrong `--wallet-password` was given, and creating a wallet
/// rewrites the Argon2 salt the existing database's key was derived from — which would render
/// that wallet, and any funds in it, permanently unrecoverable.
fn open_or_create_wallet(
    dir: &Path,
    password: &str,
    network: Network,
) -> anyhow::Result<BMPWallet<Connection>> {
    std::fs::create_dir_all(dir)?;
    let db_path = dir.join(BMPWallet::<Connection>::DB_NAME);

    if db_path.exists() {
        let wallet = BMPWallet::load_wallet(dir, network, password).with_context(|| {
            format!(
                "failed to open the existing wallet at {} (wrong --wallet-password?)",
                db_path.display()
            )
        })?;
        info!(dir = %dir.display(), "Loaded existing BMP wallet.");
        Ok(wallet)
    } else {
        info!(dir = %dir.display(), "No BMP wallet found; creating a new one.");
        BMPWallet::new(dir, password, network)
    }
}

fn parse_peers(peers: &[String]) -> Result<Vec<SocketAddr>, AddrParseError> {
    peers.iter().map(|peer| peer.parse()).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli: Cli = Cli::parse();
    bmp_tracing::init("info");
    // Create RPC client. (No connection is made at this point.)
    let rpc_client = {
        let auth = if let (Some(user), Some(pass)) = (&cli.bitcoin_rpc_user, &cli.bitcoin_rpc_pass) {
            Auth::UserPass(user.clone(), pass.clone())
        } else {
            Auth::None
        };
        Arc::new(BitcoinCoreClient::new(&cli.bitcoin_rpc_url, auth)?)
    };

    let addr = format!("127.0.0.1:{}", cli.port).parse()?;
    let musig = MusigImpl::default();
    let wallet = WalletImpl {
        wallet_service: Arc::new(WalletServiceImpl::new()),
    };
    wallet
        .wallet_service
        .clone()
        .spawn_connection(Arc::clone(&rpc_client));

    let mut server = Server::builder()
        .add_service(MusigServer::new(musig))
        .add_service(WalletServer::new(wallet));

    // The bisq2-facing wallet service is optional: without --wallet-dir there is no BMPWallet to
    // serve, and musigd behaves exactly as before.
    let bmp_wallet = if let Some(dir) = &cli.wallet_dir {
        let wallet = open_or_create_wallet(dir, &cli.wallet_password, cli.wallet_network)?;

        let mut service = BMPWalletServiceImpl::new(wallet)
            .with_broadcaster(Arc::new(BitcoinCoreChainApi::new(Arc::clone(&rpc_client))));

        if let Some(secs) = cli.wallet_poll_secs {
            service = service.with_poll_period(Duration::from_secs(secs));
        }

        let peers = parse_peers(&cli.wallet_peers)?;
        if peers.is_empty() {
            warn!("No --wallet-peer given: the BMP wallet will not sync with the chain.");
        } else {
            info!(
                peer_count = peers.len(),
                "Syncing the BMP wallet over compact block filters."
            );
            service = service.with_chain_data_source(CBFScanner::from_socket_addrs(peers));
        }

        let service = Arc::new(service);
        Arc::clone(&service).spawn_connection(Arc::clone(&rpc_client));
        Some(service)
    } else {
        None
    };

    if let Some(service) = bmp_wallet {
        server = server.add_service(BmpWalletServer::new(BmpWalletImpl {
            wallet_service: service,
        }));
    }

    info!(port = cli.port, "Starting gRPC server.");
    server.serve(addr).await?;

    Ok(())
}
