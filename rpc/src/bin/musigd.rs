use std::error::Error;
use std::sync::Arc;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as BitcoinCoreClient};
use bmp_tracing::tracing::info;
use clap::Parser;
use rpc::bmp_service::BmpServiceImpl;
use rpc::bmp_wallet_service::BmpWalletServiceImpl;
use rpc::pb::bmp_protocol::bmp_protocol_service_server::BmpProtocolServiceServer;
use rpc::pb::bmp_wallet::wallet_server::WalletServer as BmpWalletServer;
use rpc::server::{MusigImpl, MusigServer, WalletImpl, WalletServer};
use rpc::wallet::WalletServiceImpl;
use tonic::transport::Server;

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
    /// Can also be set via BITCOIN_RPC_URL environment variable.
    #[arg(long)]
    bitcoin_rpc_url: Option<String>,

    /// Bitcoin Core RPC username
    /// Can also be set via BITCOIN_RPC_USER environment variable.
    #[arg(long)]
    bitcoin_rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    /// Can also be set via BITCOIN_RPC_PASS environment variable.
    #[arg(long)]
    bitcoin_rpc_pass: Option<String>,

    /// Electrum server URL (optional, for wallet sync optimization)
    /// Can also be set via ELECTRUM_URL environment variable.
    #[arg(long)]
    electrum_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut cli: Cli = Cli::parse();

    bmp_tracing::init("info");

    // Check environment variables as fallback
    if cli.bitcoin_rpc_url.is_none() {
        cli.bitcoin_rpc_url = std::env::var("BITCOIN_RPC_URL").ok();
    }
    if cli.bitcoin_rpc_user.is_none() {
        cli.bitcoin_rpc_user = std::env::var("BITCOIN_RPC_USER").ok();
    }
    if cli.bitcoin_rpc_pass.is_none() {
        cli.bitcoin_rpc_pass = std::env::var("BITCOIN_RPC_PASS").ok();
    }
    if cli.electrum_url.is_none() {
        cli.electrum_url = std::env::var("ELECTRUM_URL").ok();
    }

    // Create or use provided RPC client
    let rpc_client = if let Some(rpc_url) = &cli.bitcoin_rpc_url {
        info!(rpc_url, "Connecting to external Bitcoin Core RPC");

        // Determine authentication method
        let auth = if let (Some(user), Some(pass)) = (&cli.bitcoin_rpc_user, &cli.bitcoin_rpc_pass)
        {
            Auth::UserPass(user.clone(), pass.clone())
        } else {
            // Try cookie file as fallback
            Auth::CookieFile(std::path::PathBuf::from("~/.bitcoin/.cookie"))
        };

        BitcoinCoreClient::new(rpc_url, auth)?
    } else {
        panic!("Can't proceed without bitcoin_rpc_url set")
    };

    let addr = format!("127.0.0.1:{}", cli.port).parse()?;
    let musig = MusigImpl::default();
    let wallet = WalletImpl {
        wallet_service: Arc::new(WalletServiceImpl::create_with_rpc_params(rpc_client)),
    };
    wallet.wallet_service.clone().spawn_connection();

    let bmp_protocol_impl = BmpServiceImpl::default();
    let bmp_wallet_service = BmpWalletServiceImpl::default();

    info!(port = cli.port, "Starting gRPC server.");
    Server::builder()
        .add_service(MusigServer::new(musig))
        .add_service(WalletServer::new(wallet))
        .add_service(BmpProtocolServiceServer::new(bmp_protocol_impl))
        .add_service(BmpWalletServer::new(bmp_wallet_service))
        .serve(addr)
        .await?;

    Ok(())
}
