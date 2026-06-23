use std::error::Error;
use std::sync::Arc;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as BitcoinCoreClient};
use bmp_tracing::tracing::info;
use clap::Parser;
use rpc::bmp_wallet_service::BmpWalletServiceImpl;
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
    #[arg(long, default_value = "http://localhost:18443")]
    bitcoin_rpc_url: Option<String>,

    /// Bitcoin Core RPC username
    #[arg(long)]
    bitcoin_rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    #[arg(long)]
    bitcoin_rpc_pass: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli: Cli = Cli::parse();
    bmp_tracing::init("info");
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
        return Err("Can't proceed without bitcoin_rpc_url".into())
    };

    let addr = format!("127.0.0.1:{}", cli.port).parse()?;
    let musig = MusigImpl::default();
    let wallet = WalletImpl {
        wallet_service: Arc::new(WalletServiceImpl::create_with_rpc_params()),
    };
    wallet
        .wallet_service
        .clone()
        .spawn_connection(Arc::new(rpc_client));

    let bmp_wallet_service = BmpWalletServiceImpl::default();

    info!(port = cli.port, "Starting gRPC server.");
    Server::builder()
        .add_service(MusigServer::new(musig))
        .add_service(WalletServer::new(wallet))
        .add_service(BmpWalletServer::new(bmp_wallet_service))
        .serve(addr)
        .await?;

    Ok(())
}
