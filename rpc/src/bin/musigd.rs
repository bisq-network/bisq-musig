use clap::Parser;
use rpc::server::{MusigImpl, MusigServer, WalletImpl, WalletServer};
use rpc::wallet::WalletServiceImpl;
use std::sync::Arc;
use tonic::transport::Server;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
#[expect(clippy::doc_markdown, reason = "doc comments are used verbatim by Clap and not intended to be markdown")]
struct Cli {
    /// The port of the MuSig daemon
    #[arg(short, long, default_value_t = 50051)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = Cli::parse();
    let addr = format!("127.0.0.1:{}", cli.port).parse()?;
    let musig = MusigImpl::default();
    let wallet = WalletImpl { wallet_service: Arc::new(WalletServiceImpl::new()) };
    wallet.wallet_service.clone().spawn_connection();

    Server::builder()
        .add_service(MusigServer::new(musig))
        .add_service(WalletServer::new(wallet))
        .serve(addr)
        .await?;

    Ok(())
}
