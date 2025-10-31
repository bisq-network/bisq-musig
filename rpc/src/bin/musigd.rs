use std::error::Error;
use std::sync::Arc;

use clap::Parser;
use rpc::bmp_service::BmpServiceImpl;
use rpc::bmp_wallet_service::BmpWalletServiceImpl;
use rpc::pb::bmp_protocol::bmp_protocol_service_server::BmpProtocolServiceServer;
use rpc::pb::bmp_wallet::wallet_server::WalletServer as BmpWalletServer;
use rpc::server::{MusigImpl, MusigServer, WalletImpl, WalletServer};
use rpc::wallet::WalletServiceImpl;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::field::MakeExt;
use tracing_subscriber::filter::{EnvFilter, ParseError};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
#[expect(clippy::doc_markdown, reason = "doc comments are used verbatim by Clap and not intended to be markdown")]
struct Cli {
    /// The port of the MuSig daemon
    #[arg(short, long, default_value_t = 50051)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli: Cli = Cli::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|e| {
            if matches!(e.source(), Some(s) if s.is::<ParseError>()) {
                eprintln!("Could not parse `RUST_LOG` environment variable: {e}");
            }
            EnvFilter::new("info,rpc=debug")
        });
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer()
            .map_fmt_fields(MakeExt::debug_alt)
            .with_writer(std::io::stderr))
        .init();

    let addr = format!("127.0.0.1:{}", cli.port).parse()?;
    let musig = MusigImpl::default();
    let wallet = WalletImpl { wallet_service: Arc::new(WalletServiceImpl::new()) };
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
