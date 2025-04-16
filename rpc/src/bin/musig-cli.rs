use bdk_wallet::bitcoin::hashes::{Hash as _, sha256d};
use clap::{Parser, Subcommand};
use futures::StreamExt as _;
use rpc::pb::walletrpc::{ConfRequest, ListUnspentRequest, NewAddressRequest, WalletBalanceRequest};
use rpc::pb::walletrpc::wallet_client::WalletClient;
use tonic::Request;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
#[expect(clippy::doc_markdown, reason = "doc comments are used verbatim by Clap and not intended to be markdown")]
struct Cli {
    /// The port of the MuSig daemon
    #[arg(short, long, default_value_t = 50051)]
    port: u16,
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Compute and display the wallet's current balance
    WalletBalance,
    /// Generate a new address
    NewAddress,
    /// List utxos available for spending
    ListUnspent,
    /// Receive a stream of confidence events for the given txid
    NotifyConfidence { tx_id: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = Cli::parse();

    let mut client = WalletClient::connect(format!("http://127.0.0.1:{}", cli.port)).await?;

    match cli.commands {
        Commands::WalletBalance => {
            let response = client.wallet_balance(Request::new(WalletBalanceRequest {})).await?;
            drop(client);
            println!("{response:#?}");
        }
        Commands::NewAddress => {
            let response = client.new_address(Request::new(NewAddressRequest {})).await?;
            drop(client);
            println!("{response:#?}");
        }
        Commands::ListUnspent => {
            let response = client.list_unspent(Request::new(ListUnspentRequest {})).await?;
            drop(client);
            println!("{response:?}");
        }
        Commands::NotifyConfidence { tx_id } => {
            let tx_id = tx_id.parse::<sha256d::Hash>()?.as_byte_array().to_vec();
            let response = client.register_confidence_ntfn(Request::new(ConfRequest { tx_id })).await?;
            drop(client);
            let mut stream = response.into_inner();
            while let Some(event_result) = stream.next().await {
                println!("{:?}", event_result?);
            }
        }
    }
    Ok(())
}
