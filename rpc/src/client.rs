mod walletrpc;

use bdk_wallet::bitcoin::hashes::{Hash as _, sha256d};
use clap::{Parser, Subcommand};
use std::prelude::rust_2021::*;
use tokio_stream::StreamExt as _;
use tonic::Request;

use crate::walletrpc::{ConfRequest, ListUnspentRequest, NewAddressRequest, WalletBalanceRequest};
use crate::walletrpc::wallet_client::WalletClient;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
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

    let mut client = WalletClient::connect("http://127.0.0.1:50051").await?;

    match cli.commands {
        Commands::WalletBalance => {
            let response = client.wallet_balance(Request::new(WalletBalanceRequest {})).await?;
            drop(client);
            println!("{:#?}", response);
        }
        Commands::NewAddress => {
            let response = client.new_address(Request::new(NewAddressRequest {})).await?;
            drop(client);
            println!("{:#?}", response);
        }
        Commands::ListUnspent => {
            let response = client.list_unspent(Request::new(ListUnspentRequest {})).await?;
            drop(client);
            println!("{:?}", response);
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
