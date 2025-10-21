use std::sync::Arc;
use std::time::Duration;

use assert_cmd::assert::Assert;
use assert_cmd::Command;
use bdk_wallet::bitcoin::hex::test_hex_unwrap as hex;
use bdk_wallet::bitcoin::{consensus, OutPoint, Transaction};
use bdk_wallet::chain::{ChainPosition, ConfirmationBlockTime};
use bdk_wallet::{KeychainKind, LocalOutput};
use const_format::str_replace;
use futures_util::stream::{self, BoxStream, StreamExt as _};
use predicates::str;
use rpc::server::{WalletImpl, WalletServer};
use rpc::wallet::{TxConfidence, WalletService, WalletServiceImpl, WalletServiceMock, WalletTx};
use tokio::task::{self, JoinHandle};
use tonic::transport::server::TcpIncoming;
use tonic::transport::{self, Server};
use unimock::{matching, MockFn as _, Unimock};

const CLI_TIMEOUT: Duration = Duration::from_millis(200);

//noinspection SpellCheckingInspection
const MOCK_TX: &str = "\
    02000000000101fb8ab4c1fb7ea3fe11a35d24853653df8823b7552cb561e5626bf4b709bbf9f70000000000fdffffff\
    0200f90295000000002251206523edfb7a73d0d1e1b38ec0068503b46557bc8368e4e4d30575c9f524e9a8748ef20295\
    0000000022512025a006cf9eb838697404da9568728e678e4fb704007d8f154b300fbdba3c9fb602473044022042821b\
    ee4e1afa02ce2ec5a931a964a3110c18987dae0c176f4ef83656ff149f0220730cc1917a8277d92ad9af155730630ac5\
    482759300bbdf0d5083407f8dea3e401210226e4d88cd0ea0cd405b8f03e4226291e094c1e8fe83a3536d438146a56c4\
    21f000000000";

const EXPECTED_WALLET_BALANCE_RESPONSE: &str = r#"{
  "immature": 0,
  "trustedPending": 0,
  "untrustedPending": 0,
  "confirmed": 0
}
"#;
const EXPECTED_NEW_ADDRESS_RESPONSE_1: &str = r#"{
  "address": "bcrt1pkar3gerekw8f9gef9vn9xz0qypytgacp9wa5saelpksdgct33qdqan7c89",
  "derivationPath": "m/86'/1'/0'/0/0"
}
"#;
const EXPECTED_NEW_ADDRESS_RESPONSE_2: &str = r#"{
  "address": "bcrt1pv537m7m6w0gdrcdn3mqqdpgrk3j400yrdrjwf5c9whyl2f8f4p6q9dn3l9",
  "derivationPath": "m/86'/1'/0'/0/1"
}
"#;
const EXPECTED_LIST_UNSPENT_RESPONSE: &str = r#"{
  "utxos": [
    {
      "txId": "37b560334094515cfdaa0146bfd4ce19e940064c505082031858b0aba3218990",
      "vout": 0,
      "scriptPubKey": "51206523edfb7a73d0d1e1b38ec0068503b46557bc8368e4e4d30575c9f524e9a874",
      "value": 2500000000
    }
  ]
}
"#;
const EXPECTED_NOTIFY_CONFIDENCE_RESPONSE: &str = str_replace!(r#"{
  "rawTx": null,
  "confidenceType": "MISSING",
  "numConfirmations": 0,
  "confirmationBlockTime": null
}
{
  "rawTx": "$MOCK_TX",
  "confidenceType": "UNCONFIRMED",
  "numConfirmations": 0,
  "confirmationBlockTime": null
}
{
  "rawTx": "$MOCK_TX",
  "confidenceType": "CONFIRMED",
  "numConfirmations": 1,
  "confirmationBlockTime": {
    "blockHash": "01b623501ea6b83b14035d8b965eaa8c78eeeaf773f60b35228ae4929e7dad56",
    "blockHeight": 104,
    "confirmationTime": 1743580321
  }
}
"#, "$MOCK_TX", MOCK_TX);

#[test]
fn test_cli_usage() {
    assert_cli([])
        .code(2)
        .stdout(str::is_empty())
        .stderr(str::starts_with("Usage:"));
}

#[test]
fn test_cli_no_connection() {
    assert_cli_with_port(50050, ["wallet-balance"])
        .code(1)
        .stdout(str::is_empty())
        .stderr(str::contains("ConnectError"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_wallet_balance() {
    let mut port = 50052;
    spawn_wallet_grpc_service(&mut port, WalletServiceImpl::new());

    task::spawn_blocking(move || assert_cli_with_port(port, ["wallet-balance"]))
        .await.unwrap()
        .success()
        .stdout(EXPECTED_WALLET_BALANCE_RESPONSE)
        .stderr(str::is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_new_address() {
    let mut port = 50052;
    spawn_wallet_grpc_service(&mut port, WalletServiceImpl::new());

    task::spawn_blocking(move || assert_cli_with_port(port, ["new-address"]))
        .await.unwrap()
        .success()
        .stdout(EXPECTED_NEW_ADDRESS_RESPONSE_1)
        .stderr(str::is_empty());

    task::spawn_blocking(move || assert_cli_with_port(port, ["new-address"]))
        .await.unwrap()
        .success()
        .stdout(EXPECTED_NEW_ADDRESS_RESPONSE_2)
        .stderr(str::is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_list_unspent() {
    let clause = WalletServiceMock::list_unspent
        .some_call(matching!()).returns(vec![mock_utxo()]);
    let mock_wallet_service = Unimock::new(clause).no_verify_in_drop();

    let mut port = 50052;
    spawn_wallet_grpc_service(&mut port, mock_wallet_service);

    task::spawn_blocking(move || assert_cli_with_port(port, ["list-unspent"]))
        .await.unwrap()
        .success()
        .stdout(EXPECTED_LIST_UNSPENT_RESPONSE)
        .stderr(str::is_empty());
}

//noinspection SpellCheckingInspection
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_notify_confidence() {
    let clause = WalletServiceMock::get_tx_confidence_stream
        .some_call(matching!((arg) if *arg == mock_tx().compute_txid()))
        .answers(&|_, _| mock_confidence_stream());
    let mock_wallet_service = Unimock::new(clause).no_verify_in_drop();

    let mut port = 50052;
    spawn_wallet_grpc_service(&mut port, mock_wallet_service);

    task::spawn_blocking(move || assert_cli_with_port(port, ["notify-confidence",
        "37b560334094515cfdaa0146bfd4ce19e940064c505082031858b0aba3218990"]))
        .await.unwrap()
        .interrupted()
        .stdout(EXPECTED_NOTIFY_CONFIDENCE_RESPONSE)
        .stderr(str::is_empty());
}

fn mock_tx() -> Transaction { consensus::deserialize(&hex!(MOCK_TX)).unwrap() }

//noinspection SpellCheckingInspection
fn mock_chain_position() -> ChainPosition<ConfirmationBlockTime> {
    ChainPosition::Confirmed {
        anchor: ConfirmationBlockTime {
            block_id: (104, "01b623501ea6b83b14035d8b965eaa8c78eeeaf773f60b35228ae4929e7dad56"
                .parse().unwrap()).into(),
            confirmation_time: 1_743_580_321,
        },
        transitively: None,
    }
}

fn mock_utxo() -> LocalOutput {
    let tx = mock_tx();
    LocalOutput {
        outpoint: OutPoint::new(tx.compute_txid(), 0),
        txout: tx.output[0].clone(),
        keychain: KeychainKind::External,
        is_spent: false,
        derivation_index: 1,
        chain_position: mock_chain_position(),
    }
}

fn mock_confidence_stream() -> BoxStream<'static, Option<TxConfidence>> {
    let tx = Arc::new(mock_tx());
    let txid = tx.compute_txid();
    let event1 = None;
    let event2 = Some(TxConfidence {
        wallet_tx: WalletTx {
            txid,
            tx: tx.clone(),
            chain_position: ChainPosition::Unconfirmed { first_seen: Some(0), last_seen: Some(0) },
        },
        num_confirmations: 0,
    });
    let event3 = Some(TxConfidence {
        wallet_tx: WalletTx {
            txid,
            tx,
            chain_position: mock_chain_position(),
        },
        num_confirmations: 1,
    });
    stream::iter([event1, event2, event3]).chain(stream::pending()).boxed()
}

fn assert_cli<'a>(args: impl IntoIterator<Item=&'a str>) -> Assert {
    Command::cargo_bin("musig-cli").unwrap()
        .args(args)
        .timeout(CLI_TIMEOUT)
        .assert()
}

fn assert_cli_with_port<'a>(port: u16, args: impl IntoIterator<Item=&'a str>) -> Assert {
    let port = port.to_string();
    #[expect(clippy::map_identity, reason = "change-of-lifetime false positive; see \
        https://github.com/rust-lang/rust-clippy/issues/9280")]
    let args = ["--port", &port].into_iter()
        .chain(args.into_iter().map(|s| s));
    assert_cli(args)
}

fn spawn_wallet_grpc_service(port: &mut u16, wallet_service: impl WalletService + Send + Sync + 'static)
                             -> JoinHandle<Result<(), transport::Error>> {
    let wallet = WalletImpl { wallet_service: Arc::new(wallet_service) };
    let incoming = loop {
        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        match TcpIncoming::bind(addr) {
            Ok(t) => break t,
            Err(_) => *port += 1
        }
    };
    task::spawn(async move {
        Server::builder()
            .add_service(WalletServer::new(wallet))
            .serve_with_incoming(incoming)
            .await
    })
}
