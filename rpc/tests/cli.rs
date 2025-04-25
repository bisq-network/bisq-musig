use assert_cmd::Command;
use assert_cmd::assert::Assert;
use rpc::server::{WalletImpl, WalletServer};
use rpc::wallet::WalletServiceImpl;
use predicates::str;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::{self, JoinHandle};
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::{self, Server};
use tonic::transport::server::TcpIncoming;

const CLI_TIMEOUT: Duration = Duration::from_millis(100);

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
  "utxos": []
}
"#;
const EXPECTED_NOTIFY_CONFIDENCE_RESPONSE: &str = r#"{
  "rawTx": null,
  "confidenceType": "MISSING",
  "numConfirmations": 0,
  "confirmationBlockTime": null
}
"#;

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
    let _guard = AbortOnDropHandle::new(spawn_wallet_grpc_service(&mut port));

    task::spawn_blocking(move || assert_cli_with_port(port, ["wallet-balance"]))
        .await.unwrap()
        .success()
        .stdout(EXPECTED_WALLET_BALANCE_RESPONSE)
        .stderr(str::is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_new_address() {
    let mut port = 50052;
    let _guard = AbortOnDropHandle::new(spawn_wallet_grpc_service(&mut port));

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
    let mut port = 50052;
    let _guard = AbortOnDropHandle::new(spawn_wallet_grpc_service(&mut port));

    task::spawn_blocking(move || assert_cli_with_port(port, ["list-unspent"]))
        .await.unwrap()
        .success()
        .stdout(EXPECTED_LIST_UNSPENT_RESPONSE)
        .stderr(str::is_empty());
}

//noinspection SpellCheckingInspection
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_notify_confidence() {
    let mut port = 50052;
    let _guard = AbortOnDropHandle::new(spawn_wallet_grpc_service(&mut port));

    task::spawn_blocking(move || assert_cli_with_port(port, ["notify-confidence",
        "37b560334094515cfdaa0146bfd4ce19e940064c505082031858b0aba3218990"]))
        .await.unwrap()
        .interrupted()
        .stdout(EXPECTED_NOTIFY_CONFIDENCE_RESPONSE)
        .stderr(str::is_empty());
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

fn spawn_wallet_grpc_service(port: &mut u16) -> JoinHandle<Result<(), transport::Error>> {
    let wallet = WalletImpl { wallet_service: Arc::new(WalletServiceImpl::new()) };
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
