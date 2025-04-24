use rpc::server::{WalletImpl, WalletServer};
use rpc::wallet::WalletServiceImpl;
use std::process::{Command, Output};
use std::sync::Arc;
use tokio::task::{self, JoinHandle};
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::{self, Server};
use tonic::transport::server::TcpIncoming;

const EXPECTED_WALLET_BALANCE_RESPONSE: &[u8] = br#"{
  "immature": 0,
  "trustedPending": 0,
  "untrustedPending": 0,
  "confirmed": 0
}
"#;
const EXPECTED_NEW_ADDRESS_RESPONSE_1: &[u8] = br#"{
  "address": "bcrt1pkar3gerekw8f9gef9vn9xz0qypytgacp9wa5saelpksdgct33qdqan7c89",
  "derivationPath": "m/86'/1'/0'/0/0"
}
"#;
const EXPECTED_NEW_ADDRESS_RESPONSE_2: &[u8] = br#"{
  "address": "bcrt1pv537m7m6w0gdrcdn3mqqdpgrk3j400yrdrjwf5c9whyl2f8f4p6q9dn3l9",
  "derivationPath": "m/86'/1'/0'/0/1"
}
"#;

#[test]
fn test_cli_usage() {
    let output = exec_cli([]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.starts_with(b"Usage:"));
}

#[test]
fn test_cli_no_connection() {
    let output = exec_cli_with_port(50050, ["wallet-balance"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains_subslice(b"ConnectError"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_wallet_balance() {
    let mut port = 50052;
    let _guard = AbortOnDropHandle::new(spawn_wallet_grpc_service(&mut port));

    let output = task::spawn_blocking(move || exec_cli_with_port(port, ["wallet-balance"]))
        .await.unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, EXPECTED_WALLET_BALANCE_RESPONSE);
    assert!(output.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cli_new_address() {
    let mut port = 50052;
    let _guard = AbortOnDropHandle::new(spawn_wallet_grpc_service(&mut port));

    let output = task::spawn_blocking(move || exec_cli_with_port(port, ["new-address"]))
        .await.unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, EXPECTED_NEW_ADDRESS_RESPONSE_1);
    assert!(output.stderr.is_empty());

    let output = task::spawn_blocking(move || exec_cli_with_port(port, ["new-address"]))
        .await.unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, EXPECTED_NEW_ADDRESS_RESPONSE_2);
    assert!(output.stderr.is_empty());
}

fn exec_cli<'a>(args: impl IntoIterator<Item=&'a str>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_musig-cli"))
        .args(args)
        .output().unwrap()
}

fn exec_cli_with_port<'a>(port: u16, args: impl IntoIterator<Item=&'a str>) -> Output {
    let port = port.to_string();
    #[expect(clippy::map_identity, reason = "change-of-lifetime false positive; see \
        https://github.com/rust-lang/rust-clippy/issues/9280")]
    let args = ["--port", &port].into_iter()
        .chain(args.into_iter().map(|s| s));
    exec_cli(args)
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

trait Searchable<T> {
    fn contains_subslice(&self, subslice: &[T]) -> bool;
}

impl<T: PartialEq> Searchable<T> for [T] {
    fn contains_subslice(&self, subslice: &[T]) -> bool {
        self.windows(subslice.len()).any(|s| subslice.eq(s))
    }
}
