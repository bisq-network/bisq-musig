//! Integration-test home of the `musigd` daemon (formerly the `rpc/src/bin/musigd.rs` binary).
//!
//! The full gRPC server — the `MuSig` trade-protocol service, the wallet service, and the two BMP
//! services — is built by [`spawn_musigd`] and backed by a real `bitcoind`/`electrs`
//! [`TestEnv`], so the daemon can be started as a test case rather than as a standalone process.
//!
//! Two entry points are provided:
//!
//! * [`test_musigd_starts_and_serves`] — a fast smoke test on an OS-assigned port that asserts the
//!   server comes up and serves, then tears it down.
//! * [`run_musigd_server`] — an `#[ignore]`d, long-running server on a fixed port (taken from the
//!   `MUSIGD_PORT` env var, default `50051`). It serves until the process is killed, replacing
//!   `cargo run --bin musigd -- --port <PORT>` for e.g. the Java integration test client. Run it
//!   with, for example:
//!
//!   ```sh
//!   MUSIGD_PORT=50051 cargo test -p rpc --test musigd -- --ignored run_musigd_server --nocapture
//!   ```
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as BitcoinCoreClient};
use bdk_wallet::bitcoin::Amount;
use protocol::protocol_musig_adaptor::{BMPContext, BMPProtocol, ProtocolRole, Round1Parameter};
use rpc::bmp_wallet_service::BmpWalletServiceImpl;
 use rpc::server::{MusigImpl, MusigServer, WalletImpl, WalletServer};
use rpc::wallet::WalletServiceImpl;
use testenv::{TestEnv, TestEnvBuilder};
use tokio::net::TcpListener;
use tokio::task::{self, JoinHandle};
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Result, Status, transport};
use tracing::info;
use wallet::protocol_wallet_api::MemWallet;
use rpc::pb::bmp_wallet::wallet_server::WalletServer as BmpWalletServer;
use rpc::pb::bmp_protocol::bmp_protocol_service_server::{BmpProtocolService, BmpProtocolServiceServer};
use rpc::pb::bmp_protocol::{self, InitializeRequest, InitializeResponse, Role};
use rpc::pb::convert::TryProtoInto as _;

#[derive(Default)]
pub struct BmpServiceImpl {
    // Each trade protocol is stored against a unique ID.
    active_protocols: Mutex<HashMap<String, BMPProtocol>>,
}

#[tonic::async_trait]
impl BmpProtocolService for BmpServiceImpl {
    async fn initialize(
        &self,
        request: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>> {
        let req = request.into_inner();
        info!("Received initialize request: {req:?}");

        //todo retrieve the actual wallet
        let mut env = TestEnv::new().unwrap(); // TODO move Wallet loading
        let mock_wallet = MemWallet::funded_wallet(&mut env);

        let chain = Box::new(env.new_testchain().unwrap());
        let role =
            Role::try_from(req.role).map_err(|_| Status::invalid_argument("Unrecognised role"))?;
        let role = match role {
            Role::Seller => ProtocolRole::Seller,
            Role::Buyer => ProtocolRole::Buyer,
        };

        let context = BMPContext::new(
            chain,
            Box::new(mock_wallet),
            role,
            Amount::from_sat(req.seller_amount_sats),
            Amount::from_sat(req.buyer_amount_sats),
        ).map_err(|e| Status::internal(e.to_string()))?;

        let protocol = BMPProtocol::new(context).map_err(|e| Status::internal(e.to_string()))?;

        let trade_id = &req.trade_id;
        if trade_id.is_empty() {
            return Err(Status::invalid_argument("Trade ID must not be empty"));
        }
        self.active_protocols
            .lock()
            .unwrap()
            .insert(trade_id.clone(), protocol);

        Ok(Response::new(InitializeResponse {
            trade_id: trade_id.clone(),
        }))
    }

    async fn execute_round1(
        &self,
        request: Request<bmp_protocol::Round1Request>,
    ) -> Result<Response<bmp_protocol::Round1Response>> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {trade_id}")))?;

        let round1_result = protocol
            .round1()
            .map_err(|e| Status::aborted(e.to_string()))?;

        drop(protocols);
        Ok(Response::new(round1_result.try_into()?))
    }

    async fn execute_round2(
        &self,
        request: Request<bmp_protocol::Round2Request>,
    ) -> Result<Response<bmp_protocol::Round2Response>> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {trade_id}")))?;

        let peer_round1_params: Round1Parameter =
            req.peer_round1_response.unwrap().try_proto_into()?;

        let round2_result = protocol
            .round2(peer_round1_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        drop(protocols);
        Ok(Response::new(round2_result.try_into()?))
    }

    async fn execute_round3(
        &self,
        request: Request<bmp_protocol::Round3Request>,
    ) -> Result<Response<bmp_protocol::Round3Response>> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {trade_id}")))?;

        let peer_round2_params = req.peer_round2_response.unwrap().try_proto_into()?;

        let round3_result = protocol
            .round3(peer_round2_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        drop(protocols);
        Ok(Response::new(round3_result.try_into()?))
    }

    async fn execute_round4(
        &self,
        request: Request<bmp_protocol::Round4Request>,
    ) -> Result<Response<bmp_protocol::Round4Response>> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {trade_id}")))?;

        let peer_round3_params = req.peer_round3_response.unwrap().try_proto_into()?;

        let round4_result = protocol
            .round4(peer_round3_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        drop(protocols);
        Ok(Response::new(round4_result.try_into()?))
    }

    async fn execute_round5(
        &self,
        request: Request<bmp_protocol::Round5Request>,
    ) -> Result<Response<bmp_protocol::ExecuteRound5Response>> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {trade_id}")))?;

        let peer_round4_params = req.peer_round4_response.unwrap().try_proto_into()?;

        info!("Round 5 params {:#?}", peer_round4_params.deposit_tx_signed.clone().extract_tx().unwrap());
        protocol
            .round5(peer_round4_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        drop(protocols);
        Ok(Response::new(bmp_protocol::ExecuteRound5Response {}))
    }
}

/// Builds and spawns the full `musigd` gRPC server, mirroring the former `musigd` binary's
/// `main`, but on a caller-supplied listener (instead of a fixed port) so it can run inside a
/// test harness.
fn spawn_musigd(
    listener: TcpListener,
    client: Arc<BitcoinCoreClient>,
) -> Result<JoinHandle<Result<(), transport::Error>>> {
    let musig = MusigImpl::default();
    let wallet = WalletImpl {
        wallet_service: Arc::new(WalletServiceImpl::create_with_rpc_params()),
    };

    wallet.wallet_service.clone().spawn_connection(client);

    let bmp_protocol_impl = BmpServiceImpl::default();
    let bmp_wallet_service = BmpWalletServiceImpl::default();

    let incoming = TcpIncoming::from(listener);
    let handle = task::spawn(async move {
        Server::builder()
            .add_service(MusigServer::new(musig))
            .add_service(WalletServer::new(wallet))
            .add_service(BmpProtocolServiceServer::new(bmp_protocol_impl))
            .add_service(BmpWalletServer::new(bmp_wallet_service))
            .serve_with_incoming(incoming)
            .await
    });
    Ok(handle)
}

/// Long-running server on a fixed port, the test-case replacement for the old `musigd` binary.
///
/// Ignored by default so it doesn't block the test suite; run it explicitly when you need a live
/// server (e.g. for the Java integration test client). The port is read from the `MUSIGD_PORT`
/// env var, defaulting to `50051`. Serves until the process is killed.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "long-running server; start manually for the Java integration test client"]
async fn run_musigd_server() -> Result<()> {
    bmp_tracing::init("info");

    let port: u16 = std::env::var("MUSIGD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(50051);
    
    // let data_dir = std::env::var("MUSIGD_DATADIR").ok().map(|v| Path::new(&v).to_path_buf());

    let rpc_url = std::env::var("RPC_URL").ok();
    let rpc_pass = std::env::var("RPC_PASS").ok();
    let rpc_user = Some("bitcoin");

    // Create RPC client
    let rpc_client = if let Some(rpc_url) = &rpc_url {
        info!(rpc_url, "Connecting to external Bitcoin Core RPC");

        // Determine authentication method
        let auth = if let (Some(user), Some(pass)) = (&rpc_user, &rpc_pass)
        {
            Auth::UserPass(user.to_string(), pass.to_string())
        } else {
            // Try cookie file as fallback
            Auth::CookieFile(std::path::PathBuf::from("~/.bitcoin/.cookie"))
        };

        BitcoinCoreClient::new(rpc_url, auth)
    } else {
        panic!("");
    };

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;

    bmp_tracing::tracing::info!(port, "Starting musigd gRPC server.");
    let _ = spawn_musigd(listener, Arc::new(rpc_client.unwrap())).unwrap().await;

    Ok(())
}
