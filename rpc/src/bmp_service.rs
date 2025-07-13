use protocol::nigiri;
use std::collections::HashMap;
use std::sync::Mutex;
use tonic::{Request, Response, Result, Status};
use tracing::info;

use bdk_wallet::bitcoin::Amount;
use protocol::protocol_musig_adaptor::{BMPContext, BMPProtocol, ProtocolRole, Round1Parameter};
use protocol::wallet_service::WalletService;

use crate::pb::bmp_protocol::bmp_protocol_service_server::BmpProtocolService;
use crate::pb::bmp_protocol::{self, InitializeRequest, InitializeResponse, Role};
use crate::pb::convert::TryProtoInto as _;

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
        info!("Received initialize request: {:?}", req);

        //todo retrieve the actual wallet
        let mut mock_wallet = nigiri::funded_wallet();
        nigiri::fund_wallet(&mut mock_wallet);
        let wallet_service = WalletService::new().load(mock_wallet);

        let role =
            Role::try_from(req.role).map_err(|_| Status::invalid_argument("Unrecognised role"))?;
        let role = match role {
            Role::Seller => ProtocolRole::Seller,
            Role::Buyer => ProtocolRole::Buyer,
            _ => return Err(Status::invalid_argument("Role must be 'Seller' or 'Buyer'")),
        };

        let context = BMPContext::new(
            wallet_service,
            role,
            Amount::from_sat(req.seller_amount_sats),
            Amount::from_sat(req.buyer_amount_sats),
        )
        .map_err(|e| Status::internal(e.to_string()))?;

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
            .ok_or_else(|| Status::not_found(format!("Trade not found: {}", trade_id)))?;

        let round1_result = protocol
            .round1()
            .map_err(|e| Status::aborted(e.to_string()))?;

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
            .ok_or_else(|| Status::not_found(format!("Trade not found: {}", trade_id)))?;

        let peer_round1_params: Round1Parameter =
            req.peer_round1_response.unwrap().try_proto_into()?;

        let round2_result = protocol
            .round2(peer_round1_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

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
            .ok_or_else(|| Status::not_found(format!("Trade not found: {}", trade_id)))?;

        let peer_round2_params = req.peer_round2_response.unwrap().try_proto_into()?;

        let round3_result = protocol
            .round3(peer_round2_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

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
            .ok_or_else(|| Status::not_found(format!("Trade not found: {}", trade_id)))?;

        let peer_round3_params = req.peer_round3_response.unwrap().try_proto_into()?;

        let round4_result = protocol
            .round4(peer_round3_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        Ok(Response::new(round4_result.try_into()?))
    }

    async fn execute_round5(
        &self,
        request: Request<bmp_protocol::Round5Request>,
    ) -> Result<Response<()>> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {}", trade_id)))?;

        let peer_round4_params = req.peer_round4_response.unwrap().try_proto_into()?;

        protocol
            .round5(peer_round4_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        Ok(Response::new(()))
    }
}
