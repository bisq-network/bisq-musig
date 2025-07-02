use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use bdk_wallet::bitcoin::Amount;
use protocol::protocol_musig_adaptor::{
    BMPContext, BMPProtocol, MemWallet, ProtocolRole, Round1Parameter,
};
use protocol::wallet_service::WalletService;

use crate::pb::bmp_converter::TryProtoInto as _;
use crate::pb::bmp_protocol::bmp_protocol_service_server::BmpProtocolService;
use crate::pb::bmp_protocol::{self, InitializeRequest, InitializeResponse, Role};

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
    ) -> Result<Response<InitializeResponse>, Status> {
        let req = request.into_inner();

        //todo: this is just a mock wallet_service at the moment
        let mem_wallet = MemWallet::new().map_err(|e| Status::internal(e.to_string()))?;
        let wallet_service = WalletService::new().load(mem_wallet);

        let role = match Role::try_from(req.role).unwrap() {
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

        let trade_id = Uuid::new_v4().to_string();

        self.active_protocols
            .lock()
            .unwrap()
            .insert(trade_id.clone(), protocol);

        Ok(Response::new(InitializeResponse { trade_id }))
    }

    async fn execute_round1(
        &self,
        request: tonic::Request<bmp_protocol::Round1Request>,
    ) -> std::result::Result<tonic::Response<bmp_protocol::Round1Response>, tonic::Status> {
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
    ) -> Result<Response<bmp_protocol::Round2Response>, Status> {
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
        request: tonic::Request<bmp_protocol::Round3Request>,
    ) -> std::result::Result<tonic::Response<bmp_protocol::Round3Response>, tonic::Status> {
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
        request: tonic::Request<bmp_protocol::Round4Request>,
    ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
        let req = request.into_inner();
        let trade_id = req.trade_id;

        let mut protocols = self.active_protocols.lock().unwrap();
        let protocol = protocols
            .get_mut(&trade_id)
            .ok_or_else(|| Status::not_found(format!("Trade not found: {}", trade_id)))?;

        let peer_round3_params = req.peer_round3_response.unwrap().try_proto_into()?;

        protocol
            .round4(peer_round3_params)
            .map_err(|e| Status::aborted(e.to_string()))?;

        Ok(Response::new(()))
    }
}
