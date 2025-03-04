mod protocol;
mod storage;

use futures::stream;
use musig2::{LiftedSignature, PubNonce};
use musigrpc::{CloseTradeRequest, CloseTradeResponse, DepositPsbt, DepositTxSignatureRequest,
    NonceSharesMessage, NonceSharesRequest, PartialSignaturesMessage, PartialSignaturesRequest,
    PubKeySharesRequest, PubKeySharesResponse, PublishDepositTxRequest, SwapTxSignatureRequest,
    SwapTxSignatureResponse, TxConfirmationStatus};
use musigrpc::musig_server::{Musig, MusigServer};
use prost::UnknownEnumValue;
use secp::{Point, MaybeScalar, Scalar};
use std::iter;
use std::pin::Pin;
use std::prelude::rust_2021::*;
use tonic::{Request, Response, Status};
use tonic::transport::Server;

use crate::protocol::{ExchangedNonces, ExchangedSigs, ProtocolErrorKind, Role, TradeModel,
    TradeModelStore as _, TRADE_MODELS};
use crate::storage::{ByRef, ByVal};

pub mod musigrpc {
    #![allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
    tonic::include_proto!("musigrpc");
}

#[derive(Debug, Default)]
pub struct MusigImpl {}

// FIXME: At present, the Musig service passes some fields to the Java client that should be kept
//  secret for a time before passing them to the peer, namely the buyer's partial signature on the
//  swap tx and the seller's private key share for the buyer payout. Premature revelation of those
//  secrets would allow the seller to close the trade before the buyer starts payment, or the buyer
//  to close the trade before the seller had a chance to confirm receipt of payment (but after the
//  buyer starts payment), respectively. This should probably be changed, as the Java client should
//  never hold secrets which directly control funds (but doing so makes the RPC interface a little
//  bigger and less symmetrical.)
#[tonic::async_trait]
impl Musig for MusigImpl {
    async fn init_trade(&self, request: Request<PubKeySharesRequest>) -> Result<Response<PubKeySharesResponse>> {
        println!("Got a request: {:?}", request);

        let request = request.into_inner();
        let mut trade_model = TradeModel::new(request.trade_id, request.my_role.my_try_into()?);
        trade_model.init_my_key_shares();
        let my_key_shares = trade_model.get_my_key_shares()
            .ok_or_else(|| Status::internal("missing key shares"))?;
        let response = PubKeySharesResponse {
            buyer_output_pub_key_share: my_key_shares[0].pub_key.serialize().into(),
            seller_output_pub_key_share: my_key_shares[1].pub_key.serialize().into(),
            current_block_height: 900_000,
        };
        TRADE_MODELS.add_trade_model(trade_model);

        Ok(Response::new(response))
    }

    async fn get_nonce_shares(&self, request: Request<NonceSharesRequest>) -> Result<Response<NonceSharesMessage>> {
        handle_request(request, move |request, trade_model| {
            trade_model.set_peer_key_shares(
                request.buyer_output_peers_pub_key_share.my_try_into()?,
                request.seller_output_peers_pub_key_share.my_try_into()?);
            trade_model.aggregate_key_shares()?;
            trade_model.init_my_nonce_shares()?;
            trade_model.trade_amount = Some(request.trade_amount);
            trade_model.buyers_security_deposit = Some(request.buyers_security_deposit);
            trade_model.sellers_security_deposit = Some(request.sellers_security_deposit);
            trade_model.deposit_tx_fee_rate = Some(request.deposit_tx_fee_rate);
            trade_model.prepared_tx_fee_rate = Some(request.prepared_tx_fee_rate);
            let my_nonce_shares = trade_model.get_my_nonce_shares()
                .ok_or_else(|| Status::internal("missing nonce shares"))?;

            Ok(NonceSharesMessage {
                warning_tx_fee_bump_address: "address1".to_owned(),
                redirect_tx_fee_bump_address: "address2".to_owned(),
                half_deposit_psbt: vec![],
                ..my_nonce_shares.into()
            })
        })
    }

    async fn get_partial_signatures(&self, request: Request<PartialSignaturesRequest>) -> Result<Response<PartialSignaturesMessage>> {
        handle_request(request, move |request, trade_model| {
            let peer_nonce_shares = request.peers_nonce_shares
                .ok_or_else(|| Status::not_found("missing request.peers_nonce_shares"))?;
            trade_model.set_peer_nonce_shares(peer_nonce_shares.my_try_into()?);
            trade_model.aggregate_nonce_shares()?;
            trade_model.sign_partial()?;
            let my_partial_signatures = trade_model.get_my_partial_signatures_on_peer_txs()
                .ok_or_else(|| Status::internal("missing partial signatures"))?;

            Ok(my_partial_signatures.into())
        })
    }

    async fn sign_deposit_tx(&self, request: Request<DepositTxSignatureRequest>) -> Result<Response<DepositPsbt>> {
        handle_request(request, move |request, trade_model| {
            let peers_partial_signatures = request.peers_partial_signatures
                .ok_or_else(|| Status::not_found("missing request.peers_partial_signatures"))?;
            trade_model.set_peer_partial_signatures_on_my_txs(&peers_partial_signatures.my_try_into()?);
            trade_model.aggregate_partial_signatures()?;

            Ok(DepositPsbt { deposit_psbt: b"deposit_psbt".into() })
        })
    }

    type PublishDepositTxStream = Pin<Box<dyn stream::Stream<Item=Result<TxConfirmationStatus>> + Send>>;

    async fn publish_deposit_tx(&self, request: Request<PublishDepositTxRequest>) -> Result<Response<Self::PublishDepositTxStream>> {
        handle_request(request, move |_request, _trade_model| {
            // TODO: *** BROADCAST DEPOSIT TX ***

            let confirmation_event = TxConfirmationStatus {
                tx: b"signed_deposit_tx".into(),
                current_block_height: 900_001,
                num_confirmations: 1,
            };

            let stream: Self::PublishDepositTxStream = Box::pin(stream::iter(iter::once(Ok(confirmation_event))));
            Ok(stream)
        })
    }

    async fn sign_swap_tx(&self, request: Request<SwapTxSignatureRequest>) -> Result<Response<SwapTxSignatureResponse>> {
        handle_request(request, move |request, trade_model| {
            trade_model.set_swap_tx_input_peers_partial_signature(request.swap_tx_input_peers_partial_signature.my_try_into()?);
            trade_model.aggregate_swap_tx_partial_signatures()?;
            let sig = trade_model.compute_swap_tx_input_signature()?;
            let prv_key_share = trade_model.get_my_private_key_share_for_peer_output()
                .ok_or_else(|| Status::internal("missing private key share"))?;

            Ok(SwapTxSignatureResponse {
                // For now, just set 'swap_tx' to be the (final) swap tx signature, rather than the actual signed tx:
                swap_tx: sig.serialize().into(),
                peer_output_prv_key_share: prv_key_share.serialize().into(),
            })
        })
    }

    async fn close_trade(&self, request: Request<CloseTradeRequest>) -> Result<Response<CloseTradeResponse>> {
        handle_request(request, move |request, trade_model| {
            if let Some(peer_prv_key_share) = request.my_output_peers_prv_key_share.my_try_into()? {
                // Trader receives the private key share from a cooperative peer, closing our trade.
                trade_model.set_peer_private_key_share_for_my_output(peer_prv_key_share)?;
                trade_model.aggregate_private_keys_for_my_output()?;
            } else if let Some(swap_tx_input_signature) = request.swap_tx.my_try_into()? {
                // Buyer supplies a signed swap tx to the Rust server, to close our trade. (Mainly for
                // testing -- normally the tx would be picked up from the bitcoin network by the server.)
                trade_model.recover_seller_private_key_share_for_buyer_output(&swap_tx_input_signature)?;
                trade_model.aggregate_private_keys_for_my_output()?;
            } else {
                // Peer unresponsive -- force-close our trade by publishing the swap tx. For seller only.
                // TODO: *** BROADCAST SWAP TX ***
            }
            let my_prv_key_share = trade_model.get_my_private_key_share_for_peer_output()
                .ok_or_else(|| Status::internal("missing private key share"))?;

            Ok(CloseTradeResponse { peer_output_prv_key_share: my_prv_key_share.serialize().into() })
        })
    }
}

trait MusigRequest: std::fmt::Debug {
    fn trade_id(&self) -> &str;
}

macro_rules! impl_musig_req {
    ($request_type:ty) => {
        impl MusigRequest for $request_type {
            fn trade_id(&self) -> &str { &self.trade_id }
        }
    };
}

impl_musig_req!(PartialSignaturesRequest);
impl_musig_req!(NonceSharesRequest);
impl_musig_req!(DepositTxSignatureRequest);
impl_musig_req!(PublishDepositTxRequest);
impl_musig_req!(SwapTxSignatureRequest);
impl_musig_req!(CloseTradeRequest);

fn handle_request<Req, Res, F>(request: Request<Req>, handler: F) -> Result<Response<Res>>
    where Req: MusigRequest,
          F: FnOnce(Req, &mut TradeModel) -> Result<Res> {
    println!("Got a request: {:?}", request);

    let request = request.into_inner();
    let trade_model = TRADE_MODELS.get_trade_model(request.trade_id())
        .ok_or_else(|| Status::not_found(format!("missing trade with id: {}", request.trade_id())))?;
    let response = handler(request, &mut trade_model.lock().unwrap())?;

    Ok(Response::new(response))
}

type Result<T, E = Status> = std::result::Result<T, E>;

impl From<musigrpc::Role> for Role {
    fn from(value: musigrpc::Role) -> Self {
        match value {
            musigrpc::Role::SellerAsMaker => Self::SellerAsMaker,
            musigrpc::Role::SellerAsTaker => Self::SellerAsTaker,
            musigrpc::Role::BuyerAsMaker => Self::BuyerAsMaker,
            musigrpc::Role::BuyerAsTaker => Self::BuyerAsTaker
        }
    }
}

impl From<ProtocolErrorKind> for Status {
    fn from(value: ProtocolErrorKind) -> Self {
        Self::internal(value.to_string())
    }
}

trait MyTryInto<T> {
    fn my_try_into(self) -> Result<T>;
}

macro_rules! impl_my_try_into_for_slice {
    ($into_type:ty, $err_msg:literal) => {
        impl MyTryInto<$into_type> for &[u8] {
            fn my_try_into(self) -> Result<$into_type> {
                self.try_into().map_err(|_| Status::invalid_argument($err_msg))
            }
        }
    }
}

impl_my_try_into_for_slice!(Point, "could not decode nonzero point");
impl_my_try_into_for_slice!(PubNonce, "could not decode pub nonce");
impl_my_try_into_for_slice!(Scalar, "could not decode nonzero scalar");
impl_my_try_into_for_slice!(MaybeScalar, "could not decode scalar");
impl_my_try_into_for_slice!(LiftedSignature, "could not decode signature");

impl MyTryInto<Role> for i32 {
    fn my_try_into(self) -> Result<Role> {
        TryInto::<musigrpc::Role>::try_into(self)
            .map_err(|UnknownEnumValue(i)| Status::out_of_range(format!("unknown enum value: {}", i)))
            .map(Into::into)
    }
}

impl<T> MyTryInto<T> for Vec<u8> where for<'a> &'a [u8]: MyTryInto<T> {
    fn my_try_into(self) -> Result<T> { (&self[..]).my_try_into() }
}

impl<T, S: MyTryInto<T>> MyTryInto<Option<T>> for Option<S> {
    fn my_try_into(self) -> Result<Option<T>> {
        Ok(match self {
            None => None,
            Some(x) => Some(x.my_try_into()?)
        })
    }
}

impl From<ExchangedNonces<'_, ByRef>> for NonceSharesMessage {
    fn from(value: ExchangedNonces<ByRef>) -> Self {
        NonceSharesMessage {
            // Use default values for proto fields besides the nonce shares. TODO: A little hacky; consider refactoring proto.
            warning_tx_fee_bump_address: String::default(),
            redirect_tx_fee_bump_address: String::default(),
            half_deposit_psbt: Vec::default(),
            // Actual nonce shares...
            swap_tx_input_nonce_share:
            value.swap_tx_input_nonce_share.serialize().into(),
            buyers_warning_tx_buyer_input_nonce_share:
            value.buyers_warning_tx_buyer_input_nonce_share.serialize().into(),
            buyers_warning_tx_seller_input_nonce_share:
            value.buyers_warning_tx_seller_input_nonce_share.serialize().into(),
            sellers_warning_tx_buyer_input_nonce_share:
            value.sellers_warning_tx_buyer_input_nonce_share.serialize().into(),
            sellers_warning_tx_seller_input_nonce_share:
            value.sellers_warning_tx_seller_input_nonce_share.serialize().into(),
            buyers_redirect_tx_input_nonce_share:
            value.buyers_redirect_tx_input_nonce_share.serialize().into(),
            sellers_redirect_tx_input_nonce_share:
            value.sellers_redirect_tx_input_nonce_share.serialize().into(),
        }
    }
}

impl<'a> MyTryInto<ExchangedNonces<'a, ByVal>> for NonceSharesMessage {
    fn my_try_into(self) -> Result<ExchangedNonces<'a, ByVal>> {
        Ok(ExchangedNonces {
            swap_tx_input_nonce_share:
            self.swap_tx_input_nonce_share.my_try_into()?,
            buyers_warning_tx_buyer_input_nonce_share:
            self.buyers_warning_tx_buyer_input_nonce_share.my_try_into()?,
            buyers_warning_tx_seller_input_nonce_share:
            self.buyers_warning_tx_seller_input_nonce_share.my_try_into()?,
            sellers_warning_tx_buyer_input_nonce_share:
            self.sellers_warning_tx_buyer_input_nonce_share.my_try_into()?,
            sellers_warning_tx_seller_input_nonce_share:
            self.sellers_warning_tx_seller_input_nonce_share.my_try_into()?,
            buyers_redirect_tx_input_nonce_share:
            self.buyers_redirect_tx_input_nonce_share.my_try_into()?,
            sellers_redirect_tx_input_nonce_share:
            self.sellers_redirect_tx_input_nonce_share.my_try_into()?,
        })
    }
}

impl From<ExchangedSigs<'_, ByRef>> for PartialSignaturesMessage {
    fn from(value: ExchangedSigs<ByRef>) -> Self {
        PartialSignaturesMessage {
            peers_warning_tx_buyer_input_partial_signature:
            value.peers_warning_tx_buyer_input_partial_signature.serialize().into(),
            peers_warning_tx_seller_input_partial_signature:
            value.peers_warning_tx_seller_input_partial_signature.serialize().into(),
            peers_redirect_tx_input_partial_signature:
            value.peers_redirect_tx_input_partial_signature.serialize().into(),
            swap_tx_input_partial_signature:
            value.swap_tx_input_partial_signature.map(|s| s.serialize().into()),
        }
    }
}

impl<'a> MyTryInto<ExchangedSigs<'a, ByVal>> for PartialSignaturesMessage {
    fn my_try_into(self) -> Result<ExchangedSigs<'a, ByVal>> {
        Ok(ExchangedSigs {
            peers_warning_tx_buyer_input_partial_signature:
            self.peers_warning_tx_buyer_input_partial_signature.my_try_into()?,
            peers_warning_tx_seller_input_partial_signature:
            self.peers_warning_tx_seller_input_partial_signature.my_try_into()?,
            peers_redirect_tx_input_partial_signature:
            self.peers_redirect_tx_input_partial_signature.my_try_into()?,
            swap_tx_input_partial_signature:
            self.swap_tx_input_partial_signature.my_try_into()?,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;
    let musig = MusigImpl::default();

    Server::builder()
        .add_service(MusigServer::new(musig))
        .serve(addr)
        .await?;

    Ok(())
}
