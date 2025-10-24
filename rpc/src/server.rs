use std::fmt::{Display, Formatter};
use std::marker::{Send, Sync};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bdk_wallet::bitcoin::{consensus, Amount, FeeRate};
use bdk_wallet::serde_json;
use drop_stream::DropStreamExt as _;
use futures_util::stream::{self, BoxStream, Stream, StreamExt as _, TryStream, TryStreamExt as _};
use serde::Serialize;
use tokio::time::{self, Duration};
use tonic::{Request, Response, Result, Status};
use tracing::{debug, error, info, instrument, trace, Span};

use crate::pb::convert::{CheckInSignedRange as _, TryProtoInto};
pub use crate::pb::musigrpc::musig_server::MusigServer;
use crate::pb::musigrpc::{
    musig_server, CloseTradeRequest, CloseTradeResponse, DepositPsbt, DepositTxSignatureRequest,
    NonceSharesMessage, NonceSharesRequest, PartialSignaturesMessage, PartialSignaturesRequest,
    PubKeySharesRequest, PubKeySharesResponse, PublishDepositTxRequest,
    SubscribeTxConfirmationStatusRequest, SwapTxSignatureRequest, SwapTxSignatureResponse,
    TxConfirmationStatus,
};
pub use crate::pb::walletrpc::wallet_server::WalletServer;
use crate::pb::walletrpc::{
    wallet_server, ConfEvent, ConfRequest, ListUnspentRequest, ListUnspentResponse,
    NewAddressRequest, NewAddressResponse, WalletBalanceRequest, WalletBalanceResponse,
};
use crate::protocol::{TradeModel, TradeModelStore as _, TRADE_MODELS};
use crate::wallet::WalletService;

#[derive(Debug, Default)]
pub struct MusigImpl {}

#[tonic::async_trait]
impl musig_server::Musig for MusigImpl {
    #[instrument(skip_all)]
    async fn init_trade(&self, request: Request<PubKeySharesRequest>) -> Result<Response<PubKeySharesResponse>> {
        handle_request(request, move |request| {
            let mut trade_model = TradeModel::new(request.trade_id, request.my_role.try_proto_into()?);
            trade_model.init_my_key_shares()?;
            let my_key_shares = trade_model.get_my_key_shares()
                .ok_or_else(|| Status::internal("missing key shares"))?;
            let response = PubKeySharesResponse {
                buyer_output_pub_key_share: my_key_shares[0].pub_key.serialize().into(),
                seller_output_pub_key_share: my_key_shares[1].pub_key.serialize().into(),
                current_block_height: 900_000,
            };
            TRADE_MODELS.add_trade_model(trade_model);

            Ok(response)
        })
    }

    #[instrument(skip_all)]
    async fn get_nonce_shares(&self, request: Request<NonceSharesRequest>) -> Result<Response<NonceSharesMessage>> {
        handle_musig_request(request, move |request, trade_model| {
            trade_model.set_peer_key_shares(
                request.buyer_output_peers_pub_key_share.try_proto_into()?,
                request.seller_output_peers_pub_key_share.try_proto_into()?)?;
            trade_model.aggregate_key_shares()?;
            trade_model.set_trade_amount(
                Amount::from_sat(request.trade_amount.check_in_signed_range()?));
            trade_model.set_buyers_security_deposit(
                Amount::from_sat(request.buyers_security_deposit.check_in_signed_range()?));
            trade_model.set_sellers_security_deposit(
                Amount::from_sat(request.sellers_security_deposit.check_in_signed_range()?));
            trade_model.set_deposit_tx_fee_rate(
                FeeRate::from_sat_per_kwu(request.deposit_tx_fee_rate.check_in_signed_range()?));
            trade_model.set_prepared_tx_fee_rate(
                FeeRate::from_sat_per_kwu(request.prepared_tx_fee_rate.check_in_signed_range()?));
            trade_model.set_trade_fee_receiver(request.trade_fee_receiver.try_proto_into()?)?;
            trade_model.init_my_addresses()?;
            trade_model.init_my_half_deposit_psbt()?;
            trade_model.init_my_nonce_shares()?;

            let redirection_amount_msat = trade_model.redirection_amount_msat()
                .and_then(|amount| amount.check_in_signed_range().ok())
                .ok_or_else(|| Status::internal("missing redirection amount"))?;
            let my_addresses = trade_model.get_my_addresses()
                .ok_or_else(|| Status::internal("missing addresses"))?;
            let my_half_deposit_psbt = trade_model.get_my_half_deposit_psbt()
                .ok_or_else(|| Status::internal("missing half deposit PSBT"))?;
            let my_nonce_shares = trade_model.get_my_nonce_shares()
                .ok_or_else(|| Status::internal("missing nonce shares"))?;

            Ok(NonceSharesMessage {
                half_deposit_psbt: my_half_deposit_psbt.serialize(),
                redirection_amount_msat,
                ..(my_addresses, my_nonce_shares).into()
            })
        })
    }

    #[instrument(skip_all)]
    async fn get_partial_signatures(&self, request: Request<PartialSignaturesRequest>) -> Result<Response<PartialSignaturesMessage>> {
        handle_musig_request(request, move |request, trade_model| {
            if let Some(my_partial_signatures) = trade_model
                .get_my_partial_signatures_on_peer_txs(request.buyer_ready_to_release) {
                // Ignore receiver list and peer's nonce shares, as they have already been set
                // (otherwise we wouldn't already have the partial signatures on the peer's txs).
                return Ok(my_partial_signatures.into());
            }
            let peer_nonce_shares = request.peers_nonce_shares
                .ok_or_else(|| Status::not_found("missing request.peers_nonce_shares"))?;
            trade_model.set_peer_half_deposit_psbt((&peer_nonce_shares.half_deposit_psbt[..]).try_proto_into()?);
            trade_model.compute_unsigned_deposit_tx()?;
            trade_model.set_redirection_receivers(request.redirection_receivers.into_iter().map(TryProtoInto::try_proto_into))?;
            trade_model.check_redirect_tx_params()?;
            let (addresses, nonce_shares) = peer_nonce_shares.try_proto_into()?;
            trade_model.set_peer_addresses(addresses)?;
            trade_model.compute_unsigned_prepared_txs()?;
            trade_model.set_peer_nonce_shares(nonce_shares);
            trade_model.aggregate_nonce_shares()?;
            trade_model.sign_partial()?;
            let my_partial_signatures = trade_model
                .get_my_partial_signatures_on_peer_txs(request.buyer_ready_to_release)
                .ok_or_else(|| Status::internal("missing partial signatures"))?;

            Ok(my_partial_signatures.into())
        })
    }

    #[instrument(skip_all)]
    async fn sign_deposit_tx(&self, request: Request<DepositTxSignatureRequest>) -> Result<Response<DepositPsbt>> {
        handle_musig_request(request, move |request, trade_model| {
            let peers_partial_signatures = request.peers_partial_signatures
                .ok_or_else(|| Status::not_found("missing request.peers_partial_signatures"))?;
            if trade_model.am_buyer() {
                let sighash = peers_partial_signatures.swap_tx_input_sighash.as_ref()
                    .ok_or_else(|| Status::not_found("missing request.peers_partial_signatures.swap_tx_input_sighash"))?;
                trade_model.sign_swap_tx_input_partial((&sighash[..]).try_proto_into()?)?;
            }
            trade_model.set_peer_partial_signatures_on_my_txs(&peers_partial_signatures.try_proto_into()?);
            trade_model.aggregate_partial_signatures()?;
            trade_model.compute_my_signed_prepared_txs()?;
            trade_model.sign_deposit_psbt()?;
            let deposit_psbt = trade_model.get_deposit_psbt()
                .ok_or_else(|| Status::internal("missing deposit PSBT"))?;

            Ok(DepositPsbt { deposit_psbt: deposit_psbt.serialize() })
        })
    }

    type PublishDepositTxStream = TracedResultStream<TxConfirmationStatus>;

    #[instrument(skip_all)]
    async fn publish_deposit_tx(&self, request: Request<PublishDepositTxRequest>) -> Result<Response<Self::PublishDepositTxStream>> {
        handle_musig_request(request, move |request, trade_model| {
            let peers_deposit_psbt = request.peers_deposit_psbt
                .ok_or_else(|| Status::not_found("missing request.peers_deposit_psbt"))?;
            trade_model.combine_deposit_psbts(peers_deposit_psbt.deposit_psbt.try_proto_into()?)?;
            let deposit_tx = trade_model.get_signed_deposit_tx()
                .ok_or_else(|| Status::internal("missing signed deposit tx"))?;

            info!("*** BROADCAST DEPOSIT TX ***"); // TODO: Implement broadcast.

            Ok(mock_tx_confirmation_status_stream(request.trade_id,
                consensus::serialize(&deposit_tx)).box_traced())
        })
    }

    type SubscribeTxConfirmationStatusStream = TracedResultStream<TxConfirmationStatus>;

    #[instrument(skip_all)]
    async fn subscribe_tx_confirmation_status(&self, request: Request<SubscribeTxConfirmationStatusRequest>)
                                              -> Result<Response<Self::SubscribeTxConfirmationStatusStream>> {
        handle_musig_request(request, move |request, _trade_model| {
            Ok(mock_tx_confirmation_status_stream(request.trade_id,
                b"signed_deposit_tx".into()).box_traced())
        })
    }

    #[instrument(skip_all)]
    async fn sign_swap_tx(&self, request: Request<SwapTxSignatureRequest>) -> Result<Response<SwapTxSignatureResponse>> {
        handle_musig_request(request, move |request, trade_model| {
            if trade_model.am_buyer() {
                return Err(Status::failed_precondition("operation only available for seller"));
            }
            let swap_tx = if let Some(swap_tx) = trade_model.get_signed_swap_tx() { swap_tx } else {
                trade_model.set_swap_tx_input_peers_partial_signature(
                    request.swap_tx_input_peers_partial_signature.try_proto_into()?);
                trade_model.aggregate_swap_tx_partial_signatures()?;
                trade_model.compute_signed_swap_tx()?;
                trade_model.get_signed_swap_tx()
                    .ok_or_else(|| Status::internal("missing signed swap tx"))?
            };
            let prv_key_share = trade_model.get_my_private_key_share_for_peer_output()
                .ok_or_else(|| Status::internal("missing private key share"))?;

            if !request.seller_ready_to_release {
                return Ok(SwapTxSignatureResponse::default());
            }
            Ok(SwapTxSignatureResponse {
                swap_tx: consensus::serialize(swap_tx),
                peer_output_prv_key_share: prv_key_share.serialize().into(),
            })
        })
    }

    #[instrument(skip_all)]
    async fn close_trade(&self, request: Request<CloseTradeRequest>) -> Result<Response<CloseTradeResponse>> {
        handle_musig_request(request, move |request, trade_model| {
            if let Some(peer_prv_key_share) = request.my_output_peers_prv_key_share.try_proto_into()? {
                // Trader receives the private key share from a cooperative peer, closing our trade.
                trade_model.set_peer_private_key_share_for_my_output(peer_prv_key_share)?;
                trade_model.aggregate_private_keys_for_my_output()?;
            } else if let Some(swap_tx) = request.swap_tx.try_proto_into()? {
                // Buyer supplies a signed swap tx to the Rust server, to close our trade. (Mainly for
                // testing -- normally the tx would be picked up from the bitcoin network by the server.)
                trade_model.recover_seller_private_key_share_for_buyer_output(&swap_tx)?;
                trade_model.aggregate_private_keys_for_my_output()?;
            } else {
                // Peer unresponsive -- force-close our trade by publishing the swap tx. For seller only.
                info!("*** BROADCAST SWAP TX ***"); // TODO: Implement broadcast.
            }
            let my_prv_key_share = trade_model.get_my_private_key_share_for_peer_output()
                .ok_or_else(|| Status::internal("missing private key share"))?;

            Ok(CloseTradeResponse { peer_output_prv_key_share: my_prv_key_share.serialize().into() })
        })
    }
}

fn mock_tx_confirmation_status_stream(trade_id: String, tx: Vec<u8>) -> impl Stream<Item=Result<TxConfirmationStatus>> {
    let confirmation_event = TxConfirmationStatus {
        tx,
        current_block_height: 900_001,
        num_confirmations: 1,
    };
    stream::once(async {
        time::sleep(Duration::from_secs(5)).await;
        Ok(confirmation_event)
    }).on_drop(move || debug!(trade_id, "Deposit tx confirmation status stream has been dropped."))
}

pub struct WalletImpl {
    pub wallet_service: Arc<dyn WalletService + Send + Sync>,
}

#[tonic::async_trait]
impl wallet_server::Wallet for WalletImpl {
    #[instrument(skip_all)]
    async fn wallet_balance(&self, request: Request<WalletBalanceRequest>) -> Result<Response<WalletBalanceResponse>> {
        handle_request(request, |_request| Ok(self.wallet_service.balance().into()))
    }

    #[instrument(skip_all)]
    async fn new_address(&self, request: Request<NewAddressRequest>) -> Result<Response<NewAddressResponse>> {
        handle_request(request, |_request| {
            let address = self.wallet_service.reveal_next_address();

            Ok(NewAddressResponse {
                address: address.address.to_string(),
                derivation_path: format!("m/86'/1'/0'/0/{}", address.index),
            })
        })
    }

    #[instrument(skip_all)]
    async fn list_unspent(&self, request: Request<ListUnspentRequest>) -> Result<Response<ListUnspentResponse>> {
        handle_request(request, |_request| {
            let utxos: Vec<_> = self.wallet_service.list_unspent().into_iter()
                .map(Into::into)
                .collect();

            Ok(ListUnspentResponse { utxos })
        })
    }

    type RegisterConfidenceNtfnStream = TracedResultStream<ConfEvent>;

    #[instrument(skip_all)]
    async fn register_confidence_ntfn(&self, request: Request<ConfRequest>) -> Result<Response<Self::RegisterConfidenceNtfnStream>> {
        handle_request(request, move |request| {
            let txid = request.tx_id.try_proto_into()?;
            let conf_events = self.wallet_service.get_tx_confidence_stream(txid)
                .map(|o| Ok(o.map(Into::into).unwrap_or_default()))
                .box_traced();

            Ok(conf_events)
        })
    }
}

struct LazyJson<T>(T);

impl<T: Serialize> Display for LazyJson<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = if f.alternate() {
            serde_json::to_string_pretty(&self.0)
        } else {
            serde_json::to_string(&self.0)
        };
        write!(f, "{}", s.as_deref().unwrap_or("<<SERIALIZATION ERROR>>"))
    }
}

#[derive(Serialize)]
pub struct TracedResultStream<T> {
    #[serde(skip)]
    inner: BoxStream<'static, Result<T>>,
    #[serde(skip)]
    span: Span,
}

impl<T> Stream for TracedResultStream<T> {
    type Item = Result<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let _enter = this.span.enter();
        Pin::new(&mut this.inner).poll_next(cx)
    }
}

pub trait TracedResultStreamExt<T: Serialize>: TryStream<Ok=T, Error=Status> + Sized + Send + 'static {
    fn box_traced(self) -> TracedResultStream<T> {
        TracedResultStream {
            inner: Box::pin(self.inspect_ok(move |event| {
                let message = LazyJson(event);
                trace!(%message, "Streaming event.");
            })),
            span: Span::current(),
        }
    }
}

impl<S> TracedResultStreamExt<S::Ok> for S
    where S: TryStream<Error=Status> + Sized + Send + 'static,
          S::Ok: Serialize {}

trait MusigRequest: Serialize {
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
impl_musig_req!(SubscribeTxConfirmationStatusRequest);
impl_musig_req!(SwapTxSignatureRequest);
impl_musig_req!(CloseTradeRequest);

// TODO: These wrapper fns don't work with async handlers, and should eventually be changed to do so:

fn handle_musig_request<Req, Res, F>(request: Request<Req>, handler: F) -> Result<Response<Res>>
    where Req: MusigRequest,
          Res: Serialize,
          F: FnOnce(Req, &mut TradeModel) -> Result<Res> {
    handle_request(request, move |request| {
        let trade_model = TRADE_MODELS.get_trade_model(request.trade_id())
            .ok_or_else(|| Status::not_found(format!("missing trade with id: {}", request.trade_id())))?;
        let response = handler(request, &mut trade_model.lock().unwrap())?;

        Ok(response)
    })
}

fn handle_request<Req, Res, F>(request: Request<Req>, handler: F) -> Result<Response<Res>>
    where Req: Serialize,
          Res: Serialize,
          F: FnOnce(Req) -> Result<Res> {
    let message = LazyJson(request.get_ref());
    debug!(%message, "Got a request.");

    let response = handler(request.into_inner())
        .inspect_err(|e| error!("Error response: {e}"))?;

    let message = LazyJson(&response);
    trace!(%message, "Sending response.");
    Ok(Response::new(response))
}
