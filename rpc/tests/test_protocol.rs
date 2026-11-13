//! In-process tests for the `Musig` trade-protocol service.
//! These tests call `MusigImpl` directly without exercising gRPC transport.

use bdk_wallet::bitcoin::{Amount, Psbt};
use rpc::pb::musigrpc::musig_server::Musig as _;
use rpc::pb::musigrpc::{
    NonceSharesRequest, PartialSignaturesRequest, PubKeySharesRequest, PubKeySharesResponse,
    ReceiverAddressAndAmount, Role,
};
use rpc::server::MusigImpl;
use tonic::Request;

fn nonce_shares_request(trade_id: &str, peer_keys: &PubKeySharesResponse) -> NonceSharesRequest {
    NonceSharesRequest {
        trade_id: trade_id.to_owned(),
        buyer_output_peers_pub_key_share: peer_keys.buyer_output_pub_key_share.clone(),
        seller_output_peers_pub_key_share: peer_keys.seller_output_pub_key_share.clone(),
        peers_multisig_script_key: peer_keys.multisig_script_key.clone(),
        deposit_tx_fee_rate: 3_125,
        prepared_tx_fee_rate: 2_500,
        trade_amount: 200_000,
        buyers_security_deposit: 30_000,
        sellers_security_deposit: 30_000,
        trade_fee_receiver: Some(ReceiverAddressAndAmount {
            address: "bcrt1qwk6p86mzqmstcsg99qlu2mhsp3766u68jktv6k".to_owned(),
            amount: 5_000,
        }),
    }
}

fn redirection_receivers() -> Vec<ReceiverAddressAndAmount> {
    vec![
        ReceiverAddressAndAmount {
            address: "bcrt1phc8m8vansnl4utths947mjquprw20puwrrdfrwx8akeeu2tqwklsnxsvf0".to_owned(),
            amount: 160_000,
        },
        ReceiverAddressAndAmount {
            address: "bcrt1qwk6p86mzqmstcsg99qlu2mhsp3766u68jktv6k".to_owned(),
            amount: 80_000,
        },
        ReceiverAddressAndAmount {
            address: "2N2x2bA28AsLZZEHss4SjFoyToQV5YYZsJM".to_owned(),
            amount: 15_055,
        },
    ]
}

#[tokio::test]
async fn corrected_retry_after_invalid_peer_half_deposit_psbt_succeeds() {
    let svc = MusigImpl::default();
    let buyer_id = "peer-psbt-rpc-buyer";
    let seller_id = "peer-psbt-rpc-seller";

    let buyer_keys = svc
        .init_trade(Request::new(PubKeySharesRequest {
            trade_id: buyer_id.to_owned(),
            my_role: Role::BuyerAsTaker as i32,
        }))
        .await
        .unwrap()
        .into_inner();
    let seller_keys = svc
        .init_trade(Request::new(PubKeySharesRequest {
            trade_id: seller_id.to_owned(),
            my_role: Role::SellerAsMaker as i32,
        }))
        .await
        .unwrap()
        .into_inner();

    let seller_nonce = svc
        .get_nonce_shares(Request::new(nonce_shares_request(seller_id, &buyer_keys)))
        .await
        .unwrap()
        .into_inner();
    let buyer_nonce = svc
        .get_nonce_shares(Request::new(nonce_shares_request(buyer_id, &seller_keys)))
        .await
        .unwrap()
        .into_inner();

    let mut invalid_seller_nonce = seller_nonce.clone();
    let mut invalid_psbt = Psbt::deserialize(&invalid_seller_nonce.half_deposit_psbt)
    .expect("deserialize seller half-deposit PSBT");
    invalid_psbt.unsigned_tx.output[0].value = Amount::from_sat(1);
    invalid_seller_nonce.half_deposit_psbt = invalid_psbt.serialize();

    let first = svc
        .get_partial_signatures(Request::new(PartialSignaturesRequest {
            trade_id: buyer_id.to_owned(),
            peers_nonce_shares: Some(invalid_seller_nonce),
            redirection_receivers: redirection_receivers(),
            buyer_ready_to_release: false,
        }))
        .await
        .expect_err("invalid peer PSBT must be rejected");
    assert_eq!(first.message(), "invalid PSBT");

    let buyer_signatures = svc
        .get_partial_signatures(Request::new(PartialSignaturesRequest {
            trade_id: buyer_id.to_owned(),
            peers_nonce_shares: Some(seller_nonce),
            redirection_receivers: redirection_receivers(),
            buyer_ready_to_release: false,
        }))
        .await
        .expect("corrected PSBT retry must succeed")
        .into_inner();

    let seller_signatures = svc
        .get_partial_signatures(Request::new(PartialSignaturesRequest {
            trade_id: seller_id.to_owned(),
            peers_nonce_shares: Some(buyer_nonce),
            redirection_receivers: redirection_receivers(),
            buyer_ready_to_release: false,
        }))
        .await
        .expect("seller partial-signature request must succeed")
        .into_inner();

    assert!(
        !buyer_signatures
            .peers_warning_tx_buyer_input_partial_signature
            .is_empty()
    );
    assert!(
        !seller_signatures
            .peers_warning_tx_buyer_input_partial_signature
            .is_empty()
    );
}
