use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::consensus::Encodable as _;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::{Address, Amount, Txid};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::{Balance, LocalOutput};
use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::{LiftedSignature, PubNonce};
use prost::UnknownEnumValue;
use tonic::{Result, Status};

use crate::pb::musigrpc::{
    self, NonceSharesMessage, PartialSignaturesMessage, ReceiverAddressAndAmount,
};
use crate::pb::walletrpc::{
    ConfEvent, ConfidenceType, ConfirmationBlockTime, TransactionOutput, WalletBalanceResponse,
};
use crate::protocol::{
    ExchangedNonces, ExchangedSigs, ProtocolErrorKind, RedirectionReceiver, Role,
};
use crate::storage::{ByRef, ByVal};
use crate::wallet::TxConfidence;

pub(crate) mod hex {
    use serde::Serializer;
    use serde_with::formats::Lowercase;
    use serde_with::hex::Hex;
    use serde_with::SerializeAs;

    pub struct ByteReversedHex;

    impl<T: AsRef<[u8]>> SerializeAs<T> for ByteReversedHex {
        fn serialize_as<S: Serializer>(source: &T, serializer: S) -> Result<S::Ok, S::Error> {
            let mut source = source.as_ref().to_owned();
            source.reverse();
            Hex::<Lowercase>::serialize_as(&source, serializer)
        }
    }
}

pub trait TryProtoInto<T> {
    /// # Errors
    /// Will return `Err` if conversion from proto fails
    fn try_proto_into(self) -> Result<T>;
}

macro_rules! impl_try_proto_into_for_slice {
    ($into_type:ty, $err_msg:literal) => {
        impl TryProtoInto<$into_type> for &[u8] {
            fn try_proto_into(self) -> Result<$into_type> {
                self.try_into().map_err(|_| Status::invalid_argument($err_msg))
            }
        }
    };
}

impl_try_proto_into_for_slice!(Point, "could not decode nonzero point");
impl_try_proto_into_for_slice!(PubNonce, "could not decode pub nonce");
impl_try_proto_into_for_slice!(Scalar, "could not decode nonzero scalar");
impl_try_proto_into_for_slice!(MaybeScalar, "could not decode scalar");
impl_try_proto_into_for_slice!(LiftedSignature, "could not decode signature");

impl TryProtoInto<Txid> for &[u8] {
    fn try_proto_into(self) -> Result<Txid> {
        Txid::from_slice(self).map_err(|_| Status::invalid_argument("could not decode txid"))
    }
}

impl TryProtoInto<Role> for i32 {
    fn try_proto_into(self) -> Result<Role> {
        TryInto::<musigrpc::Role>::try_into(self)
            .map_err(|UnknownEnumValue(i)| Status::out_of_range(format!("unknown enum value: {i}")))
            .map(Into::into)
    }
}

impl TryProtoInto<Address<NetworkUnchecked>> for &str {
    fn try_proto_into(self) -> Result<Address<NetworkUnchecked>> {
        self.parse::<Address<_>>()
            .map_err(|e| Status::invalid_argument(format!("could not parse address: {e}")))
    }
}

impl TryProtoInto<RedirectionReceiver<NetworkUnchecked>> for ReceiverAddressAndAmount {
    fn try_proto_into(self) -> Result<RedirectionReceiver<NetworkUnchecked>> {
        Ok(RedirectionReceiver {
            address: self.address.try_proto_into()?,
            amount: Amount::from_sat(self.amount),
        })
    }
}

impl<T> TryProtoInto<T> for Vec<u8> where for<'a> &'a [u8]: TryProtoInto<T> {
    fn try_proto_into(self) -> Result<T> { (&self[..]).try_proto_into() }
}

impl<T, S: TryProtoInto<T>> TryProtoInto<Option<T>> for Option<S> {
    fn try_proto_into(self) -> Result<Option<T>> {
        Ok(match self {
            None => None,
            Some(x) => Some(x.try_proto_into()?)
        })
    }
}

impl<'a> TryProtoInto<ExchangedNonces<'a, ByVal>> for NonceSharesMessage {
    fn try_proto_into(self) -> Result<ExchangedNonces<'a, ByVal>> {
        Ok(ExchangedNonces {
            swap_tx_input_nonce_share:
            self.swap_tx_input_nonce_share.try_proto_into()?,
            buyers_warning_tx_buyer_input_nonce_share:
            self.buyers_warning_tx_buyer_input_nonce_share.try_proto_into()?,
            buyers_warning_tx_seller_input_nonce_share:
            self.buyers_warning_tx_seller_input_nonce_share.try_proto_into()?,
            sellers_warning_tx_buyer_input_nonce_share:
            self.sellers_warning_tx_buyer_input_nonce_share.try_proto_into()?,
            sellers_warning_tx_seller_input_nonce_share:
            self.sellers_warning_tx_seller_input_nonce_share.try_proto_into()?,
            buyers_redirect_tx_input_nonce_share:
            self.buyers_redirect_tx_input_nonce_share.try_proto_into()?,
            sellers_redirect_tx_input_nonce_share:
            self.sellers_redirect_tx_input_nonce_share.try_proto_into()?,
        })
    }
}

impl<'a> TryProtoInto<ExchangedSigs<'a, ByVal>> for PartialSignaturesMessage {
    fn try_proto_into(self) -> Result<ExchangedSigs<'a, ByVal>> {
        Ok(ExchangedSigs {
            peers_warning_tx_buyer_input_partial_signature:
            self.peers_warning_tx_buyer_input_partial_signature.try_proto_into()?,
            peers_warning_tx_seller_input_partial_signature:
            self.peers_warning_tx_seller_input_partial_signature.try_proto_into()?,
            peers_redirect_tx_input_partial_signature:
            self.peers_redirect_tx_input_partial_signature.try_proto_into()?,
            swap_tx_input_partial_signature:
            self.swap_tx_input_partial_signature.try_proto_into()?,
        })
    }
}

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

impl From<ExchangedNonces<'_, ByRef>> for NonceSharesMessage {
    fn from(value: ExchangedNonces<ByRef>) -> Self {
        Self {
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

impl From<ExchangedSigs<'_, ByRef>> for PartialSignaturesMessage {
    fn from(value: ExchangedSigs<ByRef>) -> Self {
        Self {
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

impl From<Balance> for WalletBalanceResponse {
    fn from(value: Balance) -> Self {
        Self {
            immature: value.immature.to_sat(),
            trusted_pending: value.trusted_pending.to_sat(),
            untrusted_pending: value.untrusted_pending.to_sat(),
            confirmed: value.confirmed.to_sat(),
        }
    }
}

impl From<LocalOutput> for TransactionOutput {
    fn from(value: LocalOutput) -> Self {
        Self {
            tx_id: value.outpoint.txid.as_byte_array().into(),
            vout: value.outpoint.vout,
            script_pub_key: value.txout.script_pubkey.into_bytes(),
            value: value.txout.value.to_sat(),
        }
    }
}

impl From<TxConfidence> for ConfEvent {
    fn from(TxConfidence { wallet_tx, num_confirmations }: TxConfidence) -> Self {
        let mut raw_tx = Vec::new();
        wallet_tx.tx.consensus_encode(&mut raw_tx).unwrap();
        let (confidence_type, confirmation_block_time) = match wallet_tx.chain_position {
            ChainPosition::Confirmed { anchor, .. } =>
                (ConfidenceType::Confirmed, Some(ConfirmationBlockTime {
                    block_hash: anchor.block_id.hash.as_byte_array().to_vec(),
                    block_height: anchor.block_id.height,
                    confirmation_time: anchor.confirmation_time,
                })),
            ChainPosition::Unconfirmed { .. } => (ConfidenceType::Unconfirmed, None)
        };
        Self {
            raw_tx: Some(raw_tx),
            confidence_type: confidence_type.into(),
            num_confirmations,
            confirmation_block_time,
        }
    }
}

impl From<ProtocolErrorKind> for Status {
    fn from(value: ProtocolErrorKind) -> Self {
        Self::internal(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::pb::walletrpc::{ConfEvent, ConfidenceType};

    #[test]
    fn conf_event_default() {
        let missing_tx_conf_event = ConfEvent {
            raw_tx: None,
            confidence_type: ConfidenceType::Missing.into(),
            num_confirmations: 0,
            confirmation_block_time: None,
        };
        assert_eq!(ConfEvent::default(), missing_tx_conf_event);
    }
}
