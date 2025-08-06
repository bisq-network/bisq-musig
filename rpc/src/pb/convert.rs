use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::consensus::Encodable as _;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::{Address, Amount, Psbt, TapSighash, Txid};
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
    ExchangedAddresses, ExchangedNonces, ExchangedSigs, ProtocolErrorKind, Role,
};
use crate::storage::{ByRef, ByVal};
use crate::transaction::Receiver;
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
                self.try_into().map_err(|e| {
                    Status::invalid_argument(format!("could not decode {}: {e}", $err_msg))
                })
            }
        }
    };
}

macro_rules! empty_to_none {
    ($self:ident.$field:ident) => {
        if $self.$field.is_empty() {
            let name = stringify!($field);
            tracing::warn!(name, "Empty proto field.");
            None
        } else {
            Some($self.$field)
        }
    };
}

impl_try_proto_into_for_slice!(Point, "nonzero point");
impl_try_proto_into_for_slice!(PubNonce, "pub nonce");
impl_try_proto_into_for_slice!(Scalar, "nonzero scalar");
impl_try_proto_into_for_slice!(MaybeScalar, "scalar");
impl_try_proto_into_for_slice!(LiftedSignature, "signature");

impl TryProtoInto<Txid> for &[u8] {
    fn try_proto_into(self) -> Result<Txid> {
        Txid::from_slice(self)
            .map_err(|e| Status::invalid_argument(format!("could not decode txid: {e}")))
    }
}

impl TryProtoInto<TapSighash> for &[u8] {
    fn try_proto_into(self) -> Result<TapSighash> {
        TapSighash::from_slice(self)
            .map_err(|e| Status::invalid_argument(format!("could not decode sighash: {e}")))
    }
}

impl TryProtoInto<Psbt> for &[u8] {
    fn try_proto_into(self) -> Result<Psbt> {
        Psbt::deserialize(self)
            .map_err(|e| Status::invalid_argument(format!("could not decode PSBT: {e}")))
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

impl TryProtoInto<Receiver<NetworkUnchecked>> for ReceiverAddressAndAmount {
    fn try_proto_into(self) -> Result<Receiver<NetworkUnchecked>> {
        Ok(Receiver {
            address: self.address.try_proto_into()?,
            amount: Amount::from_sat(self.amount),
        })
    }
}

impl<T> TryProtoInto<T> for Vec<u8> where for<'a> &'a [u8]: TryProtoInto<T> {
    fn try_proto_into(self) -> Result<T> { (&self[..]).try_proto_into() }
}

impl<T> TryProtoInto<T> for String where for<'a> &'a str: TryProtoInto<T> {
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

type SentAddressesNoncesPair<'a> = (ExchangedAddresses<'a, ByRef>, ExchangedNonces<'a, ByRef>);

type ReceivedAddressesNoncesPair<'a> = (ExchangedAddresses<'a, ByVal, NetworkUnchecked>, ExchangedNonces<'a, ByVal>);

impl<'a> TryProtoInto<ReceivedAddressesNoncesPair<'a>> for NonceSharesMessage {
    fn try_proto_into(self) -> Result<ReceivedAddressesNoncesPair<'a>> {
        Ok((ExchangedAddresses {
            warning_tx_fee_bump_address:
            self.warning_tx_fee_bump_address.try_proto_into()?,
            redirect_tx_fee_bump_address:
            self.redirect_tx_fee_bump_address.try_proto_into()?,
            claim_tx_payout_address:
            empty_to_none!(self.claim_tx_payout_address).try_proto_into()?,
        }, ExchangedNonces {
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
            buyers_claim_tx_input_nonce_share:
            empty_to_none!(self.buyers_claim_tx_input_nonce_share).try_proto_into()?,
            sellers_claim_tx_input_nonce_share:
            empty_to_none!(self.sellers_claim_tx_input_nonce_share).try_proto_into()?,
        }))
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
            peers_claim_tx_input_partial_signature:
            empty_to_none!(self.peers_claim_tx_input_partial_signature).try_proto_into()?,
            swap_tx_input_partial_signature:
            self.swap_tx_input_partial_signature.try_proto_into()?,
            swap_tx_input_sighash:
            self.swap_tx_input_sighash.try_proto_into()?,
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

impl From<SentAddressesNoncesPair<'_>> for NonceSharesMessage {
    fn from((addresses, nonces): SentAddressesNoncesPair) -> Self {
        Self {
            // Use default value for the PSBT & redirection amount fields. TODO: A little hacky; consider refactoring proto.
            half_deposit_psbt: Vec::default(),
            redirection_amount_msat: 0,
            // Addresses...
            warning_tx_fee_bump_address: addresses.warning_tx_fee_bump_address.to_string(),
            redirect_tx_fee_bump_address: addresses.redirect_tx_fee_bump_address.to_string(),
            claim_tx_payout_address: addresses.claim_tx_payout_address.map(Address::to_string).unwrap_or_default(),
            // Actual nonce shares...
            swap_tx_input_nonce_share:
            nonces.swap_tx_input_nonce_share.serialize().into(),
            buyers_warning_tx_buyer_input_nonce_share:
            nonces.buyers_warning_tx_buyer_input_nonce_share.serialize().into(),
            buyers_warning_tx_seller_input_nonce_share:
            nonces.buyers_warning_tx_seller_input_nonce_share.serialize().into(),
            sellers_warning_tx_buyer_input_nonce_share:
            nonces.sellers_warning_tx_buyer_input_nonce_share.serialize().into(),
            sellers_warning_tx_seller_input_nonce_share:
            nonces.sellers_warning_tx_seller_input_nonce_share.serialize().into(),
            buyers_redirect_tx_input_nonce_share:
            nonces.buyers_redirect_tx_input_nonce_share.serialize().into(),
            sellers_redirect_tx_input_nonce_share:
            nonces.sellers_redirect_tx_input_nonce_share.serialize().into(),
            buyers_claim_tx_input_nonce_share:
            nonces.buyers_claim_tx_input_nonce_share.map(|n| n.serialize().into()).unwrap_or_default(),
            sellers_claim_tx_input_nonce_share:
            nonces.sellers_claim_tx_input_nonce_share.map(|n| n.serialize().into()).unwrap_or_default(),
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
            peers_claim_tx_input_partial_signature:
            value.peers_claim_tx_input_partial_signature.map(|s| s.serialize().into()).unwrap_or_default(),
            swap_tx_input_partial_signature:
            value.swap_tx_input_partial_signature.map(|s| s.serialize().into()),
            swap_tx_input_sighash:
            value.swap_tx_input_sighash.map(|s| s.as_byte_array().into()),
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
            tx_id: value.outpoint.txid.to_byte_array().into(),
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
                    block_hash: anchor.block_id.hash.to_byte_array().into(),
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
