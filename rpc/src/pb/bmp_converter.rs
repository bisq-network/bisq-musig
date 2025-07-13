use crate::pb::bmp_protocol as bmp_pb;
use crate::pb::convert::TryProtoInto;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::{psbt::Psbt, ScriptBuf};
use protocol::protocol_musig_adaptor::{self as bmp_engine};
use tonic::{Result, Status};

impl TryProtoInto<bmp_engine::Round1Parameter> for bmp_pb::Round1Response {
    fn try_proto_into(self) -> Result<bmp_engine::Round1Parameter> {
        Ok(bmp_engine::Round1Parameter {
            p_a: self.p_a.as_slice().try_proto_into()?,
            q_a: self.q_a.as_slice().try_proto_into()?,
            dep_part_psbt: Psbt::deserialize(&self.dep_part_psbt).map_err(|e| {
                Status::invalid_argument(format!("Failed to deserialize Psbt: {e}"))
            })?,
            swap_script: self.swap_script.map(ScriptBuf::from_bytes),
            warn_anchor_spend: ScriptBuf::from_bytes(self.warn_anchor_spend),
            claim_spend: ScriptBuf::from_bytes(self.claim_spend),
            redirect_anchor_spend: ScriptBuf::from_bytes(self.redirect_anchor_spend),
        })
    }
}

impl TryFrom<bmp_engine::Round1Parameter> for bmp_pb::Round1Response {
    type Error = Status;
    fn try_from(value: bmp_engine::Round1Parameter) -> Result<Self, Self::Error> {
        Ok(Self {
            p_a: value.p_a.serialize().to_vec(),
            q_a: value.q_a.serialize().to_vec(),
            dep_part_psbt: value.dep_part_psbt.serialize(),
            swap_script: value
                .swap_script
                .map(bdk_wallet::bitcoin::ScriptBuf::into_bytes),
            warn_anchor_spend: value.warn_anchor_spend.into_bytes(),
            claim_spend: value.claim_spend.into_bytes(),
            redirect_anchor_spend: value.redirect_anchor_spend.into_bytes(),
        })
    }
}

impl TryFrom<bmp_engine::Round2Parameter> for bmp_pb::Round2Response {
    type Error = Status;
    fn try_from(value: bmp_engine::Round2Parameter) -> Result<Self, Self::Error> {
        Ok(Self {
            p_agg: value.p_agg.serialize().to_vec(),
            q_agg: value.q_agg.serialize().to_vec(),
            swap_pub_nonce: value.swap_pub_nonce.serialize().to_vec(),
            warn_alice_p_nonce: value.warn_alice_p_nonce.serialize().to_vec(),
            warn_alice_q_nonce: value.warn_alice_q_nonce.serialize().to_vec(),
            warn_bob_p_nonce: value.warn_bob_p_nonce.serialize().to_vec(),
            warn_bob_q_nonce: value.warn_bob_q_nonce.serialize().to_vec(),
            claim_alice_nonce: value.claim_alice_nonce.serialize().to_vec(),
            claim_bob_nonce: value.claim_bob_nonce.serialize().to_vec(),
            redirect_alice_nonce: value.redirect_alice_nonce.serialize().to_vec(),
            redirect_bob_nonce: value.redirect_bob_nonce.serialize().to_vec(),
        })
    }
}

impl TryProtoInto<bmp_engine::Round2Parameter> for bmp_pb::Round2Response {
    fn try_proto_into(self) -> Result<bmp_engine::Round2Parameter> {
        Ok(bmp_engine::Round2Parameter {
            p_agg: self.p_agg.as_slice().try_proto_into()?,
            q_agg: self.q_agg.as_slice().try_proto_into()?,
            swap_pub_nonce: self.swap_pub_nonce.as_slice().try_proto_into()?,
            warn_alice_p_nonce: self.warn_alice_p_nonce.as_slice().try_proto_into()?,
            warn_alice_q_nonce: self.warn_alice_q_nonce.as_slice().try_proto_into()?,
            warn_bob_p_nonce: self.warn_bob_p_nonce.as_slice().try_proto_into()?,
            warn_bob_q_nonce: self.warn_bob_q_nonce.as_slice().try_proto_into()?,
            claim_alice_nonce: self.claim_alice_nonce.as_slice().try_proto_into()?,
            claim_bob_nonce: self.claim_bob_nonce.as_slice().try_proto_into()?,
            redirect_alice_nonce: self.redirect_alice_nonce.as_slice().try_proto_into()?,
            redirect_bob_nonce: self.redirect_bob_nonce.as_slice().try_proto_into()?,
        })
    }
}

impl TryFrom<bmp_engine::Round3Parameter> for bmp_pb::Round3Response {
    type Error = Status;
    fn try_from(value: bmp_engine::Round3Parameter) -> Result<Self, Self::Error> {
        Ok(Self {
            deposit_txid: value.deposit_txid.to_byte_array().to_vec(),
            swap_part_sig: value.swap_part_sig.serialize().to_vec(),
            p_part_peer: value.p_part_peer.serialize().to_vec(),
            q_part_peer: value.q_part_peer.serialize().to_vec(),
            claim_part_sig: value.claim_part_sig.serialize().to_vec(),
            redirect_part_sig: value.redirect_part_sig.serialize().to_vec(),
        })
    }
}

impl TryProtoInto<bmp_engine::Round3Parameter> for bmp_pb::Round3Response {
    fn try_proto_into(self) -> Result<bmp_engine::Round3Parameter> {
        Ok(bmp_engine::Round3Parameter {
            deposit_txid: self.deposit_txid.as_slice().try_proto_into()?,
            swap_part_sig: self.swap_part_sig.as_slice().try_proto_into()?,
            p_part_peer: self.p_part_peer.as_slice().try_proto_into()?,
            q_part_peer: self.q_part_peer.as_slice().try_proto_into()?,
            claim_part_sig: self.claim_part_sig.as_slice().try_proto_into()?,
            redirect_part_sig: self.redirect_part_sig.as_slice().try_proto_into()?,
        })
    }
}

impl TryFrom<bmp_engine::Round4Parameter> for bmp_pb::Round4Response {
    type Error = Status;
    fn try_from(value: bmp_engine::Round4Parameter) -> Result<Self, Self::Error> {
        Ok(Self {
            deposit_tx_signed: value.deposit_tx_signed.serialize(),
        })
    }
}

impl TryProtoInto<bmp_engine::Round4Parameter> for bmp_pb::Round4Response {
    fn try_proto_into(self) -> Result<bmp_engine::Round4Parameter> {
        Ok(bmp_engine::Round4Parameter {
            deposit_tx_signed: Psbt::deserialize(&self.deposit_tx_signed).map_err(|e| {
                Status::invalid_argument(format!("Failed to deserialize Psbt: {e}"))
            })?,
        })
    }
}
