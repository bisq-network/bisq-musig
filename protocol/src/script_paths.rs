use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV};
use bdk_wallet::bitcoin::taproot::TaprootBuilder;
use bdk_wallet::bitcoin::{ScriptBuf, TapNodeHash, XOnlyPublicKey, relative, script};
use bdk_wallet::miniscript::{DefiniteDescriptorKey, Descriptor};

use crate::transaction::NetworkParams;

pub fn deposit_payout_merkle_root(buyer_pub_key: &XOnlyPublicKey, seller_pub_key: &XOnlyPublicKey) -> TapNodeHash {
    single_path_merkle_root(multisig_script(buyer_pub_key, seller_pub_key))
}

pub fn warning_escrow_merkle_root(claim_pub_key: &XOnlyPublicKey, network: impl NetworkParams + Copy) -> TapNodeHash {
    single_path_merkle_root(claim_script(claim_pub_key, network.claim_lock_time()))
}

// FIXME: Can panic; improve:
pub fn deposit_payout_descriptor(
    internal_key: &XOnlyPublicKey,
    buyer_pub_key: &XOnlyPublicKey,
    seller_pub_key: &XOnlyPublicKey,
) -> Descriptor<DefiniteDescriptorKey> {
    format!("tr({internal_key},and_v(v:pk({buyer_pub_key}),pk({seller_pub_key})))").parse().unwrap()
}

fn single_path_merkle_root(script: ScriptBuf) -> TapNodeHash {
    TaprootBuilder::with_capacity(1)
        .add_leaf(0, script)
        .expect("hardcoded TapTree build sequence should be valid")
        .try_into_taptree()
        .expect("hardcoded TapTree build sequence should be complete")
        .root_hash()
}

fn multisig_script(buyer_pub_key: &XOnlyPublicKey, seller_pub_key: &XOnlyPublicKey) -> ScriptBuf {
    // Comes from miniscript policy: format!("and(pk({buyer_pub_key}),pk({seller_pub_key}))")
    // which compiles to miniscript: format!("and_v(v:pk({buyer_pub_key}),pk({seller_pub_key}))")
    script::Builder::new()
        .push_x_only_key(buyer_pub_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(seller_pub_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn claim_script(pub_key: &XOnlyPublicKey, lock_time: relative::LockTime) -> ScriptBuf {
    // Comes from miniscript policy: format!("and(pk({pub_key}),older({lock_time}))")
    // which compiles to miniscript: format!("and_v(v:pk({pub_key}),older({lock_time}))")
    script::Builder::new()
        .push_x_only_key(pub_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_sequence(lock_time.to_sequence())
        .push_opcode(OP_CSV)
        .into_script()
}

#[cfg(test)]
mod tests {
    use bdk_wallet::miniscript::{Miniscript, Tap};

    use super::*;

    #[test]
    fn scripts_match_miniscript() {
        let buyer_pub_key =
            "0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        let seller_pub_key =
            "0000000000000000000000000000000000000000000000000000000000000002".parse().unwrap();
        let lock_time = relative::LockTime::from_height(720);

        let multisig_ms = format!("and_v(v:pk({buyer_pub_key}),pk({seller_pub_key}))")
            .parse::<Miniscript<XOnlyPublicKey, Tap>>().unwrap();
        assert_eq!(multisig_ms.encode(), multisig_script(&buyer_pub_key, &seller_pub_key));

        let claim_ms = format!("and_v(v:pk({buyer_pub_key}),older({lock_time}))")
            .parse::<Miniscript<XOnlyPublicKey, Tap>>().unwrap();
        assert_eq!(claim_ms.encode(), claim_script(&buyer_pub_key, lock_time));
    }
}
