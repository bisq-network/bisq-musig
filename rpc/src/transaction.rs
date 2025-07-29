use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bdk_wallet::bitcoin::taproot::TaprootBuilder;
use bdk_wallet::bitcoin::{relative, script, ScriptBuf, TapNodeHash, XOnlyPublicKey};
use relative::LockTime;

pub const REGTEST_CLAIM_LOCK_TIME: LockTime = LockTime::from_height(5);

fn claim_script(pub_key: &XOnlyPublicKey, lock_time: LockTime) -> ScriptBuf {
    script::Builder::new()
        .push_sequence(lock_time.to_sequence())
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pub_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn warning_output_merkle_root(claim_pub_key: &XOnlyPublicKey, claim_lock_time: LockTime) -> TapNodeHash {
    let claim_script = claim_script(claim_pub_key, claim_lock_time);
    TaprootBuilder::with_capacity(1)
        .add_leaf(0, claim_script)
        .expect("hardcoded TapTree build sequence should be valid")
        .try_into_taptree()
        .expect("hardcoded TapTree build sequence should be complete")
        .root_hash()
}
