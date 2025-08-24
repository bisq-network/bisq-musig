use bdk_wallet::bitcoin::amount::CheckedSum as _;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::opcodes::all::OP_RETURN;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    absolute, script, Address, Amount, FeeRate, Network, Psbt, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Weight,
};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use std::mem;

use crate::swap::Swap as _;
use crate::transaction::{Receiver, Result, TransactionErrorKind, TxOutput};

// The outputs of each trader's half-deposit PSBT consists of a temporary OP_RETURN placeholder with
// a 27-byte random datagram, burning their trade deposit, followed by any fee receivers(s) in the
// case of the seller (who the Rust side shall deem responsible for paying the trade fees), followed
// by optional change output(s).
//
// A 27-byte-length datagram is chosen to make the estimated weights of the signed half-deposit
// PSBTs sum to 2 wu more than the final signed deposit tx weight. (Attaining an exact match is not
// possible, due to the 4 wu granularity of non-witness part of the tx.)
//
// When the half-PSBTs are merged, the placeholders are replaced with the actual payout UTXOs. The
// injected randomness of the (trade-private) OP_RETURN datagrams ensures that a _deterministic_
// shuffling of the merged deposit PSBT inputs & outputs is unpredictable to any 3rd party.
pub fn half_deposit_placeholder_spk(rng: &mut impl RngCore) -> ScriptBuf {
    let mut data = [0u8; 27];
    rng.fill_bytes(&mut data);
    script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(data)
        .into_script()
}

fn half_deposit_tx_weight(num_keyspend_inputs: u16, num_p2tr_change_outputs: u16) -> Weight {
    const HALF_DEPOSIT_TX_BASE_WEIGHT: Weight = Weight::from_wu(193);
    const KEYSPEND_INPUT_WEIGHT: Weight = Weight::from_wu(230); // Assumes default sighash type
    const P2TR_OUTPUT_WEIGHT: Weight = Weight::from_wu(172);

    HALF_DEPOSIT_TX_BASE_WEIGHT
        + KEYSPEND_INPUT_WEIGHT * u64::from(num_keyspend_inputs)
        + P2TR_OUTPUT_WEIGHT * u64::from(num_p2tr_change_outputs)
}

//noinspection SpellCheckingInspection
pub(crate) fn mock_buyer_half_deposit_psbt(
    deposit_amount: Amount,
    fee_rate: FeeRate,
    rng: &mut impl RngCore,
) -> Option<Psbt> {
    let weight = half_deposit_tx_weight(1, 1);

    let change_amount = Amount::from_sat(100_000_000)
        .checked_sub(deposit_amount)?
        .checked_sub(fee_rate.checked_mul_by_weight(weight)?)?;
    let change_address = "bcrt1pgsj9aw0wvs5h6zj780djnu267v6jazmfekwm4g4q4s6ax3w3t0lseqqnjc"
        .parse::<Address<_>>().ok()?.require_network(Network::Regtest).ok()?;

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: "658654575bbbeb46e965bd9eb37fd3be550a7e0fa2d64bc5f218763155602300:0".parse().ok()?,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            },
        ],
        output: vec![
            TxOut { value: deposit_amount, script_pubkey: half_deposit_placeholder_spk(rng) },
            TxOut { value: change_amount, script_pubkey: change_address.script_pubkey() },
        ],
    };
    Psbt::from_unsigned_tx(unsigned_tx).ok()
}

//noinspection SpellCheckingInspection
pub(crate) fn mock_seller_half_deposit_psbt(
    deposit_amount: Amount,
    fee_rate: FeeRate,
    trade_fee_receivers: &[Receiver],
    rng: &mut impl RngCore,
) -> Option<Psbt> {
    let weight_excluding_receivers = half_deposit_tx_weight(2, 1);

    // We assume a large `extra_output_num` of 128 here because the peer may have decided to add a
    // large number of change outputs to his deposit tx half (for whatever reason), so budget half
    // of the single-byte-compact-integer output count limit of 252 to each trader.
    let total_fees_msat = Receiver::total_output_cost_msat(trade_fee_receivers, fee_rate, 128)?
        .checked_add(fee_rate.to_sat_per_kwu().checked_mul(weight_excluding_receivers.to_wu())?)?;

    let change_amount = Amount::from_sat(200_000_000)
        .checked_sub(deposit_amount)?
        .checked_sub(Amount::from_sat(total_fees_msat.checked_add(999)? / 1000))?;
    let change_address = "bcrt1p80xu5f0nqjarfnechsmlt488jf3tykx8cva9zeeczlsu4c7x557qr499gz"
        .parse::<Address<_>>().ok()?.require_network(Network::Regtest).ok()?;

    let mut output = Vec::with_capacity(trade_fee_receivers.len() + 2);
    output.push(TxOut { value: deposit_amount, script_pubkey: half_deposit_placeholder_spk(rng) });
    output.extend(trade_fee_receivers.iter().map(TxOut::from));
    output.push(TxOut { value: change_amount, script_pubkey: change_address.script_pubkey() });

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: "4a5ecc72ec8db78f11c6785f560a13f6f32eac66d160a8157d30956695ccf523:0".parse().ok()?,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            },
            TxIn {
                previous_output: "373b3ca0b9135e9649672772d4659bb5597d06b4694f1fbdbece285823fde0a3:1".parse().ok()?,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            },
        ],
        output,
    };
    Psbt::from_unsigned_tx(unsigned_tx).ok()
}

fn half_psbt_fee_overpay_msat(psbt: &Psbt, target_fee_rate: FeeRate) -> Option<i64> {
    // Satisfaction weight of each input assuming default sighash type.
    // FIXME: Don't just assume that all inputs are p2tr keyspends.
    const KEYSPEND_WITNESS_WEIGHT: Weight = Weight::from_wu(66);

    // This is the extra weight of witness vs non-witness consensus-serialization (2 wu) minus 1 wu
    // to account for the fact that the base weight of a half-deposit PSBT is 194 wu, which is 1 wu
    // more than half the base weight (386 wu) of the final deposit tx, so just pretend it's 193 wu.
    const EXTRA_WEIGHT: Weight = Weight::from_wu(1);

    let signed_tx_weight = psbt.unsigned_tx.weight() + EXTRA_WEIGHT
        + KEYSPEND_WITNESS_WEIGHT * psbt.inputs.len() as u64;

    // FIXME: Don't just assume that all inputs are 1 BTC each!
    let input_amount = Amount::ONE_BTC * psbt.inputs.len() as u64;
    let output_amount = psbt.unsigned_tx.output.iter().map(|o| o.value).checked_sum()?;

    let actual_fee_msat = input_amount.checked_sub(output_amount)?.to_sat().checked_mul(1000)?;
    let target_fee_msat = target_fee_rate.to_sat_per_kwu().checked_mul(signed_tx_weight.to_wu())?;

    Some(i64::try_from(actual_fee_msat).ok()? - i64::try_from(target_fee_msat).ok()?)
}

pub fn merge_psbt_halves(buyer_psbt: &Psbt, seller_psbt: &Psbt, target_fee_rate: FeeRate, num_receivers: usize) -> Result<Psbt> {
    fn re<T: Clone>(dest: &mut Vec<T>, src: &[T]) -> Vec<T> {
        let mut cloned_src = Vec::with_capacity(src.len() + dest.len());
        cloned_src.extend(src.iter().cloned());
        mem::replace(dest, cloned_src)
    }
    use std::convert::identity as id;

    // TODO: Need to do much more thorough half-PSBT validation than this:
    if buyer_psbt.outputs.is_empty() || seller_psbt.outputs.is_empty() ||
        buyer_psbt.inputs.len() != buyer_psbt.unsigned_tx.input.len() ||
        buyer_psbt.outputs.len() != buyer_psbt.unsigned_tx.output.len() ||
        seller_psbt.inputs.len() != seller_psbt.unsigned_tx.input.len() ||
        seller_psbt.outputs.len() != seller_psbt.unsigned_tx.output.len() {
        return Err(TransactionErrorKind::InvalidPsbt);
    }

    let buyer_overpay_msat = half_psbt_fee_overpay_msat(buyer_psbt, target_fee_rate)
        .ok_or(TransactionErrorKind::Overflow)?;
    let seller_overpay_msat = half_psbt_fee_overpay_msat(seller_psbt, target_fee_rate)
        .ok_or(TransactionErrorKind::Overflow)?;
    if buyer_overpay_msat.is_negative() || seller_overpay_msat.is_negative() {
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    #[expect(clippy::cast_sign_loss, reason = "already checked for negatives")]
    let overpay_total_msat = buyer_overpay_msat as u64 + seller_overpay_msat as u64;
    let buyer_has_change = buyer_psbt.outputs.len() > 1;
    let seller_has_change = seller_psbt.outputs.len() > 1 + num_receivers;

    // Because each PSBT half must pay tx fees rounded up to the next satoshi, the fee overpay of
    // the merged deposit tx can exceed 1 sat, even when neither half is overpaying. In that case,
    // give the extra 1 sat to whoever suffered the greater rounding error. Don't redistribute more
    // than 1 sat of overpay, however, as we probably shouldn't allow one peer to recover the other
    // peer's loss of change to dust.
    let award_1_sat_to_buyer = overpay_total_msat > 999 && buyer_has_change
        && (buyer_overpay_msat >= seller_overpay_msat || !seller_has_change);
    let award_1_sat_to_seller = overpay_total_msat > 999 && seller_has_change
        && !award_1_sat_to_buyer;

    let mut merged_psbt = seller_psbt.clone();
    let seller_tx_input = re(&mut merged_psbt.unsigned_tx.input, &buyer_psbt.unsigned_tx.input);
    let seller_tx_output = re(&mut merged_psbt.unsigned_tx.output, &buyer_psbt.unsigned_tx.output);
    let seller_inputs = re(&mut merged_psbt.inputs, &buyer_psbt.inputs);
    let seller_outputs = re(&mut merged_psbt.outputs, &buyer_psbt.outputs);
    if merged_psbt != *buyer_psbt {
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    merged_psbt.unsigned_tx.input.append(&mut id(seller_tx_input));
    merged_psbt.unsigned_tx.output.append(&mut id(seller_tx_output));
    merged_psbt.inputs.append(&mut id(seller_inputs));
    merged_psbt.outputs.append(&mut id(seller_outputs));

    let seller_output_start = buyer_psbt.outputs.len();
    if award_1_sat_to_buyer {
        merged_psbt.unsigned_tx.output[1].value += Amount::ONE_SAT;
    }
    if award_1_sat_to_seller {
        let i = seller_output_start + 1 + num_receivers;
        merged_psbt.unsigned_tx.output[i].value += Amount::ONE_SAT;
    }
    // Move the seller's placeholder output to the 2nd position (after the buyer's) for convenience:
    (&mut merged_psbt.outputs[..], &mut merged_psbt.unsigned_tx.output[..])
        .swap(1, seller_output_start);

    Ok(merged_psbt)
}

pub fn set_payouts_and_shuffle(psbt: &mut Psbt, buyer_payout: &mut TxOutput, seller_payout: &mut TxOutput) {
    let seed = psbt.unsigned_tx.compute_txid().to_byte_array();
    psbt.unsigned_tx.output[0] = buyer_payout.1.clone();
    psbt.unsigned_tx.output[1] = seller_payout.1.clone();
    [buyer_payout.0.vout, seller_payout.0.vout] = [0, 1];

    let mut rng = ChaCha20Rng::from_seed(seed);
    (&mut psbt.inputs[..], &mut psbt.unsigned_tx.input[..])
        .shuffle(&mut rng);
    (&mut psbt.outputs[..], (&mut psbt.unsigned_tx.output[..],
        (&mut buyer_payout.0.vout, &mut seller_payout.0.vout)))
        .shuffle(&mut rng);

    let txid = psbt.unsigned_tx.compute_txid();
    [buyer_payout.0.txid, seller_payout.0.txid] = [txid; 2];
}
