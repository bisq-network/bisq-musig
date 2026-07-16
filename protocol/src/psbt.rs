use std::collections::BTreeSet;
use std::mem;

use bdk_wallet::bitcoin::amount::CheckedSum as _;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::opcodes::all::{OP_PUSHBYTES_27, OP_RETURN};
use bdk_wallet::bitcoin::{
    Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxOut, Weight, psbt, script,
};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use wallet::protocol_wallet_api::ProtocolWalletApi;

use crate::receiver::Receiver;
use crate::swap::Swap as _;
use crate::transaction::{Result, TransactionErrorKind, TxOutput};

// We disallow half-deposit PSBTs with more than half the single-byte VarInt-representable limit
// number (252) of inputs or outputs, as otherwise merging the peer's PSBT could cause it to tip
// over the limit and lead to an unexpected (but slight) underpaying of the deposit tx fee.
// TODO: Maybe this is a little too restrictive. We could instead choose length limits that are on
//  the boundary of what would guarantee a standard deposit tx if both sides maxed them out.
pub const MAX_ALLOWED_HALF_PSBT_INPUT_NUM: usize = 126;
pub const MAX_ALLOWED_HALF_PSBT_OUTPUT_NUM: usize = 126;

pub fn create_half_deposit_psbt(
    wallet: &mut (impl ProtocolWalletApi + ?Sized),
    deposit_amount: Amount,
    fee_rate: FeeRate,
    trade_fee_receivers: &[Receiver],
    rng: &mut dyn RngCore,
) -> Result<Psbt> {
    let mut recipients = Vec::with_capacity(1 + trade_fee_receivers.len());
    recipients.push((half_deposit_placeholder_spk(rng), deposit_amount));
    recipients.extend(trade_fee_receivers.iter()
        .map(|r| (r.address.script_pubkey(), r.amount)));

    let mut psbt = wallet.create_psbt(recipients, fee_rate)?;

    // Calculate tx fee overpay unconditionally, as this performs additional checks on the PSBT:
    let overpay_msat = u64::try_from(half_psbt_fee_overpay_msat(&psbt, fee_rate)?)
        .map_err(|_| TransactionErrorKind::InvalidPsbt)?;
    let change_output_index = 1 + trade_fee_receivers.len();
    if psbt.unsigned_tx.output.len() > change_output_index {
        // Correct any tx fee overpay due to overly conservative input witness size estimation by
        // BDK (as each witness is assumed to potentially have a non-default sighash type in the
        // case of P2TR and not grind for low R in the case of P2WPKH), and also due to the fact
        // that each would-be-signed half-deposit PSBT is 1 wu bigger than ideal.
        let overpay = Amount::from_sat(overpay_msat / 1000);
        psbt.unsigned_tx.output[change_output_index].value += overpay;
    }
    psbt.redact_sensitive_fields();
    Ok(psbt)
}

pub trait Redact {
    fn redact_sensitive_fields(&mut self);
}

impl Redact for Psbt {
    fn redact_sensitive_fields(&mut self) {
        self.inputs.iter_mut().for_each(psbt::Input::redact_sensitive_fields);
        self.outputs.iter_mut().for_each(psbt::Output::redact_sensitive_fields);
    }
}

impl Redact for psbt::Input {
    fn redact_sensitive_fields(&mut self) {
        self.tap_key_origins.clear();
        self.tap_scripts.clear();
        self.tap_script_sigs.clear();
        self.tap_internal_key = None;
        self.tap_merkle_root = None;
    }
}

impl Redact for psbt::Output {
    fn redact_sensitive_fields(&mut self) {
        self.tap_key_origins.clear();
        self.tap_internal_key = None;
        self.tap_tree = None;
    }
}

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
fn half_deposit_placeholder_spk<R: RngCore + ?Sized>(rng: &mut R) -> ScriptBuf {
    let mut data = [0u8; 27];
    rng.fill_bytes(&mut data);
    script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(data)
        .into_script()
}

pub fn prevout_set(psbt: &Psbt) -> BTreeSet<OutPoint> {
    psbt.unsigned_tx.input.iter().map(|input| input.previous_output).collect()
}

pub fn check_placeholder_output(psbt: &Psbt, expected_deposit: Amount) -> Result<()> {
    let Some(TxOut { value, script_pubkey }) = psbt.unsigned_tx.output.first() else {
        return Err(TransactionErrorKind::InvalidPsbt);
    };
    if *value != expected_deposit || !script_pubkey.is_op_return() || script_pubkey.len() != 29
        || script_pubkey.as_bytes()[1] != OP_PUSHBYTES_27.to_u8() {
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    Ok(())
}

pub fn check_receiver_outputs(psbt: &Psbt, trade_fee_receivers: &[Receiver]) -> Result<()> {
    if psbt.unsigned_tx.output.len() <= trade_fee_receivers.len() ||
        (0..trade_fee_receivers.len())
            .any(|i| psbt.unsigned_tx.output[i + 1] != (&trade_fee_receivers[i]).into()) {
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    Ok(())
}

fn input_coin(psbt: &Psbt, index: usize) -> Result<TxOutput> {
    if psbt.unsigned_tx.input[index].sequence != Sequence::ENABLE_RBF_NO_LOCKTIME {
        // Enforce that all deposit PSBT inputs have a sequence number of 0xFFFFFFFD.
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    Ok(TxOutput {
        outpoint: psbt.unsigned_tx.input[index].previous_output,
        prevout: psbt.inputs[index].witness_utxo.clone()
            .ok_or(TransactionErrorKind::InvalidPsbt)?,
    })
}

fn half_psbt_fee_overpay_msat(psbt: &Psbt, target_fee_rate: FeeRate) -> Result<i64> {
    const INPUT_NON_WITNESS_WEIGHT: Weight = Weight::from_wu(164);

    // This is the extra weight of witness vs non-witness consensus-serialization (2 wu) minus 1 wu
    // to account for the fact that the base weight of a half-deposit PSBT is 194 wu, which is 1 wu
    // more than half the base weight (386 wu) of the final deposit tx, so just pretend it's 193 wu.
    const EXTRA_WEIGHT: Weight = Weight::from_wu(1);

    if psbt.inputs.len() > MAX_ALLOWED_HALF_PSBT_INPUT_NUM ||
        psbt.outputs.len() > MAX_ALLOWED_HALF_PSBT_OUTPUT_NUM {
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    let mut signed_tx_weight = psbt.unsigned_tx.weight() + EXTRA_WEIGHT
        - INPUT_NON_WITNESS_WEIGHT * psbt.inputs.len() as u64;
    let mut input_amount = Amount::ZERO;

    for i in 0..psbt.inputs.len() {
        let coin = input_coin(psbt, i)?;
        signed_tx_weight += coin.estimated_input_weight()
            .ok_or(TransactionErrorKind::InvalidPsbt)?;
        input_amount = input_amount.checked_add(coin.prevout.value)
            .ok_or(TransactionErrorKind::Overflow)?;
    }
    (|| {
        let output_amount = psbt.unsigned_tx.output.iter().map(|o| o.value).checked_sum()?;
        let actual_fee_msat = input_amount.checked_sub(output_amount)?.to_sat().checked_mul(1000)?;
        let target_fee_msat = target_fee_rate.to_sat_per_kwu().checked_mul(signed_tx_weight.to_wu())?;

        Some(i64::try_from(actual_fee_msat).ok()? - i64::try_from(target_fee_msat).ok()?)
    })().ok_or(TransactionErrorKind::Overflow)
}

fn is_well_formed(psbt: &Psbt) -> bool {
    psbt.inputs.len() == psbt.unsigned_tx.input.len() &&
        psbt.outputs.len() == psbt.unsigned_tx.output.len() &&
        psbt.unsigned_tx.input.iter().all(|i| i.script_sig.is_empty() && i.witness.is_empty())
}

pub fn merge_psbt_halves(
    buyer_psbt: &Psbt,
    seller_psbt: &Psbt,
    target_fee_rate: FeeRate,
    num_receivers: usize,
) -> Result<Psbt> {
    fn re<T: Clone>(dest: &mut Vec<T>, src: &[T]) -> Vec<T> {
        let mut cloned_src = Vec::with_capacity(src.len() + dest.len());
        cloned_src.extend(src.iter().cloned());
        mem::replace(dest, cloned_src)
    }
    use std::convert::identity as id;

    if !is_well_formed(buyer_psbt) || buyer_psbt.outputs.is_empty() ||
        !is_well_formed(seller_psbt) || seller_psbt.outputs.is_empty() {
        return Err(TransactionErrorKind::InvalidPsbt);
    }

    let buyer_overpay_msat = half_psbt_fee_overpay_msat(buyer_psbt, target_fee_rate)?;
    let seller_overpay_msat = half_psbt_fee_overpay_msat(seller_psbt, target_fee_rate)?;
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
        // All fields of the PSBT halves, apart from their input & output lists, must exactly match.
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
    // Check for duplicate prevouts, which may be caused by the peer attempting to use some of ours:
    if prevout_set(&merged_psbt).len() != merged_psbt.inputs.len() {
        return Err(TransactionErrorKind::InvalidPsbt);
    }

    Ok(merged_psbt)
}

pub fn set_payouts_and_shuffle(psbt: &mut Psbt, buyer_payout: &mut TxOutput, seller_payout: &mut TxOutput) {
    let seed = psbt.unsigned_tx.compute_txid().to_byte_array();
    psbt.unsigned_tx.output[0] = buyer_payout.prevout.clone();
    psbt.unsigned_tx.output[1] = seller_payout.prevout.clone();
    [buyer_payout.outpoint.vout, seller_payout.outpoint.vout] = [0, 1];

    let mut rng = ChaCha20Rng::from_seed(seed);
    (&mut psbt.inputs[..], &mut psbt.unsigned_tx.input[..])
        .shuffle(&mut rng);
    (&mut psbt.outputs[..], (&mut psbt.unsigned_tx.output[..],
        (&mut buyer_payout.outpoint.vout, &mut seller_payout.outpoint.vout)))
        .shuffle(&mut rng);

    let txid = psbt.unsigned_tx.compute_txid();
    [buyer_payout.outpoint.txid, seller_payout.outpoint.txid] = [txid; 2];
}

pub fn extract_signed_tx(psbt: &Psbt) -> Result<Transaction> {
    if !is_well_formed(psbt) || psbt.inputs.iter().any(|input| input.final_script_sig.is_some()) {
        return Err(TransactionErrorKind::InvalidPsbt);
    }
    if psbt.inputs.iter().any(|input| input.final_script_witness.is_none()) {
        return Err(TransactionErrorKind::MissingSignature);
    }
    // TODO: Report undocumented panics in `Psbt::extract_tx` & `Psbt::fee` if the PSBT is malformed.
    Ok(psbt.clone().extract_tx()?)
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{Address, Network, TxIn, absolute, secp256k1};
    use bdk_wallet::miniscript::psbt::PsbtInputExt as _;
    use bdk_wallet::psbt::PsbtUtils as _;
    use bdk_wallet::{KeychainKind, test_utils};

    use super::*;
    use crate::script_paths::deposit_payout_descriptor;

    static LIBSECP256K1_CTX: LazyLock<secp256k1::Secp256k1<secp256k1::All>> =
        LazyLock::new(secp256k1::Secp256k1::new);

    //noinspection SpellCheckingInspection
    #[test]
    fn bdk_trade_wallet_half_deposit_psbt() -> Result<()> {
        let descriptor = test_utils::get_test_tr_single_sig_xprv();
        let mut wallet = test_utils::get_funded_wallet_single(descriptor).0;
        let mut rng = rand::rng();

        let deposit_amount = Amount::from_sat(40_000);
        let fee_rate = FeeRate::from_sat_per_vb_u32(10);
        let receiver_address = "bcrt1qwk6p86mzqmstcsg99qlu2mhsp3766u68jktv6k"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let trade_fee_receivers = [
            Receiver { address: receiver_address, amount: Amount::from_sat(5_000) }
        ];

        // Create a test half-deposit PSBT with one 50_000 sat input, one 40_000 sat OP_RETURN
        // output, one 5_000 sat trade fee output and one change output.
        let mut psbt = create_half_deposit_psbt(&mut wallet, deposit_amount, fee_rate, &trade_fee_receivers, &mut rng)?;
        assert_eq!([40_000, 5_000, 3_202], psbt.unsigned_tx.output.first_chunk().unwrap().clone()
            .map(|o| o.value.to_sat()));

        let overpay_msat = half_psbt_fee_overpay_msat(&psbt, fee_rate)?;
        assert!((0..1000).contains(&overpay_msat));

        // (The PSBT halves would not ever be signed in production, only the merged and shuffled
        // Deposit Tx resulting from them.)
        wallet.sign_selected_inputs(&mut psbt, &|_| true)?;

        let fee_amount = psbt.fee_amount().unwrap();
        let actual_weight = psbt.extract_tx()?.weight();
        // The ideal weights of each would-be-signed deposit PSBT half are 1 wu less than their
        // actual signed tx weights. They sum exactly to the weight of the final signed Deposit Tx
        // and should accordingly each give rise to the target fee rate (10 sat/vB in this case).
        let ideal_weight = actual_weight - Weight::from_wu(1);
        assert!(fee_rate * actual_weight > fee_amount);
        assert_eq!(fee_rate * ideal_weight, fee_amount);
        Ok(())
    }

    #[test]
    fn bdk_trade_wallet_new_address() -> Result<()> {
        let descriptor = test_utils::get_test_tr_single_sig_xprv();
        let mut wallet = test_utils::get_funded_wallet_single(descriptor).0;

        // Wallet was created with one already-used non-change address at index 0.
        assert_eq!(Some(0), wallet.derivation_index(KeychainKind::External));

        let addresses = [wallet.new_address()?, wallet.new_address()?];
        let spk_indices = addresses.map(|addr|
            wallet.spk_index().index_of_spk(addr.script_pubkey()).expect("missing address").1);

        assert_eq!([1, 2], spk_indices);
        Ok(())
    }

    #[test]
    fn bdk_trade_wallet_new_internal_key() -> Result<()> {
        let descriptor = test_utils::get_test_tr_single_sig_xprv();
        let mut wallet = test_utils::get_funded_wallet_single(descriptor).0;

        // Wallet was created with one already-used non-change address at index 0.
        assert_eq!(Some(0), wallet.derivation_index(KeychainKind::External));

        let ik1 = wallet.new_internal_key()?;
        let addr2 = wallet.new_address()?;
        let ik3 = wallet.new_internal_key()?;

        let spk1 = ScriptBuf::new_p2tr(&*LIBSECP256K1_CTX, ik1, None);
        let spk2 = addr2.script_pubkey();
        let spk3 = ScriptBuf::new_p2tr(&*LIBSECP256K1_CTX, ik3, None);

        let spk_indices = [spk1, spk2, spk3].map(|spk|
            wallet.spk_index().index_of_spk(spk).expect("missing spk").1);

        assert_eq!([1, 2, 3], spk_indices);
        Ok(())
    }

    #[test]
    fn bdk_trade_wallet_multisig_signing() -> Result<()> {
        let descriptors = test_utils::get_test_tr_single_sig_xprv_and_change_desc();
        let mut buyer_wallet = test_utils::get_funded_wallet_single(descriptors.0).0;
        let mut seller_wallet = test_utils::get_funded_wallet_single(descriptors.1).0;

        let payout_address = buyer_wallet.new_address()?;

        // Generate buyer and seller pubkeys from their respective wallet HD keychains.
        let internal_key =
            &"0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        let buyer_pub_key = &buyer_wallet.new_internal_key()?;
        let seller_pub_key = &seller_wallet.new_internal_key()?;

        // Input descriptor: tr({internal_key},and_v(v:pk({buyer_pub_key}),pk({seller_pub_key})))
        let multisig_desc = deposit_payout_descriptor(internal_key, buyer_pub_key, seller_pub_key)?;

        // Create a PSBT paying from a single 1 BTC dummy input into the buyer's wallet, with zero
        // fee, and update the input metadata with the above descriptor.
        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::ONE_BTC,
                script_pubkey: payout_address.script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: multisig_desc.script_pubkey(),
        });
        psbt.inputs[0].update_with_descriptor_unchecked(&multisig_desc)?;

        // After the buyer signs, the PSBT holds one tapscript signature but is not yet finalized.
        buyer_wallet.sign_selected_inputs(&mut psbt, &|_| true)?;
        assert_eq!(1, psbt.inputs[0].tap_script_sigs.len());
        assert!(psbt.inputs[0].final_script_witness.is_none());

        // After the seller signs, the PSBT is automatically finalized, clearing remaining metadata.
        seller_wallet.sign_selected_inputs(&mut psbt, &|_| true)?;
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert!(psbt.inputs[0].final_script_witness.is_some());

        // Expected weight of signed multisig tx is 168 wu greater than that of a regular single-
        // keyspend-input, single-P2TR-output tx (namely, `SIGNED_FORWARDING_TX_WEIGHT` = 444 wu).
        assert_eq!(Weight::from_wu(612), psbt.extract_tx()?.weight());
        Ok(())
    }
}
