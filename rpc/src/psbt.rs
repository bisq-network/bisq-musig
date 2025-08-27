use bdk_wallet::bitcoin::amount::CheckedSum as _;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::opcodes::all::OP_RETURN;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    absolute, psbt, script, Address, Amount, FeeRate, Network, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Weight,
};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use std::mem;

use crate::swap::Swap as _;
use crate::transaction::{Receiver, Result, TransactionErrorKind, TxOutput};

// We disallow half-deposit PSBTs with more than half the single-byte VarInt-representable limit
// number (252) of inputs or outputs, as otherwise merging the peer's PSBT could cause it to tip
// over the limit and lead to an unexpected (but slight) underpaying of the deposit tx fee.
// TODO: Maybe this is a little too restrictive. We could instead choose length limits that are on
//  the boundary of what would guarantee a standard deposit tx if both sides maxed them out.
pub const MAX_ALLOWED_HALF_PSBT_INPUT_NUM: usize = 126;
pub const MAX_ALLOWED_HALF_PSBT_OUTPUT_NUM: usize = 126;

pub trait TradeWallet {
    fn create_half_deposit_psbt(
        &mut self,
        deposit_amount: Amount,
        fee_rate: FeeRate,
        trade_fee_receivers: &[Receiver],
        rng: &mut impl RngCore,
    ) -> Result<Psbt>;
}

pub(crate) struct MockTradeWallet<Cs: Iterator<Item=TxOutput>, As: Iterator<Item=Address>> {
    funding_coins: Cs,
    new_addresses: As,
}

impl<Cs: Iterator<Item=TxOutput>, As: Iterator<Item=Address>> TradeWallet for MockTradeWallet<Cs, As> {
    fn create_half_deposit_psbt(
        &mut self,
        deposit_amount: Amount,
        fee_rate: FeeRate,
        trade_fee_receivers: &[Receiver],
        rng: &mut impl RngCore,
    ) -> Result<Psbt> {
        const HALF_DEPOSIT_TX_BASE_WEIGHT: Weight = Weight::from_wu(193);

        let fee_cost_msat = |weight: Weight|
            fee_rate.to_sat_per_kwu().checked_mul(weight.to_wu())
                .ok_or(TransactionErrorKind::Overflow);
        let deposit_amount_msat = deposit_amount.to_sat().checked_mul(1000)
            .ok_or(TransactionErrorKind::Overflow)?;

        let mut input = Vec::new();
        let mut inputs = Vec::new();
        let mut output = Vec::with_capacity(trade_fee_receivers.len() + 2);

        output.push(TxOut {
            value: deposit_amount,
            script_pubkey: half_deposit_placeholder_spk(rng),
        });
        output.extend(trade_fee_receivers.iter().map(TxOut::from));
        let mut change_output = self.new_addresses.next()
            .map(|addr| TxOut { value: Amount::ZERO, script_pubkey: addr.script_pubkey() })
            .ok_or(TransactionErrorKind::MissingAddress)?;

        let mut cost_msat = Receiver::total_output_cost_msat(trade_fee_receivers, fee_rate, 2)
            .ok_or(TransactionErrorKind::Overflow)?
            .checked_add(deposit_amount_msat)
            .ok_or(TransactionErrorKind::Overflow)?
            .checked_add(fee_cost_msat(HALF_DEPOSIT_TX_BASE_WEIGHT)?)
            .ok_or(TransactionErrorKind::Overflow)?
            .checked_add(fee_cost_msat(change_output.weight())?)
            .ok_or(TransactionErrorKind::Overflow)?;

        let mut funds = Amount::ZERO;
        while funds < Amount::from_sat(cost_msat.div_ceil(1000)) {
            let new_coin = self.funding_coins.next()
                .ok_or(TransactionErrorKind::MissingTxOutput)?;
            let new_coin_weight = new_coin.estimated_input_weight()
                .ok_or(TransactionErrorKind::InvalidPsbt)?;
            funds = funds.checked_add(new_coin.1.value)
                .ok_or(TransactionErrorKind::Overflow)?;
            cost_msat = cost_msat.checked_add(fee_cost_msat(new_coin_weight)?)
                .ok_or(TransactionErrorKind::Overflow)?;
            let new_input = TxIn {
                previous_output: new_coin.0,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            };
            input.push(new_input);
            let new_psbt_input = psbt::Input { witness_utxo: Some(new_coin.1), ..psbt::Input::default() };
            inputs.push(new_psbt_input);
        }

        change_output.value = funds - Amount::from_sat(cost_msat.div_ceil(1000));
        if change_output.value >= change_output.script_pubkey.minimal_non_dust() {
            output.push(change_output);
        }

        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        Ok(Psbt { inputs, ..Psbt::from_unsigned_tx(unsigned_tx).expect("tx is unsigned by construction") })
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
pub fn half_deposit_placeholder_spk(rng: &mut impl RngCore) -> ScriptBuf {
    let mut data = [0u8; 27];
    rng.fill_bytes(&mut data);
    script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(data)
        .into_script()
}

//noinspection SpellCheckingInspection
pub(crate) fn mock_buyer_trade_wallet() -> impl TradeWallet {
    let change_address = "bcrt1pgsj9aw0wvs5h6zj780djnu267v6jazmfekwm4g4q4s6ax3w3t0lseqqnjc"
        .parse::<Address<_>>().unwrap().require_network(Network::Regtest).unwrap();
    MockTradeWallet {
        funding_coins: [
            TxOutput::mock_1_btc_coin("658654575bbbeb46e965bd9eb37fd3be550a7e0fa2d64bc5f218763155602300:0"),
        ].into_iter(),
        new_addresses: [change_address].into_iter(),
    }
}

//noinspection SpellCheckingInspection
pub(crate) fn mock_seller_trade_wallet() -> impl TradeWallet {
    let change_address = "bcrt1p80xu5f0nqjarfnechsmlt488jf3tykx8cva9zeeczlsu4c7x557qr499gz"
        .parse::<Address<_>>().unwrap().require_network(Network::Regtest).unwrap();
    MockTradeWallet {
        funding_coins: [
            TxOutput::mock_1_btc_coin("4a5ecc72ec8db78f11c6785f560a13f6f32eac66d160a8157d30956695ccf523:0"),
            TxOutput::mock_1_btc_coin("373b3ca0b9135e9649672772d4659bb5597d06b4694f1fbdbece285823fde0a3:1"),
        ].into_iter(),
        new_addresses: [change_address].into_iter(),
    }
}

fn input_coin(psbt: &Psbt, index: usize) -> Option<TxOutput> {
    Some(TxOutput(psbt.unsigned_tx.input[index].previous_output,
        psbt.inputs[index].witness_utxo.clone()?))
}

fn half_psbt_fee_overpay_msat(psbt: &Psbt, target_fee_rate: FeeRate) -> Option<i64> {
    const INPUT_NON_WITNESS_WEIGHT: Weight = Weight::from_wu(164);

    // This is the extra weight of witness vs non-witness consensus-serialization (2 wu) minus 1 wu
    // to account for the fact that the base weight of a half-deposit PSBT is 194 wu, which is 1 wu
    // more than half the base weight (386 wu) of the final deposit tx, so just pretend it's 193 wu.
    const EXTRA_WEIGHT: Weight = Weight::from_wu(1);

    if psbt.inputs.len() > MAX_ALLOWED_HALF_PSBT_INPUT_NUM ||
        psbt.outputs.len() > MAX_ALLOWED_HALF_PSBT_OUTPUT_NUM {
        return None;
    }
    let mut signed_tx_weight = psbt.unsigned_tx.weight() + EXTRA_WEIGHT
        - INPUT_NON_WITNESS_WEIGHT * psbt.inputs.len() as u64;
    let mut input_amount = Amount::ZERO;

    for i in 0..psbt.inputs.len() {
        // FIXME: This will lead to an overflow error if a corrupted or disallowed input coin is
        //  encountered, instead of an invalid PSBT error as it should:
        let coin = input_coin(psbt, i)?;
        signed_tx_weight += coin.estimated_input_weight()?;
        input_amount = input_amount.checked_add(coin.1.value)?;
    }
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
