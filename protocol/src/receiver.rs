use std::sync::Arc;

use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::amount::CheckedSum as _;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, TxOut, Weight};

use crate::transaction::Result;

// Receivers paid less than this absolute satoshi amount are excluded:
const MIN_OUTPUT_AMOUNT: Amount = Amount::from_sat(1000);
// Twice the cost (32 bytes) of a P2SH output -- receivers paid less than this weight-equivalent are excluded:
const MIN_OUTPUT_EQUIVALENT_WEIGHT: Weight = Weight::from_wu(256);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receiver<V: NetworkValidation = NetworkChecked> {
    pub address: Address<V>,
    pub amount: Amount,
}

impl Receiver<NetworkUnchecked> {
    pub fn require_network(self, required: Network) -> Result<Receiver> {
        Ok(Receiver { address: self.address.require_network(required)?, amount: self.amount })
    }
}

impl Receiver {
    fn output_weight(&self) -> Weight { TxOut::from(self).weight() }

    fn output_cost_msat(&self, fee_rate: FeeRate) -> Option<u64> {
        let amount_msat = self.amount.to_sat().checked_mul(1000)?;
        let fee_msat = fee_rate.to_sat_per_kwu().checked_mul(self.output_weight().to_wu())?;
        amount_msat.checked_add(fee_msat)
    }

    pub fn total_output_cost_msat<'a, I>(receivers: I, fee_rate: FeeRate, extra_output_num: u16) -> Option<u64>
        where I: IntoIterator<Item=&'a Self>
    {
        let mut cost = 0u64;
        let mut num = extra_output_num;
        for receiver in receivers {
            cost = cost.checked_add(receiver.output_cost_msat(fee_rate)?)?;
            // Fail if more than 65535 outputs, which will never happen for a standard tx:
            num = num.checked_add(1)?;
        }
        if num > 252 {
            // For more than 252 outputs, we get a 3-byte length encoding instead of 1, adding 8 wu.
            cost = cost.checked_add(fee_rate.to_sat_per_kwu().checked_mul(8)?)?;
        }
        Some(cost)
    }

    // TODO: Consider returning a `Result<T>` instead of an `Option<T>` to distinguish overflows
    //  from other errors (negative shares, empty receiver list, etc.).
    pub fn compute_receivers_from_shares(
        mut receiver_shares: Vec<(Address, f64)>,
        available_amount_msat: u64,
        fee_rate: FeeRate,
    ) -> Option<ReceiverList> {
        fn min_output_amount(fee_rate: FeeRate) -> Option<Amount> {
            Some(MIN_OUTPUT_AMOUNT.max(fee_rate.checked_mul_by_weight(MIN_OUTPUT_EQUIVALENT_WEIGHT)?))
        }
        fn output_fee_msat(address: &Address, index: u16, fee_rate: FeeRate) -> Option<u64> {
            let wu = (address.script_pubkey().len() as u64 + if index == 251 { 11 } else { 9 }) * 4;
            fee_rate.to_sat_per_kwu().checked_mul(wu)
        }
        fn scale(amount: Amount, scale_factor: f64) -> Amount {
            #[expect(clippy::cast_precision_loss,
            reason = "any satoshi amount up to `Amount::MAX_MONEY` fits in a 52-bit mantissa")]
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss,
            reason = "`scale_factor` always lies in 0.0..=1.0 and `amount` always fits in an i64")]
            Amount::from_sat((amount.to_sat() as f64 * scale_factor).round() as u64)
        }

        if receiver_shares.iter().any(|(_, x)| !(0.0..f64::INFINITY).contains(x)) {
            // All receiver share sizes must be finite and non-negative.
            return None;
        }
        // Sort the receivers by order of decreasing share size.
        receiver_shares.sort_by(|(_, x), (_, y)| y.total_cmp(x));

        // Compute the total to receive after subtracting the tx fee, and which receivers can be
        // economically included.
        let min_output_amount = min_output_amount(fee_rate)?;
        let mut total_to_receive_msat = available_amount_msat;
        let mut total_share = 0.0;
        let mut num_receivers = 0;
        for share in &receiver_shares {
            let new_total_share = total_share + share.1;
            let new_total_to_receive_msat = total_to_receive_msat
                .saturating_sub(output_fee_msat(&share.0, num_receivers, fee_rate)?);
            let new_total_to_receive = Amount::from_sat(new_total_to_receive_msat / 1000);
            let output_amount = scale(new_total_to_receive, share.1 / new_total_share);
            if output_amount < min_output_amount {
                // No further receivers with this share size or smaller can be economically added.
                break;
            }
            if min_output_amount.checked_mul(u64::from(num_receivers) + 1)? > new_total_to_receive {
                // We would get stuck if we include any more outputs, since there are insufficient
                // funds for all of them, even paying each the allowed minimum.
                break;
            }
            total_share = new_total_share;
            total_to_receive_msat = new_total_to_receive_msat;
            num_receivers = num_receivers.checked_add(1)?;
        }
        if num_receivers == 0 {
            // We could not economically include any receivers, so fail.
            return None;
        }

        // Convert the included shares into absolute satoshi amounts, subject to rounding errors.
        let total_to_receive = Amount::from_sat(total_to_receive_msat / 1000);
        let mut receivers: Vec<Self> = receiver_shares.into_iter()
            .take(num_receivers as usize)
            .map(|share| Self {
                address: share.0,
                amount: scale(total_to_receive, share.1 / total_share),
            })
            .collect();

        // Correct any slight total overpayment/underpayment to the receivers (likely just a few
        // satoshis), by subtracting/adding a uniform (or as close to uniform as possible) amount
        // from/to each output, favoring the bigger receivers and making sure that no receiver
        // amount dips below the fee dependent `min_output_amount`.
        let min_output_amount = i64::try_from(min_output_amount.to_sat()).ok()?;
        let mut underpayment = i64::try_from(total_to_receive.to_sat()).ok()?
            .checked_sub_unsigned(receivers.iter().map(|r| r.amount).checked_sum()?.to_sat())?;
        for (i, receiver) in receivers.iter_mut().enumerate().rev() {
            let amount = receiver.amount.to_sat();
            let correction = underpayment
                .div_euclid(i64::try_from(i + 1).expect("i < num_receivers"))
                .max(min_output_amount.checked_sub_unsigned(amount)?);
            receiver.amount = Amount::from_sat(amount.checked_add_signed(correction)?);
            underpayment = underpayment.checked_sub(correction)?;
        }
        Some(receivers.into())
    }
}

impl From<&Receiver> for TxOut {
    fn from(value: &Receiver) -> Self {
        Self { value: value.amount, script_pubkey: value.address.script_pubkey() }
    }
}

pub type ReceiverList = Arc<[Receiver]>;

#[cfg(test)]
mod tests {
    use super::*;

    //noinspection SpellCheckingInspection
    #[test]
    fn test_compute_receivers_from_shares_none_filtered() {
        // These are the same available msat amount, fee rate & absolute receiver amounts used in
        // the test trades of 'rpc/src/main/java/bisq/TradeProtocolClient.java'.
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        let available_amount_msat = 256_115_000;

        // (The precise fractions chosen here sum to unity and exercise the use of `f64::round` in
        // `Receiver::compute_receivers_from_shares::scale` to round to nearest as intended, to
        // minimize cumulative rounding errors prior to fixup. Casting directly to u64 rounds _down_
        // instead, producing slightly different receiver amounts which fail the test.)
        let receiver_shares = receiver_shares([
            ("2N2x2bA28AsLZZEHss4SjFoyToQV5YYZsJM", 0.059_026),
            ("bcrt1qwk6p86mzqmstcsg99qlu2mhsp3766u68jktv6k", 0.313_659),
            ("bcrt1phc8m8vansnl4utths947mjquprw20puwrrdfrwx8akeeu2tqwklsnxsvf0", 0.627_315),
        ]);

        let expected_receivers: ReceiverList = receivers([
            ("bcrt1phc8m8vansnl4utths947mjquprw20puwrrdfrwx8akeeu2tqwklsnxsvf0", 160_000),
            ("bcrt1qwk6p86mzqmstcsg99qlu2mhsp3766u68jktv6k", 80_000),
            ("2N2x2bA28AsLZZEHss4SjFoyToQV5YYZsJM", 15_055),
        ]);

        let receivers = Receiver::compute_receivers_from_shares(
            receiver_shares, available_amount_msat, fee_rate).unwrap();

        assert_eq!(expected_receivers, receivers);
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_compute_receivers_from_shares_one_filtered_normally() {
        // This is the smallest fee for which the minimum allowed receiver output amount starts
        // scaling linearly with the fee and exceeds the absolute minimum of 1000 sats, instead
        // being rounded _up_ to 1001 sats:
        let fee_rate = FeeRate::from_sat_per_kwu(3_907); // 15.628 sats per vbyte
        // 2000 sats for two P2TR outputs, plus 1_344_008 msat for their fee contributions:
        let available_amount_msat = 3_344_008;

        // To be paid 1000 sats each, if both were included:
        let receiver_shares = receiver_shares([
            ("bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk", 0.5),
            ("bcrt1phhl8d90r9haqwtvw2cv4ryjl8tlnqrv48nhpy7yyks5du6mr66xq5nlwhz", 0.5),
        ]);

        // The 2nd receiver gets filtered out, falling short of the minimum output amount by 1 sat.
        // The 1st receiver is not filtered out, in spite of having the same share, since removing
        // the remaining receivers makes another 1_672 sats available, taking him above the minimum.
        let expected_receivers: ReceiverList = receivers([
            ("bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk", 2_672),
        ]);

        let receivers = Receiver::compute_receivers_from_shares(
            receiver_shares, available_amount_msat, fee_rate).unwrap();

        assert_eq!(expected_receivers, receivers);
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_compute_receivers_from_shares_one_filtered_by_min_output_saturation() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        // 1999 sats for two P2TR outputs, plus 860 sats for their fee contributions:
        let available_amount_msat = 2_859_000;

        // To be paid 1000 sats each, if both were included, since the 999.5 sats owed to each
        // receiver gets rounded up to 1000. But since this would lead to a total overpayment of 1
        // sat, and 1000 is the minimum output amount, we are not allowed to include both.
        let receiver_shares = receiver_shares([
            ("bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk", 0.5),
            ("bcrt1phhl8d90r9haqwtvw2cv4ryjl8tlnqrv48nhpy7yyks5du6mr66xq5nlwhz", 0.5),
        ]);

        // The 2nd receiver gets filtered out, in spite of just reaching the 1000 sat minimum needed
        // to be included, since `min_output_amount` * 2 exceeds the 1999 sats available for 2 P2TR
        // outputs. The 1st receiver is not filtered out, in spite of having the same share, since
        // `min_output_amount` * 1 is less than the 2_429 sats available for 1 P2TR output.
        let expected_receivers: ReceiverList = receivers([
            ("bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk", 2_429),
        ]);

        let receivers = Receiver::compute_receivers_from_shares(
            receiver_shares, available_amount_msat, fee_rate).unwrap();

        assert_eq!(expected_receivers, receivers);
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_compute_receivers_from_shares_all_filtered() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        // 999 sats for one P2TR output, plus 430 sats for its fee contribution:
        let available_amount_msat = 1_429_000;

        // The first receiver to be paid 999 sats, if he alone were included:
        let receiver_shares = receiver_shares([
            ("bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk", 0.5),
            ("bcrt1phhl8d90r9haqwtvw2cv4ryjl8tlnqrv48nhpy7yyks5du6mr66xq5nlwhz", 0.5),
        ]);

        let receivers = Receiver::compute_receivers_from_shares(
            receiver_shares, available_amount_msat, fee_rate);

        // Computing the receiver list fails, as none could be economically included.
        assert!(receivers.is_none());
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_compute_receivers_from_shares_more_than_251_outputs() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
        // 10_000 sats each for 252 P2SH outputs, 8_064 = 252 * 32 sats for their fee contributions,
        // but this _doesn't_ include the extra 2 vB <-> 2 sats cost for including >251 outputs:
        let mut available_amount_msat = 2_528_064_000;

        // Receiver address repetitions are permitted, as well as shares that don't sum to unity
        // (which would be difficult to achieve due to rounding errors anyway). Instead, the shares
        // are implicitly divided by their total and need only be non-negative and finite.
        let mut receiver_shares = receiver_shares([
            ("2N2x2bA28AsLZZEHss4SjFoyToQV5YYZsJM", 1.0); 252
        ]);

        // Since the available amount is short by 2 sats, the last two output amounts are 9_999 sats
        // each instead of the 10_000 sats for each of the first 250 outputs.
        let mut expected_receivers: Vec<Receiver> = receivers([
            ("2N2x2bA28AsLZZEHss4SjFoyToQV5YYZsJM", 10_000); 252
        ]);
        expected_receivers[250].amount -= Amount::ONE_SAT;
        expected_receivers[251].amount -= Amount::ONE_SAT;

        let receivers = Receiver::compute_receivers_from_shares(
            receiver_shares.clone(), available_amount_msat, fee_rate).unwrap();

        assert_eq!(expected_receivers[..], receivers[..]);

        // Now add an extra 10_032 sats to the available total and a 253rd receiver share identical
        // to the others. This means we are still short by 2 sats, so only the last two outputs are
        // 9_999 sats, as before. (That is, the 2 vB size cost should only be incurred once.)
        assert_eq!(0, available_amount_msat % 252);
        available_amount_msat = available_amount_msat / 252 * 253;
        receiver_shares.push(receiver_shares[0].clone());
        expected_receivers.insert(250, expected_receivers[0].clone());

        let receivers = Receiver::compute_receivers_from_shares(
            receiver_shares, available_amount_msat, fee_rate).unwrap();

        assert_eq!(expected_receivers[..], receivers[..]);
    }

    fn receiver_shares<const N: usize>(arr: [(&'static str, f64); N]) -> Vec<(Address, f64)> {
        arr.map(|(addr, share)|
            (addr.parse::<Address<NetworkUnchecked>>().unwrap().assume_checked(), share)).into()
    }

    fn receivers<const N: usize, Rs: From<[Receiver; N]>>(arr: [(&'static str, u64); N]) -> Rs {
        arr.map(|(addr, satoshi)| Receiver {
            address: addr.parse::<Address<NetworkUnchecked>>().unwrap().assume_checked(),
            amount: Amount::from_sat(satoshi),
        }).into()
    }
}
