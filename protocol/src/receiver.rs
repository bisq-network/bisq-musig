use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, TxOut, Weight};
use std::sync::Arc;

use crate::transaction::Result;

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
}

impl From<&Receiver> for TxOut {
    fn from(value: &Receiver) -> Self {
        Self { value: value.amount, script_pubkey: value.address.script_pubkey() }
    }
}

pub type ReceiverList = Arc<[Receiver]>;
