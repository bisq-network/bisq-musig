use bdk_wallet::bitcoin::{key, Amount, FeeRate, Script};
use bdk_wallet::coin_selection::{
    CoinSelectionAlgorithm, CoinSelectionResult, DefaultCoinSelectionAlgorithm, InsufficientFunds,
};
use bdk_wallet::WeightedUtxo;

#[derive(Debug)]
pub struct AlwaysSpendImportedFirst(pub Vec<WeightedUtxo>);

impl CoinSelectionAlgorithm for AlwaysSpendImportedFirst {
    fn coin_select<R: key::rand::RngCore>(
        &self,
        mut required_utxos: Vec<WeightedUtxo>,
        mut optional_utxos: Vec<WeightedUtxo>,
        fee_rate: FeeRate,
        target_amount: Amount,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        let mut imported_utxos = self.0.clone();

        // Attempt to build the tx with only imported if it fails before adding more utxos
        let bnb = DefaultCoinSelectionAlgorithm::default();
        let cs_result = bnb.coin_select(
            imported_utxos.clone(),
            optional_utxos.clone(),
            fee_rate,
            target_amount,
            drain_script,
            rand,
        );

        match cs_result {
            Ok(res) => Ok(res),
            Err(_) => {
                // Take the required and put them inside the optional and replace the required with
                // the imported utxos This is done so that imported utxos always get
                // spent first
                optional_utxos.append(&mut required_utxos);
                required_utxos.append(&mut imported_utxos);

                bnb.coin_select(
                    required_utxos,
                    optional_utxos,
                    fee_rate,
                    target_amount,
                    drain_script,
                    rand,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use bdk_wallet::bitcoin::key::rand::thread_rng;
    use bdk_wallet::bitcoin::{Amount, FeeRate, ScriptBuf};
    use bdk_wallet::coin_selection::{CoinSelectionAlgorithm, Excess};

    use crate::coin_selection::AlwaysSpendImportedFirst;
    use crate::test_utils::{confirmed_utxo, foreign_utxo};

    #[test]
    fn test_coin_selection() {
        let mut imported_utxos = (0..1)
            .map(|i| foreign_utxo(Amount::from_int_btc(1), i))
            .collect::<Vec<_>>();

        imported_utxos.push(foreign_utxo(Amount::from_btc(0.3).unwrap(), 0));

        let local_utxos = (0..3)
            .map(|i| confirmed_utxo(Amount::from_int_btc(1), i, 1, 1231006505))
            .collect::<Vec<_>>();

        let selection_strategy = AlwaysSpendImportedFirst(imported_utxos.clone());
        let target_amount = Amount::from_int_btc(1);
        let drain_script = ScriptBuf::default();

        let res = selection_strategy
            .coin_select(
                imported_utxos.clone(),
                local_utxos.clone(),
                FeeRate::from_sat_per_kwu(50000),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        // Target amount is 1 BTC so the selected coins + fees should be from foreign
        let selected = res.selected;

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].txout().script_pubkey.as_bytes(), vec![0, 0, 1]);

        // Target amount is 1.5 imported only have 1.3 so this will include another output from main
        // wallet
        let target_amount = Amount::from_btc(1.5).unwrap();

        let res = selection_strategy
            .coin_select(
                imported_utxos.clone(),
                local_utxos.clone(),
                FeeRate::from_sat_per_kwu(50000),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(res.selected.len(), 3);
        assert!(matches!(res.excess, Excess::Change { amount: _, fee: _ }));

        // Target is 0.5 and there's no imported keys, the main wallet should be able to fulfill
        let target_amount = Amount::from_btc(0.5).unwrap();
        let selection_strategy = AlwaysSpendImportedFirst(vec![]);

        let res = selection_strategy
            .coin_select(
                imported_utxos.clone(),
                local_utxos.clone(),
                FeeRate::from_sat_per_kwu(50000),
                target_amount,
                &drain_script,
                &mut thread_rng(),
            )
            .unwrap();

        assert_eq!(res.selected.len(), 1);
        assert!(matches!(res.excess, Excess::Change { amount: _, fee: _ }));
    }
}
