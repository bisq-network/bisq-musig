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

        if cs_result.is_ok() {
            return cs_result;
        }

        // Take the required and put them inside the optional and replace the required with the
        // imported utxos This is done so that imported utxos always get spent first
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
