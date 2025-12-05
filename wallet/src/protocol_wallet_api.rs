use crate::bmp_wallet::BMPWallet;
use bdk_wallet::bitcoin::secp256k1::Scalar;
use bdk_wallet::bitcoin::{absolute, Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, TxOrdering, Wallet};

/// The Protocol Wallet API is used by the protocol to create and sign transactions.
/// It's the part of functionality being exposed only to the protocol.
/// The protocol will see `protocol_wallet_api` and the GUI will see `WalletApi`, both are implemented in the BMPWallet.
pub trait ProtocolWalletApi {
    fn network(&self) -> Network;

    fn new_address(&mut self) -> anyhow::Result<Address>;

    ///  this creates a PSBT for use with the depositTx (but not limited to). You specify the recipients, consisting of the
    /// deposit- (and trade-)amount and spk, and the trade_fee_outputs.
    /// This method returns a PSBT with added inputs sufficient to pay the outputs and an optional change output.
    /// NOTE: There might be no change output, if not needed.
    /// The method guarantees that it won't reorder the outputs.
    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Psbt>;

    fn sign_selected_inputs(
        &self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> anyhow::Result<()>;

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    fn import_private_key(&mut self, pk: Scalar);
}
impl ProtocolWalletApi for BMPWallet<Connection> {
    fn network(&self) -> Network {
        todo!()
    }

    fn new_address(&mut self) -> anyhow::Result<Address> {
        Ok(self.next_address(KeychainKind::External)?.address)
    }

    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Psbt> {
        todo!()
    }

    fn sign_selected_inputs(
        &self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> anyhow::Result<()> {
        todo!()
    }

    fn import_private_key(&mut self, pk: Scalar) {
        todo!()
    }
}

/// This is a sample implementation, only for demonstration purpose.
/// It doesn't make sense to implement the protocol_wallet_api trait for Wallet, it should be implemented for BMPWallet.
impl ProtocolWalletApi for Wallet {
    fn network(&self) -> Network {
        self.network()
    }

    fn new_address(&mut self) -> anyhow::Result<Address> {
        Ok(self.next_unused_address(KeychainKind::External).address)
    }


    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Psbt> {
        let mut builder = self.build_tx();
        builder
                .ordering(TxOrdering::Untouched)
                .nlocktime(absolute::LockTime::ZERO)
                .fee_rate(fee_rate)
                .set_recipients(recipients);
        Ok(builder.finish()?)
    }

    fn sign_selected_inputs(&self, psbt: &mut Psbt, is_selected: &dyn Fn(&OutPoint) -> bool) -> anyhow::Result<()> {
        let mut psbt_copy = psbt.clone();
        self.sign(&mut psbt_copy, bdk_wallet::SignOptions::default())?;
        for i in 0..psbt.inputs.len() {
            if is_selected(&psbt.unsigned_tx.input[i].previous_output) {
                psbt.inputs[i].final_script_sig = psbt_copy.inputs[i].final_script_sig.take();
                psbt.inputs[i].final_script_witness = psbt_copy.inputs[i].final_script_witness.take();
            }
        }
        Ok(())
    }

    fn import_private_key(&mut self, pk: Scalar) {
        todo!()
    }
}
