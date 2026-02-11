use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf};
use secp::Scalar;

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
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> anyhow::Result<()>;

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    fn import_private_key(&mut self, pk: Scalar);
}
