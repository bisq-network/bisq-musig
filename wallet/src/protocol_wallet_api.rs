use std::io::Write;
use std::sync::LazyLock;
use bdk_electrum::bdk_core::bitcoin::{absolute, secp256k1, Transaction, Txid, XOnlyPublicKey};
use bdk_electrum::bdk_core::bitcoin::bip32::Xpriv;
use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::Client;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf};
use bdk_wallet::template::{Bip86, DescriptorTemplate};
use bdk_wallet::{AddressInfo, KeychainKind, SignOptions, TxOrdering, Wallet};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor};
use bdk_wallet::miniscript::descriptor::ConversionError;
use bdk_wallet::miniscript::ToPublicKey;
use rand::RngCore;
use secp::Scalar;
use thiserror::Error;


/// The Protocol Wallet API is used by the protocol to create and sign transactions.
/// It's the part of functionality being exposed only to the protocol.
/// The protocol will see `protocol_wallet_api` and the GUI will see `WalletApi`, both are
/// implemented in the `BMPWallet`.
pub trait ProtocolWalletApi {
    fn network(&self) -> Network;

    fn new_address(&mut self) -> anyhow::Result<Address>;

    /// This creates a PSBT for use with the depositTx (but not limited to). You specify the
    /// recipients, consisting of the deposit- (and trade-)amount and spk, and the
    /// `trade_fee_outputs`. This method returns a PSBT with added inputs sufficient to pay the
    /// outputs and an optional change output. NOTE: There might be no change output, if not
    /// needed. The method guarantees that it won't reorder the outputs.
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

pub struct MemWallet {
    wallet: Wallet,
    client: BdkElectrumClient<Client>,
}
// TODO think about stop_gap and batch_size
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

pub(crate) static LIBSECP256K1_CTX: LazyLock<secp256k1::Secp256k1<secp256k1::All>> =
    LazyLock::new(secp256k1::Secp256k1::new);

impl MemWallet {
    pub fn network(&self) -> Network {
        self.wallet.network()
    }

    pub fn reveal_next_address(&mut self) -> Address {
        self.wallet.reveal_next_address(KeychainKind::External).address
    }

    pub fn public_descriptor(&self, chain: KeychainKind) -> &ExtendedDescriptor {
        self.wallet.public_descriptor(chain)
    }
    pub fn new_internal_key(&mut self) -> Result<XOnlyPublicKey, WalletErrorKind> {
        if let Descriptor::Tr(tr) = self.public_descriptor(KeychainKind::External) {
            let ik = tr.internal_key().clone();
            let index = self.wallet.reveal_next_address(KeychainKind::External).index;

            return Ok(ik.at_derivation_index(index)?.derive_public_key(&*LIBSECP256K1_CTX)?
                    .to_x_only_pubkey());
        }
        Err(WalletErrorKind::NotTaprootAddress)
    }

    pub fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Psbt> {
        let mut builder = self.wallet.build_tx();
        builder
                .ordering(TxOrdering::Untouched)
                .nlocktime(absolute::LockTime::ZERO)
                .fee_rate(fee_rate)
                .set_recipients(recipients);
        Ok(builder.finish()?)
    }

    pub fn sign_the_selected_inputs(
        &self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> anyhow::Result<()> {
        let mut psbt_copy = psbt.clone();
        self.wallet.sign(&mut psbt_copy, SignOptions { trust_witness_utxo: true, ..SignOptions::default() })?;

        for i in 0..psbt.inputs.len() {
            if is_selected(&psbt.unsigned_tx.input[i].previous_output) {
                psbt.inputs[i].final_script_sig = psbt_copy.inputs[i].final_script_sig.take();
                psbt.inputs[i].final_script_witness =
                        psbt_copy.inputs[i].final_script_witness.take();
            }
        }
        Ok(())
    }


    pub fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        let result = self.client.transaction_broadcast(tx);

        if let Err(e) = result {
            if e.to_string().contains("Transaction already in block chain") {
                return Ok(tx.compute_txid());
            }
            return Err(e.into());
        }

        Ok(result?)
    }

    pub fn new(client: BdkElectrumClient<Client>) -> anyhow::Result<Self> {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let network: Network = Network::Regtest;
        let xprv: Xpriv = Xpriv::new_master(network, &seed)?;
        tracing::info!(
            "Generated Master Private Key:\n{xprv}\nWarning: be very careful with private \
            keys when using MainNet! We are logging these values for convenience only because this \
            is an example on RegTest.\n"
        );

        let (descriptor, external_map, _) = Bip86(xprv, KeychainKind::External)
                .build(network)
                .expect("Failed to build external descriptor");

        let (change_descriptor, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
                .build(network)
                .expect("Failed to build internal descriptor");

        let wallet = Wallet::create(descriptor, change_descriptor)
                .network(network)
                .keymap(KeychainKind::External, external_map)
                .keymap(KeychainKind::Internal, internal_map)
                .create_wallet_no_persist()?;

        Ok(Self { wallet, client })
    }

    pub fn sync(&mut self) -> anyhow::Result<()> {
        // Populate the electrum client's transaction cache so it doesn't re-download transaction we
        // already have.
        self.client
                .populate_tx_cache(self.wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

        let request = self.wallet.start_full_scan().inspect({
            let mut stdout = std::io::stdout();
            // let mut once = HashSet::<KeychainKind>::new();
            move |_k, _spk_i, _| {
                stdout.flush().expect("must flush");
            }
        });
        tracing::info!("requesting update...");
        let update = self
                .client
                .full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
        self.wallet.apply_update(update)?;
        Ok(())
    }

    pub fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    pub fn next_unused_address(&mut self) -> AddressInfo {
        // FIXME: `next_unused_address` just returns the same unused address over and over. It has
        //  to either be marked as used (which change isn't staged and therefore presumably never
        //  persisted) or a fresh address requested with `reveal_next_address`.
        self.wallet.next_unused_address(KeychainKind::External)
    }

    pub fn funded_wallet(env: &testenv::TestEnv) -> Self {
        let client = BdkElectrumClient::new(Client::new(&env.electrum_url()).unwrap());
        let mut wallet = Self::new(client).unwrap();
        let address = wallet.next_unused_address();
        let txid = env
            .fund_address(&address, Amount::from_btc(10f64).unwrap())
            .unwrap();
        env.mine_block().unwrap();
        env.wait_for_tx(txid).unwrap();
        wallet.sync().unwrap();
        wallet
    }
}

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum WalletErrorKind {
    #[error("not a Taproot address")]
    NotTaprootAddress,
    ConversionError(#[from]ConversionError),
}