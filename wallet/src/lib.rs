use std::vec;

use anyhow::Ok;
use bdk_electrum::{BdkElectrumClient, electrum_client};
use bdk_wallet::{
    AddressInfo, KeychainKind, PersistedWallet, Wallet,
    bitcoin::{Amount, Network, bip32::Xpriv},
    coin_selection::{CoinSelectionAlgorithm, CoinSelectionResult, InsufficientFunds},
    keys::SinglePriv,
    rusqlite::Connection,
    template::{Bip86, DescriptorTemplate},
};
use rand::RngCore;

const DB_PATH: &str = "bmp_bdk_wallet.db3";
const IMPORTED_KEYS_BD: &str = "bmp_imported_keys.db3";
const ELECTRUM_URL: &str = "http://localhost:8080";

pub struct BMPWallet {
    wallet: PersistedWallet<Connection>,
    client: BdkElectrumClient<electrum_client::Client>,
    imported_keys: Vec<SinglePriv>,
}

#[derive(Debug)]
struct AlwaysSpendImportedFirst;

impl CoinSelectionAlgorithm for AlwaysSpendImportedFirst {
    fn coin_select<R: bdk_wallet::bitcoin::key::rand::RngCore>(
        &self,
        required_utxos: Vec<bdk_wallet::WeightedUtxo>,
        optional_utxos: Vec<bdk_wallet::WeightedUtxo>,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
        target_amount: Amount,
        drain_script: &bdk_wallet::bitcoin::Script,
        rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        todo!()
    }
}

impl BMPWallet {
    // Create a new wallet
    // 1-
    pub fn new(network: Network) -> anyhow::Result<Self> {
        // TODO: Make the word size configurable?
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let xprv = Xpriv::new_master(network, &seed)?;

        let (descriptor, external_map, _) = Bip86(xprv, KeychainKind::External)
            .build(network)
            .expect("Failed to build external descriptor");

        let (change_descriptor, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
            .build(network)
            .expect("Failed to build internal descriptor");

        let mut db = Connection::open(DB_PATH)?;

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet(&mut db)?;

        let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL)?);

        Ok(Self {
            wallet,
            client,
            imported_keys: vec![],
        })
    }

    // Create a new wallet from the passed mnemonic
    // Word count can be inferred
    pub fn from_mnemonic(network: Network, mnemonic: &str) -> anyhow::Result<()> {
        Ok(())
    }

    // For already created wallets this will load stored data
    // This will also load the imported keys
    pub fn load_wallet() -> anyhow::Result<()> {
        Ok(())
    }

    // Retrieve the balance of the main wallet
    // This should also take into account the balance of the imported keys
    pub fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    // Generate a new bitcoin address, we don't take into account addresses from imported keys
    pub fn next_unused_address(&mut self) -> AddressInfo {
        self.wallet.next_unused_address(KeychainKind::External)
    }

    // Import an external private from the HD wallet
    pub fn import_private_key(&mut self, pk: SinglePriv) {
        self.imported_keys.push(pk);
    }

    // This will persist the external_keys vector, which are keys imported duing trade ops
    // The keys are stored inside rusqlite kv database
    pub fn persist_imported_keys(&self) -> anyhow::Result<()> {
        let mut db = Connection::open(IMPORTED_KEYS_BD)?;

        self.imported_keys.iter().for_each(|key| {
            let query = "";
        });
        Ok(())
    }

    // Sync the main wallet and taking into account the imported keys data
    //
    pub fn sync() -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]

mod tests {
    use crate::BMPWallet;
    use bdk_wallet::{Wallet, bitcoin::Network};

    #[test]
    fn test_create_wallet() -> anyhow::Result<()> {
        let bmp_wallet2 = BMPWallet::new(Network::Regtest);
        Ok(())
    }

    #[test]
    fn test_create_wallet_from_mnemonic() -> anyhow::Result<()> {
        let bmp_wallet = BMPWallet::from_mnemonic(Network::Regtest, "h b c d");
        Ok(())
    }

    #[test]
    fn test_load_wallet() -> anyhow::Result<()> {
        let existing_wallet = BMPWallet::load_wallet();
        Ok(())
    }
}
