use anyhow::Ok;
use bdk_electrum::{BdkElectrumClient, electrum_client};
use bdk_wallet::{
    bitcoin::{self, bip32::Xpriv, Amount, FeeRate, Network, Script}, chain::Impl, coin_selection::{CoinSelectionAlgorithm, CoinSelectionResult, InsufficientFunds}, keys::SinglePriv, rusqlite::{self, named_params, Connection, ToSql}, template::{Bip86, DescriptorTemplate}, AddressInfo, KeychainKind, PersistedWallet, Wallet, WeightedUtxo
};
use rand::RngCore;
use std::collections::HashSet;
use std::vec;

const DB_PATH: &str = "bmp_bdk_wallet.db3";
const IMPORTED_KEYS_BD: &str = "bmp_imported_keys.db3";
const ELECTRUM_URL: &str = "http://localhost:8080";

pub struct BMPWallet {
    wallet: PersistedWallet<rusqlite::Connection>,
    client: BdkElectrumClient<electrum_client::Client>,
    imported_keys: Vec<SinglePriv>,
    db: rusqlite::Connection,
}

#[derive(Debug)]
struct AlwaysSpendImportedFirst;

impl CoinSelectionAlgorithm for AlwaysSpendImportedFirst {
    fn coin_select<R: bitcoin::key::rand::RngCore>(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        optional_utxos: Vec<WeightedUtxo>,
        fee_rate: FeeRate,
        target_amount: Amount,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        todo!()
    }
}

impl BMPWallet {
    const IMPORTED_KEYS_SCHEMA_NAME: &'static str = "bmp_imported_keys";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";

    pub fn schema() -> String {
        format!(
            "CREATE TABLE {} ( \
                id INTEGER PRIMARY KEY NOT NULL CHECK (id = 0), \
                key TEXT, \
                network TEXT \
                ) STRICT;",
            Self::IMPORTED_KEYS_TABLE_NAME,
        )
    }

    pub fn init_sqlite(db_tx: &mut rusqlite::Connection) -> anyhow::Result<()> {
        let trx = db_tx.transaction().expect("Can't get db transaction");

        trx.execute(&Self::schema(), ())?;
        trx.commit()?;

        Ok(())
    }

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

        Self::init_sqlite(&mut db)?;

        Ok(Self {
            wallet,
            client,
            imported_keys: vec![],
            db,
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
        let addr = self.wallet.next_unused_address(KeychainKind::External);

        // Persist the revealed address, to avoid address reuse
        self.wallet.persist(&mut self.db).expect("Write is okay");

        addr
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    pub fn import_private_key(&mut self, pk: SinglePriv) {
        self.imported_keys.push(pk);
    }


    fn persist_to_sqlite(keys: &Vec<SinglePriv>, network: Network, db_trx: &mut rusqlite::Transaction) -> anyhow::Result<()> {        
        let mut statement = db_trx.prepare_cached(&format!(
            "INSERT INTO {} (key, network) VALUES (:key, :network)",
            Self::IMPORTED_KEYS_TABLE_NAME
        ))?;

        for key in keys {
            statement.execute(
                named_params! {
                    ":key": key.key.to_wif(),
                    ":network": Impl(network)
                }
            )?;
        };
        Ok(())
    }

    // This will persist the imported_keys vector, which are keys imported during trade ops
    // The keys are stored inside rusqlite kv database
    pub fn persist_imported_keys(&mut self) -> anyhow::Result<()> {
        let mut db_trx = self.db.transaction()?;
        Self::persist_to_sqlite(&self.imported_keys, self.wallet.network(), &mut db_trx)?;
        db_trx.commit()?;
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

    #[test]
    fn test_persist_imported_keys() -> anyhow::Result<()> {

        Ok(())
    }
}
