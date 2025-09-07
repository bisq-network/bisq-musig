use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{self, Client},
};
use bdk_wallet::{
    AddressInfo, KeychainKind, PersistedWallet, Wallet,
    bitcoin::{Amount, Network, bip32::Xpriv, hex::DisplayHex},
    keys::bip39::Mnemonic,
    rusqlite::{self, Connection, named_params},
    template::{Bip86, DescriptorTemplate},
};

use rand::RngCore;
use secp::Scalar;
use std::vec;

const DB_PATH: &str = "bmp_bdk_wallet.db3";
const ELECTRUM_URL: &str = "ssl://electrum.blockstream.info:6000";

#[allow(unused)]
pub struct BMPWallet {
    wallet: PersistedWallet<Connection>,
    client: BdkElectrumClient<Client>,
    imported_keys: Vec<Scalar>,
    db: Connection,
}

// @TODO: revisit here for double persistance
impl Drop for BMPWallet {
    fn drop(&mut self) {
        let _ = self
            .wallet
            .persist(&mut self.db)
            .inspect_err(|e| eprintln!("Error occured while persisting: {e:?}"));

        let _ = self
            .persist_imported_keys()
            .inspect(|e| eprintln!("Error occured while persisting: {e:?}"));
    }
}

impl BMPWallet {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";

    fn schema() -> String {
        let create_imported_keys_table = format!(
            "CREATE TABLE {} ( \
                key TEXT PRIMARY KEY NOT NULL
            ) STRICT",
            Self::IMPORTED_KEYS_TABLE_NAME,
        );

        let create_seeds_table = format!(
            "CREATE TABLE {} ( \
                seed TEXT PRIMARY KEY NOT NULL
            ) STRICT",
            Self::SEEDS_TABLE_NAME,
        );

        format!("{create_imported_keys_table}; {create_seeds_table}")
    }

    fn init_sqlite(db_tx: &mut rusqlite::Connection) -> anyhow::Result<()> {
        let trx = db_tx.transaction()?;
        trx.execute_batch(&Self::schema())?;
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
            .expect("External description generation should not fail");

        let (change_descriptor, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
            .build(network)
            .expect("Internal description generation should not fail");

        let mut db = Connection::open(DB_PATH)?;

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet(&mut db)?;

        let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL)?);

        Self::init_sqlite(&mut db)?;

        let mnemonic = Mnemonic::from_entropy(&seed)?;
        let words = mnemonic.to_string();

        Self::persist_seed_phrase(&words, &mut db)?;

        Ok(Self {
            wallet,
            client,
            imported_keys: vec![],
            db,
        })
    }

    fn persist_seed_query(
        mnemonic: &str,
        db_trx: &mut rusqlite::Transaction,
    ) -> anyhow::Result<()> {
        let mut stmt = db_trx.prepare(&format!(
            "INSERT INTO {}(seed) VALUES(:seed)",
            Self::SEEDS_TABLE_NAME
        ))?;
        stmt.execute(named_params! {
                ":seed": mnemonic
        })?;
        Ok(())
    }

    fn persist_seed_phrase(mnemonic: &str, db: &mut rusqlite::Connection) -> anyhow::Result<()> {
        let mut trx = db.transaction()?;
        Self::persist_seed_query(mnemonic, &mut trx)?;
        trx.commit()?;
        Ok(())
    }

    // Create a new wallet from the passed mnemonic
    // Word count can be inferred
    pub fn from_mnemonic(_mnemonic: &str, _network: Network) -> anyhow::Result<()> {
        Ok(())
    }

    fn load_imported_keys(db: &Connection) -> anyhow::Result<Vec<Scalar>> {
        let mut imported_keys: Vec<Scalar> = vec![];

        let mut statement = db.prepare(&format!(
            "SELECT key FROM {}",
            Self::IMPORTED_KEYS_TABLE_NAME
        ))?;

        let row_iter = statement.query_map([], |row| {
            anyhow::Result::Ok((row.get::<_, String>("key")?,))
        })?;

        for row in row_iter {
            let hex_key = row?;
            let secret = Scalar::from_hex(&hex_key.0)?;
            imported_keys.push(secret);
        }

        Ok(imported_keys)
    }

    // For already created wallets this will load stored data
    // This will also load the imported keys
    pub fn load_wallet(network: Network) -> anyhow::Result<Self> {
        let mut db = Connection::open(DB_PATH)?;
        let wallet_opt = Wallet::load().check_network(network).load_wallet(&mut db)?;

        if let Some(wallet) = wallet_opt {
            let imported_keys = Self::load_imported_keys(&db)?;
            let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL)?);

            return Ok(Self {
                wallet,
                client,
                imported_keys,
                db,
            });
        }

        Err(anyhow::anyhow!("Unable to load wallet"))
    }

    // Retrieve the balance of the main wallet
    // This should also take into account the balance of the imported keys
    pub fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    // Generate a new bitcoin address, we don't take into account addresses from imported keys
    pub fn next_unused_address(&mut self) -> anyhow::Result<AddressInfo> {
        let addr = self.wallet.next_unused_address(KeychainKind::External);
        // Persist the revealed address, to avoid address reuse
        self.wallet.persist(&mut self.db)?;

        Ok(addr)
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    pub fn import_private_key(&mut self, pk: Scalar) {
        self.imported_keys.push(pk);
    }

    fn persist_imported_keys_query(
        keys: &Vec<Scalar>,
        db_trx: &mut rusqlite::Transaction,
    ) -> anyhow::Result<()> {
        let mut statement = db_trx.prepare_cached(&format!(
            "INSERT OR IGNORE INTO {} (key) VALUES (:key)",
            Self::IMPORTED_KEYS_TABLE_NAME
        ))?;

        for key in keys {
            statement.execute(named_params! {
                ":key": key.serialize().to_lower_hex_string()
            })?;
        }
        Ok(())
    }

    // Return the generated mnemonic phrase
    pub fn get_seed_phrase(&self) -> anyhow::Result<String> {
        let mnemonic = self.db.query_row(
            &format!("SELECT seed FROM {}", Self::SEEDS_TABLE_NAME),
            (),
            |row| row.get::<_, String>("seed"),
        )?;

        Ok(mnemonic)
    }

    // This will persist the imported_keys vector, which are keys imported during trade ops
    // The keys are stored inside rusqlite kv database
    pub fn persist_imported_keys(&mut self) -> anyhow::Result<()> {
        let mut db_trx = self.db.transaction()?;
        Self::persist_imported_keys_query(&self.imported_keys, &mut db_trx)?;
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
    use std::fs;

    use crate::{BMPWallet, DB_PATH};
    use bdk_wallet::{
        KeychainKind,
        bitcoin::{Amount, Network},
    };
    use rand::RngCore;
    use secp::Scalar;

    fn tear_down() {
        fs::remove_file(DB_PATH).expect("DB should be removed after tests");
    }

    #[test]
    fn test_create_wallet() -> anyhow::Result<()> {
        let mut bmp_wallet2 = BMPWallet::new(Network::Regtest)?;
        assert_eq!(bmp_wallet2.balance(), Amount::from_sat(0));

        let addr1 = bmp_wallet2.next_unused_address()?;
        let addr2 = bmp_wallet2.next_unused_address()?;

        println!("Addr1 {}", addr1);
        println!("Addr2 {}", addr2);

        assert_eq!(addr1, addr2);

        bmp_wallet2
            .wallet
            .mark_used(KeychainKind::External, addr1.index);

        let addr2 = bmp_wallet2.next_unused_address()?;

        assert_ne!(addr1, addr2);

        tear_down();

        Ok(())
    }

    #[test]
    fn test_create_wallet_from_mnemonic() -> anyhow::Result<()> {
        let _bmp_wallet = BMPWallet::from_mnemonic("h b c d", Network::Regtest);
        Ok(())
    }

    #[test]
    fn test_load_wallet() -> anyhow::Result<()> {
        let mut seed: [u8; 32] = [0u8; 32];
        let mut seed2: [u8; 32] = [0u8; 32];

        rand::rng().fill_bytes(&mut seed);
        rand::rng().fill_bytes(&mut seed2);

        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;
        assert_eq!(bmp_wallet.balance(), Amount::from_sat(0));

        let pk1 = Scalar::from_slice(&seed)?;
        let pk2 = Scalar::from_slice(&seed2)?;

        bmp_wallet.import_private_key(pk1);
        bmp_wallet.import_private_key(pk2);

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        bmp_wallet.persist_imported_keys().unwrap();

        let loaded_wallet = BMPWallet::load_wallet(Network::Regtest)?;

        assert_eq!(bmp_wallet.imported_keys, loaded_wallet.imported_keys);
        assert_eq!(bmp_wallet.balance(), loaded_wallet.balance());

        tear_down();
        Ok(())
    }

    #[test]
    fn test_persist_imported_keys() -> anyhow::Result<()> {
        Ok(())
    }
}
