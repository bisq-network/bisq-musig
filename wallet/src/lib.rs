use bdk_electrum::{
    electrum_client::{self, Client},
    BdkElectrumClient,
};

use bdk_wallet::{
    bitcoin::{bip32::Xpriv, hex::DisplayHex, Amount, Network},
    keys::bip39::Mnemonic,
    rusqlite::{self, named_params, Connection},
    template::{Bip86, DescriptorTemplate},
    AddressInfo, KeychainKind, PersistedWallet, Wallet, WalletPersister,
};

use rand::RngCore;
use secp::Scalar;
use std::vec;

#[allow(unused)]
const ELECTRUM_URL: &str = "ssl://electrum.blockstream.info:6000";

pub trait BMPWalletPersister: WalletPersister {
    type DB;

    fn new(db_path: &str) -> anyhow::Result<Self::DB, <Self as WalletPersister>::Error>;

    fn init(
        db: &mut Self::DB,
        imported_keys_table: Option<&str>,
        seeds_table_name: Option<&str>,
    ) -> anyhow::Result<()>;

    fn persist_seed_phrase(
        db: &mut Self::DB,
        seeds_table_name: &str,
        seed_phrase: &str,
    ) -> anyhow::Result<()>;

    fn load_imported_keys(db: &mut Self::DB, keys_table_name: &str) -> anyhow::Result<Vec<Scalar>>;

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[Scalar],
    ) -> anyhow::Result<()>;

    fn get_seed_phrase(db: &Self::DB, keys_table_name: &str) -> anyhow::Result<String>;
}

impl BMPWalletPersister for Connection {
    type DB = Connection;

    fn new(db_path: &str) -> Result<Self::DB, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Ok(db)
    }

    fn init(
        db: &mut Self::DB,
        imported_keys_table: Option<&str>,
        seeds_table_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let create_imported_keys_table = format!(
            "CREATE TABLE {} ( \
                    key TEXT PRIMARY KEY NOT NULL
                ) STRICT",
            imported_keys_table.unwrap(),
        );

        let create_seeds_table = format!(
            "CREATE TABLE {} ( \
                    seed TEXT PRIMARY KEY NOT NULL
                ) STRICT",
            seeds_table_name.unwrap(),
        );

        let query = format!("{create_imported_keys_table}; {create_seeds_table}");

        let trx = db.transaction()?;

        trx.execute_batch(&query)?;
        trx.commit()?;
        Ok(())
    }

    fn persist_seed_phrase(
        db: &mut Self::DB,
        seeds_table_name: &str,
        seed_phrase: &str,
    ) -> anyhow::Result<()> {
        let trx = db.transaction()?;
        {
            let mut stmt = trx.prepare(&format!(
                "INSERT INTO {}(seed) VALUES(:seed)",
                seeds_table_name
            ))?;

            stmt.execute(named_params! {
                    ":seed": seed_phrase
            })?;
        }

        trx.commit()?;
        Ok(())
    }

    fn load_imported_keys(db: &mut Self::DB, keys_table_name: &str) -> anyhow::Result<Vec<Scalar>> {
        let mut imported_keys: Vec<Scalar> = vec![];

        let mut statement = db.prepare(&format!("SELECT key FROM {}", keys_table_name))?;

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

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[Scalar],
    ) -> anyhow::Result<()> {
        let db_trx = db.transaction()?;
        {
            let mut statement = db_trx.prepare_cached(&format!(
                "INSERT OR IGNORE INTO {} (key) VALUES (:key)",
                keys_table_name
            ))?;

            for key in keys {
                statement.execute(named_params! {
                    ":key": key.serialize().to_lower_hex_string()
                })?;
            }
        }

        db_trx.commit()?;
        Ok(())
    }

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String> {
        let mnemonic = db.query_row(
            &format!("SELECT seed FROM {}", seeds_table_name),
            (),
            |row| row.get::<_, String>("seed"),
        )?;

        Ok(mnemonic)
    }
}

#[allow(unused)]
pub struct BMPWallet<P: BMPWalletPersister> {
    wallet: PersistedWallet<P>,
    client: BdkElectrumClient<Client>,
    imported_keys: Vec<Scalar>,
    db: P,
}

pub trait WalletApi {
    const DB_PATH: &str;
    const SEEDS_TABLE_NAME: &'static str;
    const IMPORTED_KEYS_TABLE_NAME: &'static str;

    fn new(network: Network) -> anyhow::Result<Self>
    where
        Self: Sized;
    fn load_wallet(network: Network) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn next_unused_address(&mut self) -> anyhow::Result<AddressInfo>;

    fn get_seed_phrase(&self) -> anyhow::Result<String>;
    fn import_private_key(&mut self, key: Scalar);

    fn balance(&self) -> Amount;
    fn encrypt(password: &str);
    fn decrypt(password: &str);
}

impl WalletApi for BMPWallet<Connection> {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";
    const DB_PATH: &str = "bmp_bdk_wallet.db3";

    fn new(network: Network) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
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

        let mut db = Connection::new(Self::DB_PATH)?;

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet(&mut db)?;

        Connection::init(
            &mut db,
            Some(Self::IMPORTED_KEYS_TABLE_NAME),
            Some(Self::SEEDS_TABLE_NAME),
        )?;

        let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL)?);

        let mnemonic = Mnemonic::from_entropy(&seed)?;
        let words = mnemonic.to_string();

        Connection::persist_seed_phrase(&mut db, Self::SEEDS_TABLE_NAME, &words)?;

        Ok(Self {
            wallet,
            client,
            imported_keys: vec![],
            db,
        })
    }

    // For already created wallets this will load stored data
    // This will also load the imported keys
    fn load_wallet(network: Network) -> anyhow::Result<Self> {
        let mut db = Connection::open(Self::DB_PATH)?;
        let wallet_opt = Wallet::load().check_network(network).load_wallet(&mut db)?;

        if let Some(wallet) = wallet_opt {
            let imported_keys =
                Connection::load_imported_keys(&mut db, Self::IMPORTED_KEYS_TABLE_NAME)?;
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

    fn next_unused_address(&mut self) -> anyhow::Result<AddressInfo> {
        let addr = self.wallet.next_unused_address(KeychainKind::External);
        // Persist the revealed address, to avoid address reuse
        self.wallet.persist(&mut self.db)?;

        Ok(addr)
    }

    fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    fn get_seed_phrase(&self) -> anyhow::Result<String> {
        Connection::get_seed_phrase(&self.db, Self::SEEDS_TABLE_NAME)
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    fn import_private_key(&mut self, pk: Scalar) {
        self.imported_keys.push(pk);
    }

    fn decrypt(_password: &str) {
        todo!()
    }

    fn encrypt(_password: &str) {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    use crate::{BMPWallet, WalletApi};
    use bdk_wallet::bitcoin::Network;

    #[test]

    fn test_the_test() {
        let _wallet = BMPWallet::new(Network::Bitcoin).unwrap();
    }
}
