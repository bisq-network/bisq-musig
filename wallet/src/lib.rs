use bdk_electrum::{
    electrum_client::{self, Client},
    BdkElectrumClient,
};

use bdk_wallet::{
    bitcoin::{bip32::Xpriv, hex::DisplayHex, Amount, Network},
    chain::Merge,
    keys::bip39::Mnemonic,
    rusqlite::{self, named_params, Connection},
    template::{Bip86, DescriptorTemplate},
    AddressInfo, ChangeSet, KeychainKind, PersistedWallet, Wallet, WalletPersister,
};

use rand::RngCore;
use secp::Scalar;
use std::{
    ops::{Deref, DerefMut},
    vec,
};

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

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error>;
}

impl BMPWalletPersister for Connection {
    type DB = Connection;

    fn new(db_path: &str) -> Result<Self::DB, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Ok(db)
    }

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error> {
        Connection::persist(db, cs)
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

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo>;
    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo>;

    fn get_seed_phrase(&self) -> anyhow::Result<String>;
    fn import_private_key(&mut self, key: Scalar);

    fn balance(&self) -> Amount;
    fn encrypt(password: &str);
    fn decrypt(password: &str);

    fn persist(&mut self) -> anyhow::Result<bool>;
}

impl WalletApi for BMPWallet<Connection> {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";
    const DB_PATH: &str = "bmp_bdk_wallet.db3";

    fn persist(&mut self) -> anyhow::Result<bool> {
        // Persist imported keys and then persist staged changes from ChangeSet
        let _ = Connection::persist_imported_keys(
            &mut self.db,
            Self::IMPORTED_KEYS_TABLE_NAME,
            &self.imported_keys,
        );

        match self.wallet.staged_mut() {
            Some(stage) => {
                Connection::persist_staged_changes(&mut self.db, &*stage)?;
                let _ = stage.take();
                Ok(true)
            }
            None => Ok(false),
        }
    }

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

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo> {
        let addr = self.wallet.next_unused_address(KeychainKind::External);
        // Persist the revealed address, to avoid address reuse
        self.persist()?;

        Ok(addr)
    }

    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo> {
        let addr = self.wallet.next_unused_address(KeychainKind::Internal);
        // Persist the revealed address, to avoid address reuse
        self.persist()?;

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

impl Deref for BMPWallet<Connection> {
    type Target = PersistedWallet<Connection>;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for BMPWallet<Connection> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
#[cfg(test)]
mod tests {

    use crate::{BMPWallet, WalletApi};
    use bdk_wallet::{
        bitcoin::{hashes::Hash, AddressType, Amount, BlockHash, Network},
        chain::{self, BlockId},
        test_utils::{receive_output_to_address, ReceiveTo},
        AddressInfo, KeychainKind,
    };
    use rand::RngCore;
    use secp::Scalar;
    use simple_semaphore::{self, Semaphore};
    use std::sync::Arc;
    use tempfile::{tempdir, TempDir};

    static SEMAPHORE: once_cell::sync::Lazy<Arc<Semaphore>> =
        once_cell::sync::Lazy::new(|| Semaphore::new(1));

    fn tear_up() -> TempDir {
        let tmp_dir = tempdir().unwrap();
        std::env::set_current_dir(tmp_dir.path()).unwrap();
        tmp_dir
    }

    fn new_private_key() -> Scalar {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Scalar::from_slice(&seed).unwrap()
    }

    #[test]
    fn test_create_wallet() -> anyhow::Result<()> {
        let permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let mut bmp_wallet = BMPWallet::new(Network::Bitcoin)?;
        assert_eq!(bmp_wallet.imported_keys.len(), 0);
        assert_eq!(bmp_wallet.balance(), Amount::from_sat(0));

        let seed = bmp_wallet.get_seed_phrase()?;

        println!("Generated mnemonic {} ", seed);
        assert_eq!(seed.len() > 0, true);

        let receiving_addr = bmp_wallet.get_new_address()?;

        assert_eq!(receiving_addr.address_type(), Some(AddressType::P2tr));

        println!("Generated address {:?}", receiving_addr);

        // Mark address as used and make sure next address will be different.
        assert!(bmp_wallet.mark_used(KeychainKind::External, receiving_addr.index));

        let new_receiving_addr = bmp_wallet.get_new_address()?;

        assert_ne!(
            bmp_wallet.next_derivation_index(KeychainKind::External),
            new_receiving_addr.index
        );

        assert_ne!(new_receiving_addr, receiving_addr);

        drop(permit);
        Ok(())
    }

    #[test]
    fn test_load_wallet() -> anyhow::Result<()> {
        let permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let stored_seed: String;
        let stored_balance: Amount;
        let last_generated_addr: AddressInfo;

        {
            let mut wallet = BMPWallet::new(Network::Regtest)?;
            assert_eq!(wallet.imported_keys.len(), 0);
            stored_balance = wallet.balance();
            stored_seed = wallet.get_seed_phrase().unwrap();
            last_generated_addr = wallet.get_new_address()?;

            receive_output_to_address(
                &mut wallet,
                last_generated_addr.address.clone(),
                Amount::ONE_BTC * 2,
                ReceiveTo::Block(chain::ConfirmationBlockTime {
                    block_id: BlockId {
                        height: 2,
                        hash: BlockHash::all_zeros(),
                    },
                    confirmation_time: 2,
                }),
            );

            wallet.persist()?;
        }

        let mut wallet = BMPWallet::load_wallet(Network::Regtest)?;
        let loaded_seed = wallet.get_seed_phrase()?;

        let new_receiving_addr = wallet.get_new_address()?;

        assert_eq!(wallet.imported_keys.len(), 0);
        assert_eq!(wallet.balance(), stored_balance);
        assert_eq!(loaded_seed, stored_seed);

        // After reloading with previously used address make sure the next generated one is different
        assert_ne!(new_receiving_addr, last_generated_addr);

        drop(permit);
        Ok(())
    }

    #[test]
    fn test_imported_keys() -> anyhow::Result<()> {
        let permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;
        let pk1 = new_private_key();
        let pk2 = new_private_key();

        bmp_wallet.import_private_key(pk1);
        bmp_wallet.import_private_key(pk2);

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        // Persist
        bmp_wallet.persist()?;

        let loaded_wallet = BMPWallet::load_wallet(Network::Regtest)?;

        assert_eq!(loaded_wallet.imported_keys, bmp_wallet.imported_keys);

        drop(permit);
        Ok(())
    }
}
