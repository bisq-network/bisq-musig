use std::ops::{Deref, DerefMut};
use std::vec;

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hex::DisplayHex;
use bdk_wallet::bitcoin::{
    psbt, Amount, Network, PrivateKey, Psbt, ScriptBuf, Sequence, Weight, XOnlyPublicKey,
};
use bdk_wallet::chain::Merge;
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::rusqlite::{self, named_params, Connection};
use bdk_wallet::signer::{InputSigner, SignerContext, SignerError, SignerWrapper};
use bdk_wallet::template::{Bip86, DescriptorTemplate};
use bdk_wallet::{
    AddressInfo, Balance, ChangeSet, KeychainKind, PersistedWallet, SignOptions, TxBuilder, Utxo,
    Wallet, WalletPersister, WeightedUtxo,
};
use rand::RngCore;
use secp::Scalar;

use crate::chain_data_source::ChainDataSource;
use crate::coin_selection::AlwaysSpendImportedFirst;

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

        let row_iter = statement.query_map([], |row| Ok((row.get::<_, String>("key")?,)))?;

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
    imported_keys: Vec<Scalar>,
    imported_balance: Balance,
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

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst>;

    fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> anyhow::Result<(), SignerError>;

    fn sync_all(&mut self, data_source: &impl ChainDataSource) -> anyhow::Result<bool>;
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

    fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> anyhow::Result<(), SignerError> {
        //// @TODO perfomance: cache the public keys derivation
        let secp = self.secp_ctx();
        let is_mine = |input_script: &ScriptBuf| {
            for key in &self.imported_keys {
                let xonly_pubkey = key.base_point_mul().serialize_xonly();
                let xonly_pubkey = XOnlyPublicKey::from_slice(&xonly_pubkey)
                    .expect("Should be valid xonlypub key");
                let script = ScriptBuf::new_p2tr(secp, xonly_pubkey, None);

                if script == *input_script {
                    return Some(*key);
                }
            }
            None
        };

        for (input_index, input_details) in psbt.inputs.clone().iter().enumerate() {
            let txout = input_details.witness_utxo.as_ref().unwrap();

            if let Some(signing_key) = is_mine(&txout.script_pubkey) {
                let signer = PrivateKey::from_slice(&signing_key.serialize(), self.network())
                    .map_err(|_e| SignerError::External("Invalid signing key".to_string()))?;

                let sw = SignerWrapper::new(
                    signer,
                    SignerContext::Tap {
                        is_internal_key: true,
                    },
                );

                sw.sign_input(psbt, input_index, &sign_options, secp)?;
                psbt.finalize_inp_mut(secp, input_index)
                    .map_err(|_e| SignerError::External("Unable to finalized input".to_string()))?;
            }
        }

        let finalized = self.wallet.sign(psbt, sign_options)?;
        assert!(finalized, "PSBT should be finalized");

        Ok(())
    }

    fn sync_all(&mut self, data_source: &impl ChainDataSource) -> anyhow::Result<bool> {
        // 1. Sync the main wallet
        data_source.sync(&mut self.wallet)?;

        let mut final_imported_balance = Balance::default();

        // 2. Sync the imported keys
        // @TODO: we can spawn threads later on to speed up the process

        for key in self.imported_keys.clone() {
            let pbk = key.base_point_mul();
            let pubk = pbk.serialize_xonly().to_lower_hex_string();
            let db_path = format!("bmp_{}.db3", pubk);

            let mut db = Connection::open(db_path)?;
            let imported_wallet_opt = Wallet::load()
                .check_network(self.wallet.network())
                .extract_keys()
                .load_wallet(&mut db)?;

            let mut imported_wallet = match imported_wallet_opt {
                Some(wallet) => wallet,
                None => {
                    let descriptor = format!("tr({})", pubk);

                    Wallet::create_single(descriptor)
                        .network(self.wallet.network())
                        .create_wallet(&mut db)?
                }
            };

            data_source.sync(&mut imported_wallet)?;

            final_imported_balance = final_imported_balance + imported_wallet.balance();

            // For having accurate Wallet::calculate_fee and Wallet::calculate_fee_rate
            for utxo in imported_wallet.list_unspent() {
                self.insert_txout(utxo.outpoint, utxo.txout);
            }

            imported_wallet.persist(&mut db)?;
        }

        self.imported_balance = final_imported_balance;

        self.persist()
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

        let mnemonic = Mnemonic::from_entropy(&seed)?;
        let words = mnemonic.to_string();

        Connection::persist_seed_phrase(&mut db, Self::SEEDS_TABLE_NAME, &words)?;

        Ok(Self {
            wallet,
            imported_keys: vec![],
            imported_balance: Balance::default(),
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

            return Ok(Self {
                wallet,
                imported_keys,
                imported_balance: Balance::default(),
                db,
            });
        }

        Err(anyhow::anyhow!("Unable to load wallet"))
    }

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst> {
        let secp = self.secp_ctx();
        let imported_weighted_utxos = self
            .tx_graph()
            .floating_txouts()
            .map(|utxo| {
                let output_script_pubkey = &utxo.1.script_pubkey;

                let tap_internal_key = self
                    .imported_keys
                    .iter()
                    .map(|scalar| {
                        let pbk = scalar.base_point_mul().serialize_xonly();
                        XOnlyPublicKey::from_slice(&pbk)
                            .expect("Should be valid xonlypub key")
                    })
                    .find(|pubkey| {
                       let script = ScriptBuf::new_p2tr(secp, *pubkey, None);
                        script == *output_script_pubkey
                    });

                WeightedUtxo {
                    utxo: Utxo::Foreign {
                        outpoint: utxo.0,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        psbt_input: Box::new(psbt::Input {
                            witness_utxo: Some(utxo.1.clone()),
                            tap_internal_key,
                            ..Default::default()
                        }),
                    },
                    satisfaction_weight: Weight::from_wu_usize(65),
                }
            })
            .collect::<Vec<_>>();

        let coin_selection = AlwaysSpendImportedFirst(imported_weighted_utxos);
        self.wallet.build_tx().coin_selection(coin_selection)
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
        (self.imported_balance.clone() + self.wallet.balance()).trusted_spendable()
    }

    fn get_seed_phrase(&self) -> anyhow::Result<String> {
        Connection::get_seed_phrase(&self.db, Self::SEEDS_TABLE_NAME)
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    // TODO move this implementation to trait ProtocolWalletApi
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
    use std::sync::Arc;

    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{psbt, Address, AddressType, Amount, BlockHash, Network, Weight};
    use bdk_wallet::chain::{self, BlockId};
    use bdk_wallet::test_utils::{receive_output_to_address, ReceiveTo};
    use bdk_wallet::{AddressInfo, KeychainKind, SignOptions};
    use rand::RngCore;
    use secp::Scalar;
    use simple_semaphore::{self, Semaphore};
    use tempfile::{tempdir, TempDir};

    use crate::bmp_wallet::{BMPWallet, WalletApi};
    use crate::test_utils::{derive_public_key, load_imported_wallet, MockedBDKElectrum};

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
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;
        assert_eq!(bmp_wallet.imported_keys.len(), 0);
        assert_eq!(bmp_wallet.balance(), Amount::from_sat(0));

        let seed = bmp_wallet.get_seed_phrase()?;

        println!("Generated mnemonic {} ", seed);
        assert!(!seed.is_empty());

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
        Ok(())
    }

    #[test]
    fn test_load_wallet() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
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

        // After reloading with previously used address make sure the next generated one is
        // different
        assert_ne!(new_receiving_addr, last_generated_addr);
        Ok(())
    }

    #[test]
    fn test_imported_keys() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
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
        Ok(())
    }

    #[test]
    fn test_sync() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let mut bmp_wallet = BMPWallet::new(Network::Bitcoin)?;
        let client = MockedBDKElectrum {};

        println!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        let _ = bmp_wallet.sync_all(&client);

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(1));

        println!("Wallet balance after syncing {}", bmp_wallet.balance());

        println!("{:#?}", bmp_wallet.tx_graph());
        Ok(())
    }

    #[test]
    fn test_sync_with_imported_keys() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let pk1 = new_private_key();
        let pk2 = new_private_key();

        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;

        bmp_wallet.import_private_key(pk1);
        bmp_wallet.import_private_key(pk2);

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        let client = MockedBDKElectrum {};

        println!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        let _ = bmp_wallet.sync_all(&client);

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        println!("Wallet balance after syncing {}", bmp_wallet.balance());
        Ok(())
    }

    #[test]

    fn sign_inputs_main_wallet_only() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let client = MockedBDKElectrum {};
        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;

        println!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        let _ = bmp_wallet.sync_all(&client);

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(1));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_sat(100_000);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(res_psbt
            .inputs
            .iter()
            .all(|i| i.final_script_witness.is_some()));

        Ok(())
    }

    #[test]
    fn sign_inputs_main_and_imported_keys() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let client = MockedBDKElectrum {};
        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;

        let keys_to_import = [new_private_key(), new_private_key()];
        keys_to_import
            .iter()
            .for_each(|k| bmp_wallet.import_private_key(*k));

        println!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        let _ = bmp_wallet.sync_all(&client);

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let first_key_wallet = load_imported_wallet(&keys_to_import[0])?;
        let second_key_wallet = load_imported_wallet(&keys_to_import[1])?;

        let first_key_unspents = first_key_wallet.list_unspent().collect::<Vec<_>>();
        let second_key_unspents = second_key_wallet.list_unspent().collect::<Vec<_>>();

        assert_eq!(first_key_unspents.len(), 1);
        assert_eq!(second_key_unspents.len(), 1);

        first_key_unspents.iter().for_each(|i| {
            let psbt_input = psbt::Input {
                witness_utxo: Some(i.txout.clone()),
                tap_internal_key: Some(derive_public_key(&keys_to_import[0])),
                ..Default::default()
            };
            tx_builder.add_foreign_utxo(i.outpoint, psbt_input, Weight::from_wu(107))
                .unwrap();
        });

        second_key_unspents.iter().for_each(|i| {
            let psbt_input = psbt::Input {
                witness_utxo: Some(i.txout.clone()),
                tap_internal_key: Some(derive_public_key(&keys_to_import[1])),
                ..Default::default()
            };
            tx_builder.add_foreign_utxo(i.outpoint, psbt_input, Weight::from_wu(107))
                .unwrap();
        });

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(res_psbt
            .inputs
            .iter()
            .all(|i| i.final_script_witness.is_some()));

        Ok(())
    }

    #[test]
    fn test_selection_with_main_and_imported() -> anyhow::Result<()> {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let client = MockedBDKElectrum {};
        let mut bmp_wallet = BMPWallet::new(Network::Regtest)?;

        let pk1: [u8; 32] = [
            180, 143, 139, 78, 9, 248, 73, 139, 169, 173, 99, 191, 248, 54, 50, 207, 137, 222, 85,
            70, 228, 53, 252, 227, 191, 26, 160, 101, 121, 195, 74, 212,
        ];

        let pk2: [u8; 32] = [
            78, 212, 125, 103, 117, 115, 156, 113, 203, 95, 207, 59, 190, 106, 63, 162, 225, 131,
            186, 216, 94, 123, 55, 23, 125, 232, 214, 160, 33, 172, 124, 61,
        ];

        bmp_wallet.import_private_key(Scalar::from_slice(&pk1).unwrap());
        bmp_wallet.import_private_key(Scalar::from_slice(&pk2).unwrap());

        bmp_wallet.sync_all(&client)?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let mut tx_builder = bmp_wallet.build_tx();

        tx_builder.add_recipient(to_address, to_spend);

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(res_psbt
            .inputs
            .iter()
            .all(|i| i.final_script_witness.is_some()));

        Ok(())
    }
}
