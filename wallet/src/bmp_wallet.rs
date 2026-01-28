use std::ops::{Deref, DerefMut};
use std::{fs, vec};

use base64::engine::general_purpose;
use base64::Engine;
use bdk_electrum::bdk_core::bitcoin::{absolute, Address, FeeRate, OutPoint};
use bdk_kyoto::bip157::{tokio, Builder};
use bdk_kyoto::{BuilderExt, LightClient, Requester, ScanType, TrustedPeer, UpdateSubscriber};
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
    AddressInfo, Balance, ChangeSet, KeychainKind, PersistedWallet, SignOptions, TxBuilder,
    TxOrdering, Utxo, Wallet, WalletPersister, WeightedUtxo,
};
use rand::RngCore;
use secp::Scalar;

use crate::chain_data_source::ChainDataSource;
use crate::coin_selection::AlwaysSpendImportedFirst;
use crate::protocol_wallet_api::ProtocolWalletApi;
use crate::utils::{derive_key_from_password, get_salt, trace_logs};

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
    signers_loaded: bool,
    db: P,
}

impl BMPWallet<Connection> {
    pub fn next_address(&mut self, key_chain: KeychainKind) -> anyhow::Result<AddressInfo> {
        let addr = self.wallet.next_unused_address(key_chain);
        // Persist the revealed address to avoid address reuse
        self.persist()?;

        Ok(addr)
    }

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    pub fn import_private_key(&mut self, pk: Scalar) {
        self.imported_keys.push(pk);
    }

    /// Helper function to run a CBF node
    /// This will:
    /// - Create a new Light client
    /// - spawn two threads one for trace logs and another for the server node
    /// - Return the requester and the subscriber from which the updates can be pulled
    ///
    /// Note: The caller is responsible for shutting down the requester at will.
    pub async fn run_node(
        wallet: &Wallet,
        scan_type: bdk_kyoto::ScanType,
        peers: Vec<TrustedPeer>,
    ) -> anyhow::Result<(Requester, UpdateSubscriber)> {
        let LightClient {
            requester,
            info_subscriber,
            warning_subscriber,
            update_subscriber,
            node,
        } = Builder::new(wallet.network())
            .add_peers(peers)
            .build_with_wallet(wallet, scan_type)?;

        tokio::task::spawn(async move { node.run().await });
        // Trace the logs with a custom function.
        tokio::task::spawn(async move { trace_logs(info_subscriber, warning_subscriber).await });
        Ok((requester, update_subscriber))
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
}

impl ProtocolWalletApi for BMPWallet<Connection> {
    fn network(&self) -> Network {
        self.wallet.network()
    }

    fn new_address(&mut self) -> anyhow::Result<Address> {
        Ok(self.next_address(KeychainKind::External)?.address)
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

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> anyhow::Result<()> {
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

    // Import an external private from the HD wallet
    // After importing a rescan should be triggered
    fn import_private_key(&mut self, pk: Scalar) {
        self.import_private_key(pk);
    }
}
pub trait WalletApi {
    const DB_PATH: &str;
    const SEEDS_TABLE_NAME: &'static str;
    const IMPORTED_KEYS_TABLE_NAME: &'static str;

    fn new(network: Network) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn load_wallet(network: Network, password: Option<&str>) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo>;
    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo>;

    fn get_seed_phrase(&self) -> anyhow::Result<String>;

    fn balance(&self) -> Amount;

    fn encrypt(self, password: &str) -> anyhow::Result<BMPWallet<Connection>>;
    fn decrypt(self, password: &str) -> anyhow::Result<BMPWallet<Connection>>;

    fn persist(&mut self) -> anyhow::Result<bool>;

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst>;

    fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> anyhow::Result<(), SignerError>;

    fn sync_all(&mut self, data_source: &impl ChainDataSource) -> anyhow::Result<bool>;
    fn sync_cbf(
        &mut self,
        scan_type: bdk_kyoto::ScanType,
        peers: Vec<TrustedPeer>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn sync_cbf_imported(
        &mut self,
        scan_type: bdk_kyoto::ScanType,
        peers: Vec<TrustedPeer>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
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

        // Check whether the signing keys were loaded if not load them into the wallet
        if !self.signers_loaded {
            println!("Loading the signers into the wallet");
            let recovery_phrase = self.get_seed_phrase().map_err(|_| SignerError::External("Unable to load keys.".to_string()))?;
            let mnemonic = Mnemonic::parse_normalized(&recovery_phrase).map_err(|_| SignerError::External("Unable to parse recovery phrase".to_string()))?;

            let xprv = Xpriv::new_master(self.network(), &mnemonic.to_entropy()).map_err(|_| SignerError::External("Unable to load keys".to_string()))?;

            let (_, external_map, _) = Bip86(xprv, KeychainKind::External)
            .build(self.network())
            .map_err(|_| SignerError::External("BIP 86 derivation failed".to_string()))?;

            let (_, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
                .build(self.network())
                .map_err(|_| SignerError::External("BIP 86 derivation failed".to_string()))?;

            self.wallet.set_keymap(KeychainKind::External, external_map);
            self.wallet.set_keymap(KeychainKind::Internal, internal_map);
            self.signers_loaded = true;
        }

        let finalized = self.wallet.sign(psbt, sign_options)?;
        assert!(finalized, "PSBT should be finalized");

        Ok(())
    }

    async fn sync_cbf(
        &mut self,
        scan_type: ScanType,
        peers: Vec<TrustedPeer>,
    ) -> anyhow::Result<()> {
        let (requester, mut updates_sub) = Self::run_node(self, scan_type, peers).await?;
        let updates = updates_sub.update().await?;

        self.apply_update(updates)?;
        self.persist()?;

        requester.shutdown()?;
        Ok(())
    }

    /// Sync the imported keys from protocol using CBF
    /// @TODO: use a shared node connection between the different imported keys sync
    async fn sync_cbf_imported(
        &mut self,
        scan_type: ScanType,
        peers: Vec<TrustedPeer>,
    ) -> anyhow::Result<()> {
        let pubkeys = self
            .imported_keys
            .iter()
            .map(|s| s.base_point_mul().serialize_xonly())
            .collect::<Vec<_>>();

        let mut req: Option<Requester> = None;

        let mut final_imported_balance = Balance::default();

        for key in pubkeys {
            let db_path = format!("bmp_{}.db3", key.to_lower_hex_string());
            let mut db = Connection::open(db_path)?;

            let imported_wallet_opt = Wallet::load()
                .check_network(self.wallet.network())
                .extract_keys()
                .load_wallet(&mut db)?;
            let mut imported_wallet = match imported_wallet_opt {
                Some(wallet) => wallet,
                None => {
                    let descriptor = format!("tr({})", key.to_lower_hex_string());
                    Wallet::create_single(descriptor)
                        .network(self.wallet.network())
                        .create_wallet(&mut db)?
                }
            };

            let LightClient {
                requester,
                info_subscriber: _,
                warning_subscriber: _,
                mut update_subscriber,
                node,
            } = Builder::new(self.network())
                .add_peers(peers.clone())
                .build_with_wallet(&imported_wallet, scan_type)?;

            tokio::task::spawn(async move { node.run().await.unwrap() });
            let updates = update_subscriber.update().await?;
            imported_wallet.apply_update(updates)?;

            imported_wallet.persist(&mut db)?;

            final_imported_balance = final_imported_balance + imported_wallet.balance();

            req.get_or_insert(requester);
        }

        self.imported_balance = final_imported_balance;

        req.is_some().then(|| req.unwrap().shutdown());

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
        let mut seed = [0u8; 32];
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
            signers_loaded: true,
            db,
        })
    }

    // For already created wallets this will load stored data
    // This will also load the imported keys
    fn load_wallet(network: Network, password: Option<&str>) -> anyhow::Result<Self> {
        let mut db = if let Some(password) = password {
            let salt = get_salt(Self::DB_PATH)?;
            let decrypt_key = derive_key_from_password(password, &salt)?;
            let conn = Connection::open(Self::DB_PATH)?;
            conn.pragma_update(None, "key", decrypt_key)?;
            conn
        } else {
            Connection::open(Self::DB_PATH)?
        };

        let wallet_opt = Wallet::load().check_network(network).load_wallet(&mut db)?;

        if let Some(wallet) = wallet_opt {
            let imported_keys =
                Connection::load_imported_keys(&mut db, Self::IMPORTED_KEYS_TABLE_NAME)?;

            return Ok(Self {
                wallet,
                imported_keys,
                imported_balance: Balance::default(),
                signers_loaded: false,
                db,
            });
        }

        Err(anyhow::anyhow!("Unable to load wallet"))
    }

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst> {
        self.build_tx()
    }

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo> {
        self.next_address(KeychainKind::External)
    }

    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo> {
        self.next_address(KeychainKind::Internal)
    }

    fn balance(&self) -> Amount {
        (self.imported_balance.clone() + self.wallet.balance()).trusted_spendable()
    }

    fn get_seed_phrase(&self) -> anyhow::Result<String> {
        Connection::get_seed_phrase(&self.db, Self::SEEDS_TABLE_NAME)
    }

    fn decrypt(self, password: &str) -> anyhow::Result<BMPWallet<Connection>> {
        let salt = get_salt(Self::DB_PATH)?;

        let decrypt_key = derive_key_from_password(password, &salt)?;

        let encrypted_conn = Connection::open(Self::DB_PATH)?;
        encrypted_conn.pragma_update(None, "key", decrypt_key)?;

        Ok(BMPWallet {
            wallet: self.wallet,
            imported_keys: self.imported_keys,
            imported_balance: self.imported_balance,
            signers_loaded: false,
            db: encrypted_conn,
        })
    }

    fn encrypt(self, password: &str) -> anyhow::Result<BMPWallet<Connection>> {
        // Derive encryption key from password
        let salt_path = format!("{}.salt", Self::DB_PATH);

        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);

        fs::write(&salt_path, general_purpose::STANDARD.encode(salt))?;
        let enc_key = derive_key_from_password(password, &salt)?;

        let encrypted_conn = Connection::open("bmp_encrypted.db3")?;
        encrypted_conn.pragma_update(None, "key", &enc_key)?;

        let mut sql = format!(
            "ATTACH DATABASE '{}' AS encrypted_db KEY '{}';",
            "bmp_encrypted.db3", enc_key
        );
        sql  += " SELECT sqlcipher_export('encrypted_db'); DETACH DATABASE encrypted_db;";

        self.db.execute_batch(&sql)?;

        // Rename the bmp_encrypted.db3 to bmp_wallet.db3
        fs::remove_file(Self::DB_PATH)?;
        fs::rename("bmp_encrypted.db3", Self::DB_PATH)?;

        Ok(BMPWallet {
            wallet: self.wallet,
            imported_keys: self.imported_keys,
            imported_balance: self.imported_balance,
            signers_loaded: false,
            db: encrypted_conn,
        })
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

        let mut wallet = BMPWallet::load_wallet(Network::Regtest, None)?;
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

        let loaded_wallet = BMPWallet::load_wallet(Network::Regtest, None)?;

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

    #[test]
    #[should_panic = "value: file is not a database"]
    fn encrypted_wallet() {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let bmp_wallet = BMPWallet::new(Network::Regtest).unwrap();
        // bmp_wallet database is unencrypted by default, reading from it should be fine
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Encrypt the wallet
        let enc_wallet = bmp_wallet.encrypt("secret123").unwrap();
        let seed = enc_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Try loading the wallet with wrong decryption key should panic
        let lw = BMPWallet::load_wallet(Network::Regtest, Some("secet123")).unwrap();
        lw.get_seed_phrase().unwrap();
    }

    #[test]
    fn encrypted_wallet_with_decryption() {
        let _permit = SEMAPHORE.acquire();
        let _tmp_dir = tear_up();

        let bmp_wallet = BMPWallet::new(Network::Regtest).unwrap();
        // bmp_wallet database is unencrypted by default, reading from it should be fine
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Encrypt the wallet and then decrypt and try reading from it
        let enc_wallet = bmp_wallet.encrypt("secret123").unwrap();
        let seed = enc_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Load the wallet with right decryption key
        let lw = BMPWallet::load_wallet(Network::Regtest, Some("secret123")).unwrap();

        assert_eq!(lw.get_seed_phrase().unwrap(), seed);
    }
}
