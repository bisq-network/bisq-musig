use std::io::Write as _;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use std::{fs, vec};

use base64::Engine as _;
use base64::engine::general_purpose;
use bdk_electrum::bdk_core::bitcoin::{Address, FeeRate, OutPoint};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hex::DisplayHex as _;
use bdk_wallet::bitcoin::{
    Amount, Network, PrivateKey, Psbt, ScriptBuf, Sequence, TapNodeHash, Transaction, Weight,
    XOnlyPublicKey, consensus, psbt,
};
use bdk_wallet::chain::{ChainPosition, Merge as _};
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::miniscript::descriptor::{TapTree, Tr};
use bdk_wallet::miniscript::psbt::PsbtExt as _;
use bdk_wallet::rusqlite::{self, Connection, named_params};
use bdk_wallet::signer::{InputSigner as _, SignerContext, SignerError, SignerWrapper};
use bdk_wallet::template::{Bip86, DescriptorTemplate as _};
use bdk_wallet::{
    AddressInfo, Balance, ChangeSet, KeychainKind, PersistedWallet, SignOptions, TxBuilder, Utxo,
    Wallet, WalletPersister, WeightedUtxo,
};
use rand::RngCore as _;
use secp::Scalar;

use crate::chain_data_source::ChainDataSource;
use crate::coin_selection::{AlwaysSpendImportedFirst, SpendImportedOnly};
use crate::protocol_wallet_api::{
    ProtocolWalletApi, WalletErrorKind, WalletExt, finish_standard_psbt, internal_key_at_index,
    sign_selected_inputs_with,
};
use crate::utils::{derive_key_from_password, get_salt, key_verifier};
use crate::wallet_info::{TxInfo, TxInputInfo, TxOutputInfo, UtxoInfo};

/// An external (non-HD) private key imported into the wallet, together with the Taproot output
/// template it controls: `tr(P, tap_tree)` where `P` is the (untweaked) internal key derived from
/// `secret`. A missing tap tree means a key-path-only output (`tr(P)`, as in BIP86).
///
/// The full descriptor is kept (rather than just the merkle root) because BDK wallets are
/// descriptor-driven: it is what lets the per-key sub-wallet in [`get_imported_wallets`] watch
/// the right script pubkey, and what [`BMPWallet::imported_utxos`] and [`WalletApi::sign`] use
/// to recognise and tweak-sign the output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedKey {
    secret: Scalar,
    descriptor: Tr<XOnlyPublicKey>,
}

impl ImportedKey {
    pub fn new(secret: Scalar, tap_tree: Option<TapTree<XOnlyPublicKey>>) -> anyhow::Result<Self> {
        let descriptor = Tr::new(Self::internal_key_of(&secret), tap_tree)?;
        Ok(Self { secret, descriptor })
    }

    /// Rebuild from the persisted `tr(..)` descriptor string; checks that it belongs to `secret`.
    fn from_descriptor_str(secret: Scalar, descriptor: &str) -> anyhow::Result<Self> {
        let descriptor: Tr<XOnlyPublicKey> = descriptor.parse()?;
        anyhow::ensure!(
            *descriptor.internal_key() == Self::internal_key_of(&secret),
            "imported key descriptor does not match its secret key"
        );
        Ok(Self { secret, descriptor })
    }

    fn internal_key_of(secret: &Scalar) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&secret.base_point_mul().serialize_xonly())
            .expect("Should be valid xonly pubkey")
    }

    pub const fn secret(&self) -> Scalar {
        self.secret
    }

    pub fn internal_key(&self) -> XOnlyPublicKey {
        *self.descriptor.internal_key()
    }

    pub fn tap_tree(&self) -> Option<&TapTree<XOnlyPublicKey>> {
        self.descriptor.tap_tree().as_ref()
    }

    pub const fn descriptor(&self) -> &Tr<XOnlyPublicKey> {
        &self.descriptor
    }

    pub fn merkle_root(&self) -> Option<TapNodeHash> {
        self.descriptor.spend_info().merkle_root()
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.descriptor.script_pubkey()
    }
}

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

    fn load_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
    ) -> anyhow::Result<Vec<ImportedKey>>;

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[ImportedKey],
    ) -> anyhow::Result<()>;

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String>;

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error>;
}

impl BMPWalletPersister for Connection {
    type DB = Self;

    fn new(db_path: &str) -> Result<Self::DB, rusqlite::Error> {
        let db = Self::open(db_path)?;
        Ok(db)
    }

    fn persist_staged_changes(
        db: &mut Self::DB,
        cs: &ChangeSet,
    ) -> anyhow::Result<(), rusqlite::Error> {
        Self::persist(db, cs)
    }

    fn init(
        db: &mut Self::DB,
        imported_keys_table: Option<&str>,
        seeds_table_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let create_imported_keys_table = format!(
            "CREATE TABLE {} ( \
                    key TEXT PRIMARY KEY NOT NULL,
                    descriptor TEXT NOT NULL
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
                "INSERT INTO {seeds_table_name}(seed) VALUES(:seed)"
            ))?;

            stmt.execute(named_params! {
                ":seed": seed_phrase
            })?;
        }

        trx.commit()?;
        Ok(())
    }

    fn load_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
    ) -> anyhow::Result<Vec<ImportedKey>> {
        let mut imported_keys = vec![];

        let mut statement =
            db.prepare(&format!("SELECT key, descriptor FROM {keys_table_name}"))?;

        let row_iter = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>("key")?,
                row.get::<_, String>("descriptor")?,
            ))
        })?;

        for row in row_iter {
            let (key_hex, descriptor) = row?;
            let secret = Scalar::from_hex(&key_hex)?;
            imported_keys.push(ImportedKey::from_descriptor_str(secret, &descriptor)?);
        }

        Ok(imported_keys)
    }

    fn persist_imported_keys(
        db: &mut Self::DB,
        keys_table_name: &str,
        keys: &[ImportedKey],
    ) -> anyhow::Result<()> {
        let db_trx = db.transaction()?;
        {
            let mut statement = db_trx.prepare_cached(&format!(
                "INSERT OR IGNORE INTO {keys_table_name} (key, descriptor) \
                 VALUES (:key, :descriptor)"
            ))?;

            for key in keys {
                statement.execute(named_params! {
                    ":key": key.secret().serialize().to_lower_hex_string(),
                    ":descriptor": key.descriptor().to_string(),
                })?;
            }
        }

        db_trx.commit()?;
        Ok(())
    }

    fn get_seed_phrase(db: &Self::DB, seeds_table_name: &str) -> anyhow::Result<String> {
        let mnemonic = db.query_row(
            &format!("SELECT seed FROM {seeds_table_name}"),
            (),
            |row| row.get::<_, String>("seed"),
        )?;

        Ok(mnemonic)
    }
}

const STOP_GAP: usize = 50;

pub struct BMPWallet<P: BMPWalletPersister> {
    wallet: PersistedWallet<P>,
    imported_keys: Vec<ImportedKey>,
    imported_balance: Balance,
    signers_loaded: bool,
    db: P,
    last_unused_address: Option<String>,
    /// Path of the `SQLCipher` database file, kept so that the encryption key can be rotated
    /// in place (see [`BMPWallet::change_password`]) without re-deriving it from `db`.
    db_path: PathBuf,
    /// Argon2 salt backing the current database key, mirrored on disk as `<db_path>.salt`.
    salt: Vec<u8>,
    /// SHA-256 fingerprint of the `SQLCipher` key currently in force. Retained so a caller-
    /// supplied password can be *verified* (re-derive, fingerprint, compare) without keeping the
    /// plaintext password — or the key itself — in memory: the derived key only exists
    /// transiently, for `PRAGMA key`/`rekey`, and is zeroized right after use.
    key_verifier: [u8; 32],
    /// Whether the user actually set a password. The database is always encrypted — an empty
    /// password still yields a valid Argon2 key — so this records intent, not mechanism.
    encrypted: bool,
}

impl BMPWallet<Connection> {
    pub fn list_unused_addresses_since_last_used(
        &self,
        key_chain: KeychainKind,
    ) -> impl Iterator<Item = AddressInfo> + '_ {
        let last_used = self.spk_index().last_used_index(key_chain);
        self.list_unused_addresses(key_chain)
            .filter(move |info| last_used.is_none_or(|idx| info.index > idx))
    }

    pub fn next_address(&mut self, key_chain: KeychainKind) -> anyhow::Result<AddressInfo> {
        let unused = self.list_unused_addresses_since_last_used(key_chain).collect::<Vec<_>>();

        let addr = if unused.len() >= STOP_GAP {
            // Find the position of the last returned address, or start at the beginning
            let next_index = if let Some(last_addr) = &self.last_unused_address {
                // Search for the last address in the current unused list
                unused.iter().position(|info| info.address.to_string() == *last_addr)
                    .map_or(0, |idx| (idx + 1) % unused.len())
            } else {
                // No previous address, start with the first one
                0
            };

            let selected = unused[next_index].clone();

            // Update index to track the address just given out
            self.last_unused_address = Some(selected.address.to_string());

            selected
        } else {
            let addr = self.reveal_next_address(key_chain);
            self.persist()?;
            // Reset the index since we've generated new addresses
            self.last_unused_address = None;
            addr
        };

        Ok(addr)
    }

    /// Import an external private key (i.e. one not derived from the HD wallet) controlling a
    /// `tr(P, tap_tree)` output, `P` being the untweaked internal key of `pk`. `None` means a
    /// key-path-only `tr(P)` output. After importing, a rescan should be triggered.
    pub fn import_private_key(
        &mut self,
        pk: Scalar,
        tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind> {
        self.imported_keys.push(ImportedKey::new(pk, tap_tree)?);
        Ok(())
    }

    /// Test-only introspection of the imported keys; enable the `test-utils` feature to use it
    /// from tests in downstream crates.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn imported_keys(&self) -> &[ImportedKey] {
        &self.imported_keys
    }

    fn imported_utxos(&self) -> Vec<WeightedUtxo> {
        self.tx_graph()
            .floating_txouts()
            .map(|utxo| {
                let output_script_pubkey = &utxo.1.script_pubkey;

                let (tap_internal_key, tap_merkle_root) = self
                    .imported_keys
                    .iter()
                    .find(|key| key.script_pubkey() == *output_script_pubkey)
                    .map_or((None, None), |key| {
                        (Some(key.internal_key()), key.merkle_root())
                    });

                WeightedUtxo {
                    utxo: Utxo::Foreign {
                        outpoint: utxo.0,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        psbt_input: Box::new(psbt::Input {
                            witness_utxo: Some(utxo.1.clone()),
                            tap_internal_key,
                            tap_merkle_root,
                            ..Default::default()
                        }),
                    },
                    satisfaction_weight: Weight::from_wu_usize(65),
                }
            })
            .collect::<Vec<_>>()
    }

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst> {
        let imported_weighted_utxos = self.imported_utxos();
        let coin_selection = AlwaysSpendImportedFirst(imported_weighted_utxos);
        self.wallet.build_tx().coin_selection(coin_selection)
    }

    /// The full balance breakdown, combining the HD wallet with any imported keys.
    ///
    /// [`WalletApi::balance`] flattens this to a single spendable [`Amount`]; callers that need
    /// to distinguish confirmed from pending funds should use this instead.
    pub fn full_balance(&self) -> Balance {
        self.imported_balance.clone() + self.wallet.balance()
    }

    /// Every address revealed so far on either keychain, external first.
    pub fn list_wallet_addresses(&self) -> Vec<String> {
        [KeychainKind::External, KeychainKind::Internal]
            .into_iter()
            .flat_map(|kind| {
                // `derivation_index` is `None` until the keychain has revealed anything, in
                // which case the inner range is skipped entirely.
                self.wallet
                    .derivation_index(kind)
                    .into_iter()
                    .flat_map(move |last_revealed| {
                        (0..=last_revealed).map(move |index| {
                            self.wallet.peek_address(kind, index).address.to_string()
                        })
                    })
            })
            .collect()
    }

    /// The imported key controlling `script_pubkey`, if any.
    fn imported_key_for_script(&self, script_pubkey: &ScriptBuf) -> Option<&ImportedKey> {
        self.imported_keys
            .iter()
            .find(|key| key.script_pubkey() == *script_pubkey)
    }

    /// Renders `script_pubkey` as an address, or `None` if it isn't a standard one.
    fn address_for_script(&self, script_pubkey: &ScriptBuf) -> Option<String> {
        Address::from_script(script_pubkey, self.wallet.network())
            .ok()
            .map(|address| address.to_string())
    }

    /// Confirmation count for a chain position: `0` while unconfirmed.
    fn num_confirmations(&self, block_height: Option<u32>) -> u32 {
        let next_height = self.wallet.latest_checkpoint().height() + 1;
        block_height.map_or(0, |height| next_height.saturating_sub(height))
    }

    /// All unspent outputs, both the HD wallet's own and those held by imported keys.
    ///
    /// Imported outputs live in the tx graph as *floating* txouts (inserted by
    /// [`WalletApi::sync_all`] so that fee calculation works), which carry no chain position —
    /// they are therefore always reported with `num_confirmations == 0`. Ones the graph already
    /// knows to be spent are dropped, so this stays consistent with [`Self::full_balance`].
    pub fn list_utxos(&self) -> Vec<UtxoInfo> {
        let own = self.wallet.list_unspent().map(|utxo| {
            let block_height = match utxo.chain_position {
                ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.height),
                ChainPosition::Unconfirmed { .. } => None,
            };
            UtxoInfo {
                tx_id: utxo.outpoint.txid,
                vout: utxo.outpoint.vout,
                amount: utxo.txout.value,
                address: self.address_for_script(&utxo.txout.script_pubkey),
                num_confirmations: self.num_confirmations(block_height),
                imported: false,
            }
        });

        let imported = self
            .tx_graph()
            .floating_txouts()
            .filter(|(outpoint, _)| self.tx_graph().outspends(*outpoint).is_empty())
            .filter(|(_, txout)| self.imported_key_for_script(&txout.script_pubkey).is_some())
            .map(|(outpoint, txout)| UtxoInfo {
                tx_id: outpoint.txid,
                vout: outpoint.vout,
                amount: txout.value,
                address: self.address_for_script(&txout.script_pubkey),
                num_confirmations: 0,
                imported: true,
            });

        own.chain(imported).collect()
    }

    /// Every wallet-relevant transaction, flattened for display.
    pub fn list_transactions(&self) -> Vec<TxInfo> {
        self.wallet
            .transactions()
            .map(|wallet_tx| {
                let tx = wallet_tx.tx_node.tx.as_ref();
                let (sent, received) = self.wallet.sent_and_received(tx);
                // `sent` counts every input we own and `received` every output we own (change
                // included), so the difference is the true net effect on the wallet.
                let incoming = received >= sent;
                let amount = if incoming {
                    received - sent
                } else {
                    sent - received
                };

                let (block_height, timestamp) = match &wallet_tx.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        (Some(anchor.block_id.height), Some(anchor.confirmation_time))
                    }
                    ChainPosition::Unconfirmed { .. } => (None, None),
                };

                TxInfo {
                    tx_id: wallet_tx.tx_node.txid,
                    inputs: tx
                        .input
                        .iter()
                        .map(|txin| TxInputInfo {
                            prev_out_tx_id: txin.previous_output.txid,
                            prev_out_index: txin.previous_output.vout,
                            sequence: txin.sequence.to_consensus_u32(),
                            script_sig: txin.script_sig.clone(),
                            witness: consensus::serialize(&txin.witness).to_lower_hex_string(),
                        })
                        .collect(),
                    outputs: tx
                        .output
                        .iter()
                        .map(|txout| TxOutputInfo {
                            value: txout.value,
                            address: self.address_for_script(&txout.script_pubkey),
                            script_pubkey: txout.script_pubkey.clone(),
                        })
                        .collect(),
                    lock_time: tx.lock_time.to_consensus_u32(),
                    block_height,
                    timestamp,
                    num_confirmations: self.num_confirmations(block_height),
                    amount,
                    incoming,
                }
            })
            .collect()
    }

    /// Whether the user has set a wallet password.
    ///
    /// Note the database is *always* SQLCipher-encrypted — an empty password still derives a
    /// valid Argon2 key — so this reports whether a password was chosen, not whether the file
    /// on disk is ciphertext.
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Checks `password` against the key currently protecting the database, without needing the
    /// plaintext password (or the key itself) to have been retained: the freshly derived key is
    /// compared by its one-way fingerprint and dropped again.
    pub fn check_password(&self, password: &str) -> anyhow::Result<bool> {
        let key = derive_key_from_password(password, &self.salt)?;
        Ok(key_verifier(&key) == self.key_verifier)
    }

    /// Re-keys the database to `new_password`, rotating the Argon2 salt at the same time.
    ///
    /// Passing an empty `new_password` leaves the file encrypted with a well-known key, which is
    /// how [`Self::change_password`] removes protection.
    ///
    /// The rotation is staged so that the database is at no point keyed by a salt that exists
    /// nowhere on disk (a crash then would make the wallet permanently unopenable): the new salt
    /// is written to `<db_path>.salt.new` *before* the re-key, and renamed over `<db_path>.salt`
    /// after it. A crash in between is healed on the next [`WalletApi::load_wallet`], which
    /// falls back to the staged salt and completes the rename.
    ///
    /// This is the raw primitive and authenticates nobody: `old_password` is only used to undo
    /// the re-key when committing the new salt fails. Every caller must verify it first — see
    /// [`Self::change_password`].
    fn rekey(&mut self, old_password: &str, new_password: &str) -> anyhow::Result<()> {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let new_key = derive_key_from_password(new_password, &salt)?;

        let salt_path = format!(
            "{}.salt",
            self.db_path.to_str().expect("Path must not be empty")
        );
        let staged_salt_path = format!("{salt_path}.new");

        // Stage the new salt on disk (durably) before re-keying; if this fails, nothing has
        // changed. A stale staged file left by an early return here is ignored — and cleaned
        // up — by `load_wallet`.
        let mut staged_salt_file = fs::File::create(&staged_salt_path)?;
        staged_salt_file.write_all(general_purpose::STANDARD.encode(salt).as_bytes())?;
        staged_salt_file.sync_all()?;
        drop(staged_salt_file);

        if let Err(e) = self.db.pragma_update(None, "rekey", new_key.as_str()) {
            let _ = fs::remove_file(&staged_salt_path);
            return Err(e.into());
        }

        // Commit the rotated salt. If that fails, undo the re-key with a key re-derived from
        // the (just verified) old password, rather than leave database and salt out of step.
        if let Err(e) = fs::rename(&staged_salt_path, &salt_path) {
            let old_key = derive_key_from_password(old_password, &self.salt)?;
            self.db.pragma_update(None, "rekey", old_key.as_str())?;
            let _ = fs::remove_file(&staged_salt_path);
            return Err(e.into());
        }

        self.salt = salt.to_vec();
        self.key_verifier = key_verifier(&new_key);
        self.encrypted = !new_password.is_empty();
        Ok(())
    }

    /// Changes the wallet password from `old_password` to `new_password`, re-keying the
    /// database and rotating the Argon2 salt.
    ///
    /// `old_password` must be the password currently in force — the empty string for a wallet
    /// that has no password yet — so nobody who cannot present the current password can rotate
    /// the key and lock the owner out. An empty `new_password` removes password protection.
    /// This single method subsumes the former encrypt/decrypt operations: encrypting is
    /// `change_password("", password)` and decrypting is `change_password(password, "")`.
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> anyhow::Result<()> {
        if !self.check_password(old_password)? {
            anyhow::bail!("invalid wallet password");
        }
        self.rekey(old_password, new_password)
    }

    /// Builds, signs and persists a payment to `address`. The caller is responsible for
    /// broadcasting the returned transaction.
    ///
    /// The signed transaction is recorded in the wallet as unconfirmed before it is returned,
    /// so its inputs count as spent from here on. The wallet cannot rely on the chain to tell
    /// it: compact block filter sync only ever reports confirmed transactions, so until the
    /// payment was mined the spent coins would still look unspent, and a second payment would
    /// happily pick the same inputs — and, since BDK opts into RBF, could replace the first one
    /// in the mempool. Treating a signed-and-handed-out transaction as spent is the safe
    /// direction: a payment that never made it to the network leaves coins looking locked
    /// (recoverable) rather than double-spent (not).
    pub fn send_to_address(
        &mut self,
        address: &Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Transaction> {
        let mut builder = self.build_tx();
        builder
            .fee_rate(fee_rate)
            .add_recipient(address.script_pubkey(), amount);
        let mut psbt = builder.finish()?;

        <Self as WalletApi>::sign(self, &mut psbt, SignOptions::default())?;
        let tx = psbt.extract_tx()?;

        let last_seen = UNIX_EPOCH.elapsed()?.as_secs();
        self.wallet.apply_unconfirmed_txs([(tx.clone(), last_seen)]);
        <Self as WalletApi>::persist(self)?;

        Ok(tx)
    }
}

impl WalletExt for BMPWallet<Connection> {
    fn update_psbt_with_derivation_paths(&self, psbt: &mut Psbt) {
        self.wallet.update_psbt_with_derivation_paths(psbt);
    }
}

impl ProtocolWalletApi for BMPWallet<Connection> {
    fn network(&self) -> Network {
        self.wallet.network()
    }

    fn new_address(&mut self) -> Result<Address, WalletErrorKind> {
        Ok(self.next_address(KeychainKind::External)?.address)
    }

    fn new_internal_key(&mut self) -> Result<XOnlyPublicKey, WalletErrorKind> {
        // Use `next_address` (gap-filling) rather than `reveal_next_address` directly so
        // that the internal key's index stays in step with what `new_address` would yield.
        let index = self.next_address(KeychainKind::External)?.index;
        internal_key_at_index(self, index)
    }

    fn create_psbt(
        &mut self,
        recipients: Vec<(ScriptBuf, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt, WalletErrorKind> {
        finish_standard_psbt(self.build_tx(), recipients, fee_rate)
    }

    fn sign_selected_inputs(
        &mut self,
        psbt: &mut Psbt,
        is_selected: &dyn Fn(&OutPoint) -> bool,
    ) -> Result<(), WalletErrorKind> {
        // TODO unify signing
        sign_selected_inputs_with(self, psbt, is_selected, |w, p, opts| {
            <Self as WalletApi>::sign(w, p, opts).map_err(Into::into)
        })
    }

    fn import_private_key(
        &mut self,
        pk: Scalar,
        tap_tree: Option<TapTree<XOnlyPublicKey>>,
    ) -> Result<(), WalletErrorKind> {
        self.import_private_key(pk, tap_tree)
    }
}

#[trait_variant::make(Send)]
pub trait WalletApi {
    const DB_NAME: &str;
    const SEEDS_TABLE_NAME: &'static str;
    const IMPORTED_KEYS_TABLE_NAME: &'static str;

    fn new(path: &Path, password: &str, network: Network) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn load_wallet(path: &Path, network: Network, password: &str) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn get_new_address(&mut self) -> anyhow::Result<AddressInfo>;
    fn get_change_address(&mut self) -> anyhow::Result<AddressInfo>;

    fn get_seed_phrase(&self) -> anyhow::Result<String>;

    fn balance(&self) -> Amount;

    fn persist(&mut self) -> anyhow::Result<bool>;

    fn build_tx(&mut self) -> TxBuilder<'_, AlwaysSpendImportedFirst>;

    fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> anyhow::Result<(), SignerError>;

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> anyhow::Result<()>;

    fn drain_imported_balance(&mut self, fee_rate: FeeRate) -> anyhow::Result<Psbt>;
}

pub fn get_imported_wallets(
    imported_keys: &[ImportedKey],
    db: &Connection,
    network: Network,
    db_name: &str,
) -> anyhow::Result<Vec<(PersistedWallet<Connection>, Connection)>> {
    let mut res = vec![];
    for key in imported_keys {
        let pubk = key.internal_key();
        // One sub-wallet DB per output template: the same internal key may back a key-path-only
        // output and a `tr(P, tree)` output, which have different script pubkeys.
        let db_file = match key.merkle_root() {
            None => format!("bmp_{pubk}.db3"),
            Some(root) => format!("bmp_{pubk}_{root}.db3"),
        };
        let path_str = db
            .path()
            .expect("DB path should not be empty")
            .replace(db_name, "");
        let db_path = Path::new(&path_str).join(db_file);
        let descriptor = key.descriptor().to_string();

        let mut db = Connection::open(db_path)?;
        let imported_wallet_opt = Wallet::load()
            .descriptor(KeychainKind::External, Some(descriptor.clone()))
            .check_network(network)
            .extract_keys()
            .load_wallet(&mut db)?;

        let imported_wallet = if let Some(wallet) = imported_wallet_opt {
            wallet
        } else {
            Wallet::create_single(descriptor)
                .network(network)
                .create_wallet(&mut db)?
        };
        res.push((imported_wallet, db));
    }
    Ok(res)
}

/// Opens the wallet database at `db_path` with the key derived from `password` and `salt`.
///
/// Factored out of [`WalletApi::load_wallet`] so that it can be retried with the *staged* salt
/// when recovering from an interrupted password change (see [`BMPWallet::rekey`]).
fn load_with_salt(
    db_path: &Path,
    salt: Vec<u8>,
    network: Network,
    password: &str,
) -> anyhow::Result<BMPWallet<Connection>> {
    let mut db = Connection::open(db_path)?;
    let key = derive_key_from_password(password, &salt)?;
    db.pragma_update(None, "key", key.as_str())?;

    let wallet_opt = Wallet::load().check_network(network).load_wallet(&mut db)?;

    if let Some(wallet) = wallet_opt {
        let imported_keys = Connection::load_imported_keys(
            &mut db,
            BMPWallet::<Connection>::IMPORTED_KEYS_TABLE_NAME,
        )?;

        return Ok(BMPWallet {
            wallet,
            imported_keys,
            imported_balance: Balance::default(),
            signers_loaded: false,
            db,
            last_unused_address: None,
            db_path: db_path.to_path_buf(),
            salt,
            key_verifier: key_verifier(&key),
            encrypted: !password.is_empty(),
        });
    }

    Err(anyhow::anyhow!("Unable to load wallet"))
}

impl WalletApi for BMPWallet<Connection> {
    const SEEDS_TABLE_NAME: &'static str = "bmp_seeds";
    const IMPORTED_KEYS_TABLE_NAME: &'static str = "bmp_imported_keys";
    const DB_NAME: &str = "bmp_bdk_wallet.db3";

    async fn sync_all(&mut self, s: &(impl ChainDataSource + Sync)) -> Result<(), anyhow::Error> {
        let network = self.network();
        let mut vec = vec![&mut self.wallet];
        let mut imported =
            get_imported_wallets(&self.imported_keys, &self.db, network, Self::DB_NAME)?;

        vec.extend(
            imported
                .iter_mut()
                .map(|persister_wallet| &mut persister_wallet.0),
        );

        s.sync(vec).await?;

        let mut final_imported_balance = Balance::default();

        // For having accurate Wallet::calculate_fee and Wallet::calculate_fee_rate
        // This is also at same time a way to have to UTXOs of the imported merged
        // into the main wallet, allowing easy manipulation during coinselection
        for (w, _) in &imported {
            for utxo in w.list_unspent() {
                self.insert_txout(utxo.outpoint, utxo.txout);
            }
            final_imported_balance = final_imported_balance + w.balance();
        }

        self.imported_balance = final_imported_balance;

        // Persist changes from imported keys
        for (w, db) in &mut imported {
            w.persist(db)?;
        }

        self.persist()?;
        Ok(())
    }

    fn new(path: &Path, password: &str, network: Network) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        // TODO: Make the word size configurable?
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let xprv = Xpriv::new_master(network, &seed)?;

        let (descriptor, external_map, _) =
            Bip86(xprv, KeychainKind::External).build(network.into())?;
        let (change_descriptor, internal_map, _) =
            Bip86(xprv, KeychainKind::Internal).build(network.into())?;

        let db_path = path.join(Self::DB_NAME);
        let db_path_str = db_path.to_str().expect("Should get path value");

        // Never create over an existing wallet. The salt written below is what the existing
        // database's encryption key was derived from, so overwriting it would leave that
        // database permanently unopenable — its key could no longer be re-derived from any
        // password. Callers meaning to open an existing wallet must use `load_wallet`.
        if db_path.exists() {
            anyhow::bail!(
                "a wallet database already exists at {}; refusing to overwrite it",
                db_path.display()
            );
        }

        let mut db = Connection::new(db_path_str)?;

        // Derive encryption key
        let salt_path = format!("{db_path_str}.salt");
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        fs::write(&salt_path, general_purpose::STANDARD.encode(salt))?;
        let key = derive_key_from_password(password, &salt)?;
        db.pragma_update(None, "key", key.as_str())?;

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
            last_unused_address: None,
            db_path,
            salt: salt.to_vec(),
            key_verifier: key_verifier(&key),
            encrypted: !password.is_empty(),
        })
    }

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
        //// @TODO performance: cache the public keys derivation
        let secp = self.secp_ctx();
        let is_mine = |input_script: &ScriptBuf| {
            self.imported_keys
                .iter()
                .find(|key| key.script_pubkey() == *input_script)
        };

        for (input_index, input_details) in psbt.inputs.clone().iter().enumerate() {
            let txout = input_details.witness_utxo.as_ref().unwrap();

            if let Some(signing_key) = is_mine(&txout.script_pubkey) {
                let signer =
                    PrivateKey::from_slice(&signing_key.secret().serialize(), self.network())
                        .map_err(|_e| SignerError::External("Invalid signing key".to_owned()))?;

                let sw = SignerWrapper::new(
                    signer,
                    SignerContext::Tap {
                        is_internal_key: true,
                    },
                );

                sw.sign_input(psbt, input_index, &sign_options, secp)?;
                psbt.finalize_inp_mut(secp, input_index)
                    .map_err(|_e| SignerError::External("Unable to finalized input".to_owned()))?;
            }
        }

        // Check whether the signing keys were loaded if not load them into the wallet
        if !self.signers_loaded {
            tracing::info!("Loading the signers into the wallet");
            let recovery_phrase = self
                .get_seed_phrase()
                .map_err(|_| SignerError::External("Unable to load keys.".to_owned()))?;
            let mnemonic = Mnemonic::parse_normalized(&recovery_phrase)
                .map_err(|_| SignerError::External("Unable to parse recovery phrase".to_owned()))?;

            let xprv = Xpriv::new_master(self.network(), &mnemonic.to_entropy())
                .map_err(|_| SignerError::External("Unable to load keys".to_owned()))?;

            let (_, external_map, _) = Bip86(xprv, KeychainKind::External)
                .build(self.network().into())
                .map_err(|_| SignerError::External("BIP 86 derivation failed".to_owned()))?;

            let (_, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
                .build(self.network().into())
                .map_err(|_| SignerError::External("BIP 86 derivation failed".to_owned()))?;

            self.wallet.set_keymap(KeychainKind::External, external_map);
            self.wallet.set_keymap(KeychainKind::Internal, internal_map);
            self.signers_loaded = true;
        }

        // BDK returns `true` only when every input of the PSBT got finalized. Partial-sign use
        // cases (e.g. the trade protocol's half-deposit PSBTs that also carry the peer's still-
        // unsigned inputs) legitimately leave inputs un-finalized, so we don't assert here.
        let _finalized = self.wallet.sign(psbt, sign_options)?;

        Ok(())
    }

    // For already created wallets this will load stored data
    // This will also load the imported keys
    fn load_wallet(path: &Path, network: Network, password: &str) -> anyhow::Result<Self> {
        let db_path = path.join(Self::DB_NAME);
        let db_path_str = db_path.to_str().expect("Path must not be empty");
        tracing::debug!(path = %db_path.display(), "Loading wallet database.");

        let staged_salt_path = format!("{db_path_str}.salt.new");
        match load_with_salt(&db_path, get_salt(db_path_str)?, network, password) {
            Ok(wallet) => {
                // A leftover staged salt (from a password change that failed before re-keying,
                // see `BMPWallet::rekey`) is dead weight once the primary salt has opened the
                // database.
                let _ = fs::remove_file(&staged_salt_path);
                Ok(wallet)
            }
            Err(primary_error) => {
                // A crash between the re-key and committing the rotated salt (see
                // `BMPWallet::rekey`) leaves the database keyed by the *staged* salt at
                // `<db_path>.salt.new`. If that salt opens the database, finish the interrupted
                // rotation; otherwise report the original failure.
                let Some(staged_salt) = fs::read_to_string(&staged_salt_path)
                    .ok()
                    .and_then(|salt| general_purpose::STANDARD.decode(salt.as_bytes()).ok())
                else {
                    return Err(primary_error);
                };
                let wallet = load_with_salt(&db_path, staged_salt, network, password)
                    .map_err(|_| primary_error)?;
                fs::rename(&staged_salt_path, format!("{db_path_str}.salt"))?;
                tracing::warn!(
                    "Completed a password change that was interrupted before its rotated salt \
                     was committed."
                );
                Ok(wallet)
            }
        }
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

    fn drain_imported_balance(&mut self, fee_rate: FeeRate) -> anyhow::Result<Psbt> {
        let drain_to_address = self.next_address(KeychainKind::Internal)?;
        let imported_balance = self.imported_balance.trusted_spendable();

        let imported_utxos = self.imported_utxos();
        let cs = SpendImportedOnly(imported_utxos.clone());

        let mut tx_builder = self.build_tx().coin_selection(cs);

        tx_builder
            .fee_rate(fee_rate)
            .add_recipient(drain_to_address.script_pubkey(), imported_balance);

        match tx_builder.finish() {
            Err(e) => match e {
                bdk_wallet::error::CreateTxError::CoinSelection(insufficient_funds) => {
                    let cs = SpendImportedOnly(imported_utxos);
                    let fees = insufficient_funds.needed - insufficient_funds.available;
                    let amount_to_send = imported_balance - fees;
                    let mut new_builder = self.build_tx().coin_selection(cs);
                    new_builder
                        .fee_rate(fee_rate)
                        .add_recipient(drain_to_address.script_pubkey(), amount_to_send);

                    let psbt = new_builder.finish()?;
                    self.imported_balance = Balance::default();

                    tracing::debug!(
                        "AMOUNT TO SEND {amount_to_send}, fees {fees}, imported balance {}",
                        self.imported_balance
                    );

                    Ok(psbt)
                }
                _ => Err(e.into()),
            },
            Ok(psbt) => Ok(psbt),
        }
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
    use std::fs;
    use std::str::FromStr as _;

    use bdk_kyoto::FeeRate;
    use bdk_kyoto::bip157::{ScriptBuf, tokio};
    use bdk_wallet::bitcoin::hashes::Hash as _;
    use bdk_wallet::bitcoin::key::{Secp256k1, TapTweak as _};
    use bdk_wallet::bitcoin::secp256k1::Message;
    use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
    use bdk_wallet::bitcoin::{
        Address, AddressType, Amount, BlockHash, Network, OutPoint, TxOut, Weight, psbt, taproot,
    };
    use bdk_wallet::chain::{self, BlockId};
    use bdk_wallet::miniscript::Descriptor;
    use bdk_wallet::rusqlite::Connection;
    use bdk_wallet::test_utils::{ReceiveTo, receive_output_to_address};
    use bdk_wallet::{AddressInfo, KeychainKind, SignOptions};
    use bmp_tracing::tracing;
    use rand::RngCore as _;
    use secp::Scalar;
    use tempfile::{TempDir, tempdir};

    use super::{TapTree, XOnlyPublicKey};
    use crate::bmp_wallet::{BMPWallet, STOP_GAP, WalletApi as _};
    use crate::test_utils::{MockedBDKElectrum, derive_public_key, load_imported_wallet};

    fn get_dir() -> TempDir {
        tempdir().unwrap()
    }

    fn new_private_key() -> Scalar {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Scalar::from_slice(&seed).unwrap()
    }

    /// Single-leaf tap tree `and_v(v:pk(a),pk(b))`, the shape of the protocol's deposit payouts.
    fn sample_tap_tree(a: &XOnlyPublicKey, b: &XOnlyPublicKey) -> TapTree<XOnlyPublicKey> {
        let Descriptor::Tr(tr) = format!("tr({a},and_v(v:pk({a}),pk({b})))")
            .parse::<Descriptor<XOnlyPublicKey>>()
            .unwrap()
        else {
            unreachable!()
        };
        tr.tap_tree().clone().unwrap()
    }

    #[test]
    fn test_create_wallet() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert_eq!(bmp_wallet.imported_keys.len(), 0);
        assert_eq!(bmp_wallet.balance(), Amount::from_sat(0));

        let seed = bmp_wallet.get_seed_phrase()?;

        tracing::info!("Generated mnemonic {} ", seed);
        assert!(!seed.is_empty());

        let receiving_addr = bmp_wallet.get_new_address()?;

        assert_eq!(receiving_addr.address_type(), Some(AddressType::P2tr));

        tracing::info!("Generated address {:?}", receiving_addr);

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
        let stored_seed: String;
        let stored_balance: Amount;
        let last_generated_addr: AddressInfo;
        let dir = get_dir();
        {
            let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
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

        let mut wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
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
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let pk1 = new_private_key();
        let pk2 = new_private_key();

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
        assert_eq!(loaded_wallet.imported_keys, bmp_wallet.imported_keys);
        Ok(())
    }

    #[test]
    fn test_imported_keys_with_tap_tree() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let pk = new_private_key();

        // A tap tree like the protocol's deposit payout: and_v(v:pk(A),pk(B))
        let (a, b) = (
            derive_public_key(&new_private_key()),
            derive_public_key(&new_private_key()),
        );
        let tap_tree = sample_tap_tree(&a, &b);

        bmp_wallet.import_private_key(pk, Some(tap_tree.clone()))?;

        assert_eq!(bmp_wallet.imported_keys.len(), 1);
        let merkle_root = bmp_wallet.imported_keys[0]
            .merkle_root()
            .expect("merkle root should be present");

        // Persist
        bmp_wallet.persist()?;
        let loaded_wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;

        assert_eq!(loaded_wallet.imported_keys.len(), 1);

        let loaded = &loaded_wallet.imported_keys[0];
        assert_eq!(loaded.secret(), pk);
        assert_eq!(loaded.internal_key(), derive_public_key(&pk));
        assert_eq!(loaded.tap_tree(), Some(&tap_tree));
        assert_eq!(loaded.merkle_root(), Some(merkle_root));
        assert_eq!(loaded_wallet.imported_keys, bmp_wallet.imported_keys);

        Ok(())
    }

    #[tokio::test]
    async fn test_sync() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(1));

        tracing::info!("Wallet balance after syncing {}", bmp_wallet.balance());

        tracing::info!("{:#?}", bmp_wallet.tx_graph());
        Ok(())
    }

    #[tokio::test]
    async fn test_sync_with_imported_keys() -> anyhow::Result<()> {
        let pk1 = new_private_key();
        let pk2 = new_private_key();
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        tracing::info!("Wallet balance after syncing {}", bmp_wallet.balance());
        Ok(())
    }

    #[tokio::test]
    async fn sign_inputs_main_wallet_only() -> anyhow::Result<()> {
        let client = MockedBDKElectrum {};
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(1));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_sat(100_000);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_inputs_main_and_imported_keys() -> anyhow::Result<()> {
        let client = MockedBDKElectrum {};
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let keys_to_import = [new_private_key(), new_private_key()];
        for k in &keys_to_import {
            bmp_wallet.import_private_key(*k, None)?;
        }

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let mut tx_builder = bmp_wallet.build_tx();
        tx_builder.add_recipient(to_address, to_spend);

        let first_key_wallet = load_imported_wallet(dir.path(), &keys_to_import[0])?;
        let second_key_wallet = load_imported_wallet(dir.path(), &keys_to_import[1])?;

        let first_key_unspents = first_key_wallet.list_unspent().collect::<Vec<_>>();
        let second_key_unspents = second_key_wallet.list_unspent().collect::<Vec<_>>();

        assert_eq!(first_key_unspents.len(), 1);
        assert_eq!(second_key_unspents.len(), 1);

        for i in &first_key_unspents {
            let psbt_input = psbt::Input {
                witness_utxo: Some(i.txout.clone()),
                tap_internal_key: Some(derive_public_key(&keys_to_import[0])),
                ..Default::default()
            };
            tx_builder
                .add_foreign_utxo(i.outpoint, psbt_input, Weight::from_wu(66))
                .unwrap();
        }

        for i in &second_key_unspents {
            let psbt_input = psbt::Input {
                witness_utxo: Some(i.txout.clone()),
                tap_internal_key: Some(derive_public_key(&keys_to_import[1])),
                ..Default::default()
            };
            tx_builder
                .add_foreign_utxo(i.outpoint, psbt_input, Weight::from_wu(66))
                .unwrap();
        }

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_imported_key_tap_tree() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let pk = new_private_key();
        let (a, b) = (
            derive_public_key(&new_private_key()),
            derive_public_key(&new_private_key()),
        );
        let tap_tree = sample_tap_tree(&a, &b);

        // Import private key with tap tree
        bmp_wallet.import_private_key(pk, Some(tap_tree))?;
        let imported = bmp_wallet.imported_keys[0].clone();
        let merkle_root = imported
            .merkle_root()
            .expect("merkle root should be present");

        // The output the key controls is tr(P, tap_tree), *not* tr(P)
        let secp = Secp256k1::new();
        let xonly = derive_public_key(&pk);
        assert_eq!(
            imported.script_pubkey(),
            ScriptBuf::new_p2tr(&secp, xonly, Some(merkle_root))
        );

        // Put a utxo paying to tr(P, tap_tree) into the wallet's graph, the way `sync_all` does,
        // and let the wallet's own `build_tx` path (imported_utxos) prepare the PSBT input.
        let outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001:0",
        )?;
        let txout = TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: imported.script_pubkey(),
        };
        bmp_wallet.insert_txout(outpoint, txout);

        let mut tx_builder = bmp_wallet.build_tx();

        // Add a recipient so transaction can be built
        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        tx_builder.add_recipient(to_address, Amount::from_sat(100_000));

        let mut res_psbt = tx_builder.finish()?;

        assert_eq!(res_psbt.inputs.len(), 1);
        assert_eq!(res_psbt.inputs[0].tap_internal_key, Some(xonly));
        assert_eq!(res_psbt.inputs[0].tap_merkle_root, Some(merkle_root));

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        // The key-path signature must verify against the *tweaked* output key
        let witness = res_psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(
            witness.len(),
            1,
            "key-path spend has a single witness element"
        );
        let sig = taproot::Signature::from_slice(&witness[0])?;
        let output_key = xonly
            .tap_tweak(&secp, Some(merkle_root))
            .0
            .to_x_only_public_key();
        let sighash = {
            let prevouts = [res_psbt.inputs[0].witness_utxo.clone().unwrap()];
            let mut cache = SighashCache::new(&res_psbt.unsigned_tx);
            cache.taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                sig.sighash_type,
            )?
        };
        secp.verify_schnorr(&sig.signature, &Message::from(sighash), &output_key)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_selection_with_main_and_imported() -> anyhow::Result<()> {
        let client = MockedBDKElectrum {};
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let pk1: [u8; 32] = [
            180, 143, 139, 78, 9, 248, 73, 139, 169, 173, 99, 191, 248, 54, 50, 207, 137, 222, 85,
            70, 228, 53, 252, 227, 191, 26, 160, 101, 121, 195, 74, 212,
        ];

        let pk2: [u8; 32] = [
            78, 212, 125, 103, 117, 115, 156, 113, 203, 95, 207, 59, 190, 106, 63, 162, 225, 131,
            186, 216, 94, 123, 55, 23, 125, 232, 214, 160, 33, 172, 124, 61,
        ];

        bmp_wallet.import_private_key(Scalar::from_slice(&pk1).unwrap(), None)?;
        bmp_wallet.import_private_key(Scalar::from_slice(&pk2).unwrap(), None)?;

        bmp_wallet.sync_all(&client).await?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
        let to_address = to_address.parse::<Address<_>>()?.assume_checked();
        let to_spend = Amount::from_int_btc(2);

        let mut tx_builder = bmp_wallet.build_tx();

        tx_builder.add_recipient(to_address, to_spend);

        let mut res_psbt = tx_builder.finish()?;

        bmp_wallet.sign(&mut res_psbt, SignOptions::default())?;

        assert!(
            res_psbt
                .inputs
                .iter()
                .all(|i| i.final_script_witness.is_some())
        );

        Ok(())
    }

    #[test]
    #[should_panic = "file is not a database"]
    fn encrypted_wallet() {
        let dir = get_dir();
        let bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest).unwrap();
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Try loading the wallet with wrong decryption key should panic
        let lw = BMPWallet::load_wallet(dir.path(), Network::Regtest, "secret123").unwrap();
        lw.get_seed_phrase().unwrap();
    }

    #[test]
    fn encrypted_wallet_with_decryption() -> anyhow::Result<()> {
        let dir = get_dir();
        let bmp_wallet = BMPWallet::new(dir.path(), "secret123", Network::Regtest)?;
        let seed = bmp_wallet.get_seed_phrase().unwrap();

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        assert!(!seed.is_empty());
        assert_eq!(seed.split_whitespace().count(), 24);

        // Load the wallet with right decryption key
        let lw = BMPWallet::load_wallet(dir.path(), Network::Regtest, "secret123").unwrap();
        assert_eq!(lw.get_seed_phrase().unwrap(), seed);
        Ok(())
    }

    /// Creating over an existing wallet must fail *before* the salt is touched. A caller that
    /// treats a failed `load_wallet` (e.g. a wrong password) as "no wallet here" would otherwise
    /// rewrite the salt and leave the existing database impossible to decrypt.
    #[test]
    fn new_refuses_to_overwrite_an_existing_wallet() -> anyhow::Result<()> {
        let dir = get_dir();
        let salt_path = dir
            .path()
            .join(format!("{}.salt", BMPWallet::<Connection>::DB_NAME));

        let seed = {
            let wallet = BMPWallet::new(dir.path(), "secret123", Network::Regtest)?;
            wallet.get_seed_phrase()?
        };
        let salt_before = fs::read(&salt_path)?;

        // `BMPWallet` isn't `Debug`, so `expect_err` isn't available here.
        let Err(err) = BMPWallet::new(dir.path(), "a different password", Network::Regtest) else {
            panic!("creating over an existing wallet must fail");
        };
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {err}"
        );

        assert_eq!(
            fs::read(&salt_path)?,
            salt_before,
            "the salt must survive a refused creation, or the wallet becomes unopenable"
        );

        // The original password still opens the original wallet.
        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "secret123")?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }

    #[tokio::test]
    async fn drain_wallet() -> anyhow::Result<()> {
        let pk1 = new_private_key();
        let pk2 = new_private_key();
        let dir = get_dir();
        let mut bmp_wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        bmp_wallet.import_private_key(pk1, None)?;
        bmp_wallet.import_private_key(pk2, None)?;

        assert_eq!(bmp_wallet.imported_keys.len(), 2);

        let client = MockedBDKElectrum {};

        tracing::info!("Wallet balance before syncing {}", bmp_wallet.balance());
        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(0));

        bmp_wallet.sync_all(&client).await?;

        assert_eq!(bmp_wallet.balance(), Amount::from_int_btc(3));
        assert_eq!(
            bmp_wallet.imported_balance.trusted_spendable(),
            Amount::from_int_btc(2)
        );

        // Now attempt to drain the 2 BTC from the imported wallets
        let psbt = bmp_wallet.drain_imported_balance(FeeRate::from_sat_per_kwu(25_000))?;
        let tx = psbt.extract_tx()?;
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_str("1.99983150 BTC")?);

        Ok(())
    }

    #[tokio::test]
    async fn test_wallet_with_path_creation() -> anyhow::Result<()> {
        let dir_one = get_dir();
        let dir_two = get_dir();

        let client = MockedBDKElectrum {};

        tracing::debug!("Wallet path {:?}", dir_one);
        tracing::debug!("Wallet 2 path {:?}", dir_two);

        let mut w1 = BMPWallet::new(dir_one.path(), "", Network::Regtest)?;
        let w2 = BMPWallet::new(dir_two.path(), "", Network::Regtest)?;

        tracing::debug!("Wallet one balance before syncing {}", w1.balance());
        assert_eq!(w1.balance(), Amount::from_int_btc(0));
        w1.sync_all(&client).await?;

        assert_eq!(w1.balance(), Amount::from_int_btc(1));
        assert_eq!(w2.balance(), Amount::ZERO);
        Ok(())
    }

    #[test]
    fn test_address_generation() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let mut add_vec: Vec<AddressInfo> = vec![];

        loop {
            add_vec.push(wallet.next_address(KeychainKind::External)?);
            if add_vec.len() >= STOP_GAP {
                break;
            }
        }

        // Since we reached STOP_GAP, next_address should return one address from the add_vec list
        let new_addr = wallet.next_address(KeychainKind::External)?;
        assert!(add_vec.contains(&new_addr));

        // Returned next address should be different from previous one but still exist in the list
        let new_addr2 = wallet.next_address(KeychainKind::External)?;
        assert!(add_vec.contains(&new_addr2) && new_addr != new_addr2);

        Ok(())
    }

    #[test]
    fn test_list_unused_addresses_since_last_used() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        // Reveal a handful of addresses (indices 0..=4).
        let revealed: Vec<AddressInfo> = (0..5)
            .map(|_| wallet.reveal_next_address(KeychainKind::External))
            .collect();
        let revealed_indices: Vec<u32> = revealed.iter().map(|a| a.index).collect();
        assert_eq!(revealed_indices, vec![0, 1, 2, 3, 4]);

        // With no on-chain activity, the new method returns the same set
        // as list_unused_addresses.
        let baseline: Vec<u32> = wallet
            .list_unused_addresses(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        assert_eq!(since_last, baseline);
        assert_eq!(since_last, vec![0, 1, 2, 3, 4]);

        // Receive an output on the address at index 2. The "last used" index
        // is now 2, so list_unused_addresses_since_last_used must exclude
        // indices 0 and 1 (gap addresses) even though list_unused_addresses
        // still includes them.
        receive_output_to_address(
            &mut wallet,
            revealed[2].address.clone(),
            Amount::ONE_BTC,
            ReceiveTo::Block(chain::ConfirmationBlockTime {
                block_id: BlockId {
                    height: 2,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 2,
            }),
        );

        let baseline: Vec<u32> = wallet
            .list_unused_addresses(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        // The unfiltered list still surfaces the gap indices 0 and 1.
        assert_eq!(baseline, vec![0, 1, 3, 4]);

        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        // Filtered list drops everything at or below the last used index.
        assert_eq!(since_last, vec![3, 4]);

        // Receive on the highest revealed index (4). No unused address with
        // a greater index exists yet, so the iterator should be empty —
        // confirming the threshold tracks the *maximum* used index.
        receive_output_to_address(
            &mut wallet,
            revealed[4].address.clone(),
            Amount::ONE_BTC,
            ReceiveTo::Block(chain::ConfirmationBlockTime {
                block_id: BlockId {
                    height: 3,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 3,
            }),
        );

        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        assert!(
            since_last.is_empty(),
            "expected no unused addresses past the highest used index, got {since_last:?}"
        );

        // Reveal one more address; it should now be the sole result.
        let new_addr = wallet.reveal_next_address(KeychainKind::External);
        assert_eq!(new_addr.index, 5);

        let since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::External)
            .map(|a| a.index)
            .collect();
        assert_eq!(since_last, vec![5]);

        // The internal keychain has had no on-chain activity at all, so the
        // method must fall back to "all revealed unused" for that keychain.
        let internal_addr = wallet.reveal_next_address(KeychainKind::Internal);
        let internal_since_last: Vec<u32> = wallet
            .list_unused_addresses_since_last_used(KeychainKind::Internal)
            .map(|a| a.index)
            .collect();
        assert!(internal_since_last.contains(&internal_addr.index));

        Ok(())
    }

    // --- the GUI-facing query/mutation surface ---------------------------------------------

    #[tokio::test]
    async fn list_transactions_describes_an_incoming_payment() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert!(
            wallet.list_transactions().is_empty(),
            "nothing before syncing"
        );

        // MockedBDKElectrum confirms 1 BTC to the wallet in the latest block.
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let txs = wallet.list_transactions();
        assert_eq!(txs.len(), 1);
        let tx = &txs[0];

        assert!(tx.incoming, "a received payment must be flagged incoming");
        assert_eq!(
            tx.amount,
            Amount::ONE_BTC,
            "amount is the net effect on the wallet"
        );
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, Amount::ONE_BTC);
        assert!(
            tx.outputs[0].address.is_some(),
            "a P2TR output must decode to an address"
        );
        assert_eq!(tx.lock_time, 0);

        // Confirmed in the tip block, so exactly one confirmation, with a real timestamp.
        assert!(
            tx.block_height.is_some(),
            "expected a confirmed tx, got {:?}",
            tx.block_height
        );
        assert_eq!(tx.num_confirmations, 1);
        assert!(tx.timestamp.is_some());
        // bisq2 decodes this with Instant.ofEpochSecond; a millisecond value would be absurd.
        assert!(
            tx.timestamp.unwrap() < 4_000_000_000,
            "timestamp must be in seconds"
        );

        Ok(())
    }

    #[tokio::test]
    async fn list_transactions_reports_an_outgoing_payment() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        let tx = wallet.send_to_address(
            &to_address,
            Amount::from_sat(100_000),
            FeeRate::from_sat_per_kwu(250),
        )?;

        let spend = wallet
            .list_transactions()
            .into_iter()
            .find(|info| info.tx_id == tx.compute_txid())
            .expect("the spend must show up in the transaction list");

        assert!(!spend.incoming, "a spend must not be flagged incoming");
        // Net effect = payment + fee, i.e. everything that left the wallet after change.
        assert!(
            spend.amount >= Amount::from_sat(100_000),
            "outgoing amount {} must cover the payment",
            spend.amount
        );
        assert!(
            spend.amount < Amount::ONE_BTC,
            "change must not be counted as spent"
        );
        assert_eq!(
            spend.num_confirmations, 0,
            "a freshly built tx is unconfirmed"
        );
        assert_eq!(spend.block_height, None);
        assert_eq!(spend.timestamp, None);
        assert!(!spend.inputs.is_empty(), "a spend must have inputs");
        assert!(
            spend.inputs.iter().all(|input| !input.witness.is_empty()),
            "signed inputs must carry a witness"
        );

        Ok(())
    }

    /// A payment must count as spent the moment it is handed out, not once it confirms —
    /// otherwise the next payment re-selects the same coin and (RBF) replaces the first one.
    #[tokio::test]
    async fn send_to_address_marks_its_inputs_spent() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;
        assert_eq!(wallet.balance(), Amount::ONE_BTC, "one coin to spend from");

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        let amount = Amount::from_sat(60_000_000);
        let fee_rate = FeeRate::from_sat_per_kwu(250);

        let first = wallet.send_to_address(&to_address, amount, fee_rate)?;
        let spent: Vec<OutPoint> = first.input.iter().map(|i| i.previous_output).collect();

        // The coin just spent is gone from the unspent set right away, and the balance drops
        // to the (unconfirmed) change.
        assert!(
            wallet.list_unspent().all(|u| !spent.contains(&u.outpoint)),
            "inputs of an unconfirmed payment must not be listed as unspent"
        );
        assert!(
            wallet.balance() < Amount::ONE_BTC - amount,
            "balance {} must exclude the payment",
            wallet.balance()
        );

        // Only ~0.4 BTC of change is left, so a second 0.6 BTC payment has to fail. Before the
        // spend was recorded it would instead "succeed" by re-selecting the 1 BTC input — a
        // replacement of the first payment.
        let err = wallet
            .send_to_address(&to_address, amount, fee_rate)
            .expect_err("must not re-spend the inputs of an unconfirmed payment");
        assert!(err.to_string().contains("Insufficient funds"), "got: {err}");

        // The spend is persisted, not merely staged: it survives a reload.
        drop(wallet);
        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
        assert!(
            reloaded
                .list_unspent()
                .all(|u| !spent.contains(&u.outpoint)),
            "a reloaded wallet must still know about the spend"
        );
        assert!(reloaded.balance() < Amount::ONE_BTC - amount);

        Ok(())
    }

    #[tokio::test]
    async fn list_utxos_covers_own_and_imported_outputs() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert!(wallet.list_utxos().is_empty(), "nothing before syncing");

        wallet.import_private_key(new_private_key(), None)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let utxos = wallet.list_utxos();
        assert_eq!(utxos.len(), 3, "1 own + 2 imported: {utxos:#?}");

        let own: Vec<_> = utxos.iter().filter(|u| !u.imported).collect();
        let imported: Vec<_> = utxos.iter().filter(|u| u.imported).collect();
        assert_eq!(own.len(), 1);
        assert_eq!(imported.len(), 2);

        assert_eq!(own[0].amount, Amount::ONE_BTC);
        assert_eq!(own[0].num_confirmations, 1);
        assert!(own[0].address.is_some());

        for utxo in imported {
            assert_eq!(utxo.amount, Amount::ONE_BTC);
            assert!(
                utxo.address.is_some(),
                "imported P2TR outputs must decode to an address"
            );
        }

        // The total must agree with what the balance reports, or the GUI contradicts itself.
        let utxo_total: Amount = utxos.iter().map(|u| u.amount).sum();
        assert_eq!(utxo_total, wallet.full_balance().trusted_spendable());

        Ok(())
    }

    #[tokio::test]
    async fn list_utxos_drops_spent_imported_outputs() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let imported = |w: &BMPWallet<_>| w.list_utxos().iter().filter(|u| u.imported).count();
        assert_eq!(imported(&wallet), 1, "the imported coin starts out unspent");

        // Sweep the imported coin, then let the wallet see the spending transaction. Imported
        // outputs are floating txouts with no chain position, so the only way to know they are
        // gone is that something in the graph spends them.
        let psbt = wallet.drain_imported_balance(FeeRate::from_sat_per_kwu(25_000))?;
        let spend = psbt.extract_tx()?;
        bdk_wallet::test_utils::insert_tx(&mut wallet.wallet, spend);

        assert_eq!(
            imported(&wallet),
            0,
            "a spent imported output must not still be listed as unspent"
        );

        Ok(())
    }

    #[tokio::test]
    async fn full_balance_includes_imported_keys() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert_eq!(wallet.full_balance().total(), Amount::ZERO);

        wallet.import_private_key(new_private_key(), None)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let balance = wallet.full_balance();
        assert_eq!(
            balance.total(),
            Amount::from_int_btc(2),
            "1 own + 1 imported"
        );
        assert_eq!(balance.confirmed, Amount::from_int_btc(2));
        assert_eq!(balance.untrusted_pending, Amount::ZERO);
        // The flattened `WalletApi::balance` must stay consistent with the breakdown.
        assert_eq!(wallet.balance(), balance.trusted_spendable());

        Ok(())
    }

    #[test]
    fn list_wallet_addresses_covers_both_keychains() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        assert!(
            wallet.list_wallet_addresses().is_empty(),
            "nothing revealed yet"
        );

        let external = wallet.get_new_address()?;
        let internal = wallet.get_change_address()?;

        let addresses = wallet.list_wallet_addresses();
        assert!(
            addresses.contains(&external.address.to_string()),
            "missing external address"
        );
        assert!(
            addresses.contains(&internal.address.to_string()),
            "missing change address"
        );
        assert_eq!(addresses.len(), 2, "one per keychain so far: {addresses:?}");

        // Revealing more must extend the list rather than replace it.
        let another = wallet.get_new_address()?;
        let addresses = wallet.list_wallet_addresses();
        assert_eq!(addresses.len(), 3);
        assert!(addresses.contains(&another.address.to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn send_to_address_builds_a_fully_signed_tx() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
        wallet.sync_all(&MockedBDKElectrum {}).await?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        let to_spend = Amount::from_sat(100_000);

        let tx = wallet.send_to_address(&to_address, to_spend, FeeRate::from_sat_per_kwu(250))?;

        assert!(
            tx.input.iter().all(|input| !input.witness.is_empty()),
            "extract_tx must only succeed on a fully signed tx"
        );
        assert!(
            tx.output
                .iter()
                .any(|output| output.script_pubkey == to_address.script_pubkey()
                    && output.value == to_spend),
            "the payment output must be present with the requested amount"
        );

        Ok(())
    }

    #[tokio::test]
    async fn send_to_address_rejects_an_unaffordable_payment() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;

        let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
            .parse::<Address<_>>()?
            .assume_checked();
        // Nothing synced, so there is nothing to spend.
        let result = wallet.send_to_address(
            &to_address,
            Amount::from_sat(100_000),
            FeeRate::from_sat_per_kwu(250),
        );
        assert!(result.is_err(), "spending from an empty wallet must fail");

        Ok(())
    }

    #[test]
    fn change_password_rotates_the_key_and_survives_a_reload() -> anyhow::Result<()> {
        let dir = get_dir();
        let seed = {
            let mut wallet = BMPWallet::new(dir.path(), "", Network::Regtest)?;
            assert!(!wallet.is_encrypted(), "created without a password");
            assert!(
                wallet.check_password("")?,
                "empty password is the current one"
            );

            let seed = wallet.get_seed_phrase()?;
            wallet.change_password("", "s3cret")?;

            assert!(wallet.is_encrypted());
            assert!(wallet.check_password("s3cret")?, "new password must verify");
            assert!(
                !wallet.check_password("")?,
                "old password must stop verifying"
            );
            assert_eq!(
                wallet.get_seed_phrase()?,
                seed,
                "seed must survive the re-key"
            );
            seed
        };

        // The rotated salt and key must both have reached disk.
        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "s3cret")?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);
        assert!(reloaded.is_encrypted());
        drop(reloaded);

        let stale = BMPWallet::load_wallet(dir.path(), Network::Regtest, "");
        assert!(
            stale.is_err() || stale.unwrap().get_seed_phrase().is_err(),
            "the pre-encryption password must no longer open the wallet"
        );

        Ok(())
    }

    /// Re-keying requires proof of the current password, so a caller who cannot present it must
    /// not be able to rotate the key and lock the owner out.
    #[test]
    fn change_password_refuses_a_wrong_old_password() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "orig", Network::Regtest)?;
        let seed = wallet.get_seed_phrase()?;

        let Err(err) = wallet.change_password("attacker", "attacker") else {
            panic!("re-keying without the current password must fail");
        };
        assert!(
            err.to_string().contains("invalid wallet password"),
            "unexpected error: {err}"
        );

        assert!(wallet.is_encrypted());
        assert!(
            wallet.check_password("orig")?,
            "the original password must still be the one in force"
        );
        assert!(
            !wallet.check_password("attacker")?,
            "the rejected password must not have taken effect"
        );
        drop(wallet);

        // ...and that survives a reload, i.e. nothing reached disk.
        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "orig")?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }

    /// Replacing one password with another happens in a single authenticated step.
    #[test]
    fn change_password_replaces_the_password_in_one_step() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "orig", Network::Regtest)?;
        let seed = wallet.get_seed_phrase()?;

        wallet.change_password("orig", "fresh")?;

        assert!(wallet.is_encrypted());
        assert!(wallet.check_password("fresh")?);
        assert!(
            !wallet.check_password("orig")?,
            "old password must stop verifying"
        );
        drop(wallet);

        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "fresh")?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }

    /// An empty new password removes protection — but only for the holder of the current one.
    #[test]
    fn removing_the_password_requires_the_current_one() -> anyhow::Result<()> {
        let dir = get_dir();
        let mut wallet = BMPWallet::new(dir.path(), "orig", Network::Regtest)?;
        let seed = wallet.get_seed_phrase()?;
        assert!(wallet.is_encrypted());

        assert!(
            wallet.change_password("wrong", "").is_err(),
            "wrong password must be rejected"
        );
        assert!(
            wallet.is_encrypted(),
            "a rejected change must not clear the flag"
        );
        assert!(wallet.check_password("orig")?, "...nor rotate the key");

        wallet.change_password("orig", "")?;
        assert!(!wallet.is_encrypted());
        drop(wallet);

        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "")?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }

    /// A leftover staged salt — from a password change that failed before the re-key — must
    /// neither stop nor confuse a normal load, and must be cleaned up.
    #[test]
    fn load_ignores_and_cleans_a_stale_staged_salt() -> anyhow::Result<()> {
        let dir = get_dir();
        let seed = {
            let wallet = BMPWallet::new(dir.path(), "pw", Network::Regtest)?;
            wallet.get_seed_phrase()?
        };

        let staged_salt_path = dir
            .path()
            .join(format!("{}.salt.new", BMPWallet::<Connection>::DB_NAME));
        fs::write(&staged_salt_path, "bm90LXRoZS1yZWFsLXNhbHQ=")?; // valid base64, wrong salt

        let wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "pw")?;
        assert_eq!(wallet.get_seed_phrase()?, seed);
        assert!(
            !staged_salt_path.exists(),
            "the stale staged salt must be cleaned up"
        );

        Ok(())
    }

    /// Simulates a crash *between* the `SQLCipher` re-key and the rename that commits the rotated
    /// salt (see `BMPWallet::rekey`): the primary salt no longer matches the database key, only
    /// the staged one does. `load_wallet` must complete the interrupted rotation.
    #[test]
    fn load_recovers_an_interrupted_salt_rotation() -> anyhow::Result<()> {
        use base64::Engine as _;

        use crate::utils::{derive_key_from_password, get_salt};

        let dir = get_dir();
        let seed = {
            let wallet = BMPWallet::new(dir.path(), "pw", Network::Regtest)?;
            wallet.get_seed_phrase()?
        };

        let db_path = dir.path().join(BMPWallet::<Connection>::DB_NAME);
        let db_path_str = db_path.to_str().unwrap();
        let staged_salt_path = format!("{db_path_str}.salt.new");

        // Re-key the database to a fresh salt that is staged but not yet committed — exactly
        // the state a crash at rekey's commit point leaves behind.
        let old_salt = get_salt(db_path_str)?;
        let mut new_salt = [0u8; 16];
        rand::rng().fill_bytes(&mut new_salt);
        fs::write(
            &staged_salt_path,
            base64::engine::general_purpose::STANDARD.encode(new_salt),
        )?;
        {
            let db = Connection::open(&db_path)?;
            let old_key = derive_key_from_password("pw", &old_salt)?;
            db.pragma_update(None, "key", old_key.as_str())?;
            let new_key = derive_key_from_password("pw", &new_salt)?;
            db.pragma_update(None, "rekey", new_key.as_str())?;
        }

        let wallet = BMPWallet::load_wallet(dir.path(), Network::Regtest, "pw")?;
        assert_eq!(
            wallet.get_seed_phrase()?,
            seed,
            "recovery must yield the same wallet"
        );
        assert!(
            !std::path::Path::new(&staged_salt_path).exists(),
            "the staged salt must have been committed"
        );
        assert_eq!(
            get_salt(db_path_str)?,
            new_salt.to_vec(),
            "the committed salt must be the rotated one"
        );
        assert!(wallet.check_password("pw")?, "password still verifies");
        drop(wallet);

        // And a subsequent plain load works off the committed salt.
        let reloaded = BMPWallet::load_wallet(dir.path(), Network::Regtest, "pw")?;
        assert_eq!(reloaded.get_seed_phrase()?, seed);

        Ok(())
    }
}
