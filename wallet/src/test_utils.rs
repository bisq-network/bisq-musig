use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::hex::DisplayHex;
use bdk_wallet::bitcoin::key::{Keypair, Secp256k1, TapTweak};
use bdk_wallet::bitcoin::secp256k1::{schnorr, Message};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_wallet::bitcoin::{
    Amount, BlockHash, Network, PrivateKey, TapSighashType, Transaction, TxOut, Witness,
    XOnlyPublicKey,
};
use bdk_wallet::chain::BlockId;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
use bdk_wallet::{PersistedWallet, Wallet};
use secp::Scalar;

use crate::bmp_wallet::BMPWalletPersister;
use crate::chain_data_source::ChainDataSource;
pub struct MockedBDKElectrum;

impl ChainDataSource for MockedBDKElectrum {
    const RECOVERY_HEIGHT: usize = 10;
    const RECOVERY_LOOKAHEAD: usize = 10;
    const BATCH_SIZE: usize = 10;
    const STOP_GAP: usize = 10;

    fn sync(&self, persister: &mut PersistedWallet<impl BMPWalletPersister>) -> anyhow::Result<()> {
        insert_checkpoint(
            persister,
            BlockId {
                height: 42,
                hash: BlockHash::all_zeros(),
            },
        );
        insert_checkpoint(
            persister,
            BlockId {
                height: 1_000,
                hash: BlockHash::all_zeros(),
            },
        );
        insert_checkpoint(
            persister,
            BlockId {
                height: 2_000,
                hash: BlockHash::all_zeros(),
            },
        );

        receive_output_in_latest_block(persister, Amount::ONE_BTC);

        Ok(())
    }
}

pub fn verify_signature(
    signing_key: &PrivateKey,
    witness: &Witness,
    unsigned_tx: &Transaction,
    prev_outputs: &[TxOut],
) -> anyhow::Result<()> {
    // To verify, we need the signature, message, and pubkey
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &signing_key.inner);
    let signature = schnorr::Signature::from_slice(witness.iter().next().unwrap())?;

    let prevouts = Prevouts::All(prev_outputs);
    let input_index = 0;
    let mut sighash_cache = SighashCache::new(unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
        .unwrap();

    let message = Message::from(sighash);

    // add tweak. this was taken from `signer::sign_psbt_schnorr`
    let keypair = keypair.tap_tweak(&secp, None).to_keypair();
    let xonlykey = XOnlyPublicKey::from_keypair(&keypair).0; // ignoring the parity

    // Must verify if we used the correct key to sign
    let verify_res = secp.verify_schnorr(&signature, &message, &xonlykey);
    assert!(verify_res.is_ok(), "The wrong internal key was used");
    Ok(())
}

pub fn load_imported_wallet(key: &Scalar) -> anyhow::Result<PersistedWallet<Connection>> {
    let pbk = key.base_point_mul();
    let pubk = pbk.serialize_xonly().to_lower_hex_string();
    let db_path = format!("bmp_{}.db3", pubk);

    let mut db = Connection::open(db_path)?;
    let imported_wallet_opt = Wallet::load()
        .check_network(Network::Regtest)
        .extract_keys()
        .load_wallet(&mut db)?;

    Ok(imported_wallet_opt.unwrap())
}

pub fn derive_public_key(key: &Scalar) -> XOnlyPublicKey {
    let xonly_pubkey = key.base_point_mul().serialize_xonly();
    XOnlyPublicKey::from_slice(&xonly_pubkey).expect("Should be valid xonlypub key")
}
