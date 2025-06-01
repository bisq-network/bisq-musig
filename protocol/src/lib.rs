use bdk_electrum::bdk_core::bitcoin;
use bdk_electrum::bdk_core::bitcoin::key::{Keypair, Secp256k1, TweakedKeypair};
use bdk_electrum::bdk_core::bitcoin::secp256k1::Message;
use bdk_electrum::bdk_core::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_electrum::bdk_core::bitcoin::{TapSighashType, Witness};
use bdk_wallet::bitcoin::key::TapTweak;
use musig2::secp::{Point, Scalar};
use musig2::KeyAggContext;
use once_cell::sync::OnceCell;
use regtest_env;
mod protocol_musig_adaptor;
mod wallet_test_utils;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_test_utils;
    use crate::protocol_musig_adaptor::{BMPContext, BMPProtocol, ProtocolRole};
    use bdk_electrum::bdk_core::bitcoin::Amount;
    
    static TEST_SETUP: OnceCell<()> = OnceCell::new();
    
    pub(crate) fn ensure_test_setup() {
        TEST_SETUP.get_or_init(|| {
            regtest_env::setup();
        });
    }

    #[test]
    fn test_musig() -> anyhow::Result<()> {
        ensure_test_setup();
        initial_tx_creation()?;
        Ok(())
    }

    pub fn initial_tx_creation() -> anyhow::Result<(BMPProtocol, BMPProtocol)> {
        println!("running...");
        let mut alice_funds = wallet_test_utils::funded_wallet();
        //TestWallet::new()?;

        let bob_funds = wallet_test_utils::funded_wallet();
        //TestWallet::new()?;
        wallet_test_utils::fund_wallet(&mut alice_funds);
        let seller_amount = &Amount::from_btc(1.4)?;
        let buyer_amount = &Amount::from_btc(0.2)?;

        // init p3 --------------------------
        let alice_context = BMPContext::new(alice_funds, ProtocolRole::Seller, seller_amount.clone(), buyer_amount.clone())?;

        let mut alice = BMPProtocol::new(alice_context)?;
        let bob_context = BMPContext::new(bob_funds, ProtocolRole::Buyer, seller_amount.clone(), buyer_amount.clone())?;
        let mut bob = BMPProtocol::new(bob_context)?;
        wallet_test_utils::tiktok();

        // Round 1--------
        let alice_response = alice.round1()?;
        let bob_response = bob.round1()?;

        // Round2 -------
        let alice_r2 = alice.round2(bob_response)?;
        let bob_r2 = bob.round2(alice_response)?;

        println!("P2TR P' {}", alice.p_tik.get_agg_adr()?.to_string());
        println!("P2TR Q' {}", alice.q_tik.get_agg_adr()?.to_string());

        assert!(alice.get_p_tik_agg() == bob.get_p_tik_agg());
        assert!(alice.q_tik.agg_point == bob.q_tik.agg_point);

        // Round 3 ----------
        // let alice_sig_p = alice.warning_tx_me.sig_p.as_ref().unwrap();
        // let alice_adaptor_p = alice_sig_p.adaptor_sig.as_ref().unwrap();


        let alice_r3 = alice.round3(bob_r2)?;
        let bob_r3 = bob.round3(alice_r2)?;

        assert_eq!(alice_r3.deposit_txid, bob_r3.deposit_txid);

        // Round 4 ---------------------------
        let alice_r4 = alice.round4(bob_r3)?;
        let bob_r4 = bob.round4(alice_r3)?;

        // Round 5 --------------------------
        alice.round5(bob_r4)?;
        bob.round5(alice_r4)?;

        // done -----------------------------
        wallet_test_utils::tiktok();
        Ok((alice, bob))
    }

    #[test]
    fn test_swap() -> anyhow::Result<()> {
        ensure_test_setup();
        // create all transaction and Broadcast DepositTx already
        let (alice, bob) = initial_tx_creation()?;
        dbg!(&alice.swap_tx.tx);
        dbg!(&bob.swap_tx.tx);

        // alice broadcats SwapTx
        dbg!(alice.swap_tx.broadcast(alice.ctx));
        wallet_test_utils::tiktok();
        Ok(())
    }

    #[test]
    fn test_warning() -> anyhow::Result<()> {
        ensure_test_setup();
        // create all transaction and Broadcast DepositTx already
        let (alice, _bob) = initial_tx_creation()?;
        dbg!(&alice.warning_tx_me.tx);
        // alice broadcats WarningTx
        dbg!(alice.warning_tx_me.broadcast(&alice.ctx));
        wallet_test_utils::tiktok();
        Ok(())
    }

    #[test]
    fn test_claim() -> anyhow::Result<()> {
        ensure_test_setup();
        // create all transaction and Broadcast DepositTx already
        let (alice, _bob) = initial_tx_creation()?;
        // dbg!(&alice.warning_tx_me.tx);
        // alice broadcats WarningTx
        alice.warning_tx_me.broadcast(&alice.ctx);
        wallet_test_utils::tiktok();
        wallet_test_utils::tiktok(); // we have set time-delay t2 to 2 Blocks
        dbg!(&alice.claim_tx_me.tx);

        // according to BIP-68 min time to wait is 512sec
        // let mut remaining_time = 532;
        // while remaining_time > 0 {
        //     println!("Remaining time: {} seconds", remaining_time);
        //     thread::sleep(Duration::from_secs(10));
        //     remaining_time -= 10;
        // }
        // thread::sleep(Duration::from_secs(512)); //otherwise non-BIP68-final error

        let tx = alice.claim_tx_me.broadcast(alice.ctx)?;
        dbg!(tx);
        wallet_test_utils::tiktok();
        Ok(())
    }

    #[test]
    fn test_claim_too_early() -> anyhow::Result<()> {
        ensure_test_setup();
        // create all transaction and Broadcast DepositTx already
        let (alice, _bob) = initial_tx_creation()?;
        alice.warning_tx_me.broadcast(&alice.ctx);
        // wallet_test_utils::tiktok();
        wallet_test_utils::tiktok(); // we have set time-delay t2 to 2 Blocks

        let rtx = alice.claim_tx_me.broadcast(alice.ctx);
        match rtx {
            Ok(_) => panic!("ClaimTx should not go through, because its been broadcast too early.
            HINT: Do not run this test in parallel with other tests, use --test-threads=1"),
            Err(e) => {
                let error_message = format!("{:?}", e);
                // println!("{}", error_message);
                if !error_message.contains("non-BIP68-final") {
                    panic!("Wrong Errormessage: {}", error_message);
                }
            }
        }
        wallet_test_utils::tiktok();
        Ok(())
    }

    #[test]
    fn test_redirect() -> anyhow::Result<()> {
        ensure_test_setup();
        // create all transaction and Broadcast DepositTx already
        let (alice, bob) = initial_tx_creation()?;
        // dbg!(&alice.warning_tx_me.tx);
        // alice broadcats WarningTx
        let bob_warn_id = bob.warning_tx_me.broadcast(&bob.ctx);
        wallet_test_utils::tiktok();
        dbg!(bob_warn_id);

        let tx = alice.redirect_tx_me.broadcast(alice.ctx);
        dbg!(tx);
        wallet_test_utils::tiktok();
        Ok(())
    }
}

//noinspection ALL
#[test]
fn test_q_tik() -> anyhow::Result<()> {
    crate::tests::ensure_test_setup();
    // create all transaction and Broadcast DepositTx already
    let (alice, bob) = crate::tests::initial_tx_creation()?;
    // test!(alice.swap_tx.)

    // message
    let tx = bob.swap_tx.tx.clone().unwrap();
    let prevout = &bob.swap_tx.calc_prevouts(&bob.deposit_tx)?;
    let prevouts = Prevouts::All(prevout);
    let input_index = 0;

    let sighash_type = TapSighashType::Default;

    let mut sighasher = SighashCache::new(tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");
    let msg = Message::from(sighash);

    // path 1: secp sig  -----------------------------

    // let grab the keys and produce new sig
    let seckeys: Vec<musig2::secp::Scalar>
        = if &alice.q_tik.pub_point < &bob.q_tik.pub_point {
        vec![alice.q_tik.sec, bob.q_tik.sec]
    } else {
        vec![bob.q_tik.sec, alice.q_tik.sec]
    };
    // dbg!(&seckeys);
    let agg_ctx = alice.q_tik.key_agg_context.clone().unwrap();

    let agg_sec: Scalar = alice.q_tik.key_agg_context.as_ref().unwrap().aggregated_seckey(seckeys)?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &agg_sec.serialize())?;
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let sig1 = secp.sign_schnorr(&msg, &keypair); // wsill end up in Bad Signature
    // let sig1 = secp.sign_schnorr(&msg, &tweaked.to_inner());
    // Update the witness stack.
    let signature_secp = bitcoin::taproot::Signature { signature: sig1, sighash_type };
    let path1pubpoint = Point::from_slice(&keypair.public_key().serialize())?;
    let path1tweakpoint = Point::from_slice(&tweaked.to_inner().public_key().serialize())?;

    // KeyAgg with no_merkle -------
    // dbg!(&agg_ctx);
    let old_d: Point = agg_ctx.aggregated_pubkey();
    let d: Point = agg_ctx.clone()
        .with_unspendable_taproot_tweak()?
        .aggregated_pubkey();
    // How to do the signature with Point d and secure key?

    // AggKey ----------------------------------------------
    // dbg!(&alice.q_tik.key_agg_context.unwrap());
    let aggkey = alice.q_tik.agg_point.unwrap();

    // recalc ---------------------------
    let ac = agg_ctx.pubkeys();
    let pks = if ac[0] < ac[1] { [ac[0], ac[1]] } else { [ac[1], ac[0]] };
    let newctx = KeyAggContext::new(pks)?;
    dbg!(&newctx,&ac,&pks);
    let newaggkey: Point = newctx.aggregated_pubkey();
    let newctx2 = newctx.with_unspendable_taproot_tweak()?;
    let newtweaked: Point = newctx2.aggregated_pubkey();

    assert_eq!(&newaggkey, &newctx2.aggregated_pubkey_untweaked(), "newaggkey not equal");


    // verify ------------------------------------------
    dbg!(&path1pubpoint,&path1tweakpoint, &d, &aggkey, &old_d,&newtweaked,&newaggkey);

    assert_eq!(&d.serialize(), &tweaked.to_inner().public_key().serialize(), "pubkey not equal");
    // assert_eq!(dser, my_agg_point.serialize(), "my pubkey not equal");

    // use signature and broadcast ------------------------------------------
    *sighasher.witness_mut(input_index).unwrap() = Witness::p2tr_key_spend(&signature_secp);

    // Get the signed transaction.
    let tx = sighasher.into_transaction();

    let txid = alice.ctx.funds.client.transaction_broadcast(&tx)?;
    dbg!(txid);
    wallet_test_utils::tiktok();
    Ok(())
}
