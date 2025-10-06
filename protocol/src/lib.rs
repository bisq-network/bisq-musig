pub mod nigiri;
pub mod protocol_musig_adaptor;
pub mod psbt;
mod swap;
pub mod transaction;
pub mod wallet_service;

#[cfg(test)]
mod tests {
    use bdk_electrum::bdk_core::bitcoin;
    use bdk_electrum::bdk_core::bitcoin::key::{Keypair, Secp256k1, TweakedKeypair};
    use bdk_electrum::bdk_core::bitcoin::secp256k1::Message;
    use bdk_electrum::bdk_core::bitcoin::sighash::{Prevouts, SighashCache};
    use bdk_electrum::bdk_core::bitcoin::{Amount, TapSighashType, Witness};
    use bdk_wallet::bitcoin::key::TapTweak as _;
    use musig2::KeyAggContext;
    use musig2::secp::{Point, Scalar};

    use crate::nigiri;
    use crate::protocol_musig_adaptor::{BMPContext, BMPProtocol, ProtocolRole};
    use crate::wallet_service::WalletService;

    #[test]
    fn test_initial_tx_creation() -> anyhow::Result<()> {
        initial_tx_creation()?;
        Ok(())
    }

    pub fn initial_tx_creation() -> anyhow::Result<(BMPProtocol, BMPProtocol)> {
        println!("running...");
        nigiri::check_start();
        let mut alice_funds = nigiri::funded_wallet();
        //TestWallet::new()?;

        let bob_funds = nigiri::funded_wallet();
        //TestWallet::new()?;
        nigiri::fund_wallet(&mut alice_funds);
        let alice_service = WalletService::new().load(alice_funds);
        let bob_service = WalletService::new().load(bob_funds);
        let seller_amount = Amount::from_btc(1.4)?;
        let buyer_amount = Amount::from_btc(0.2)?;

        // up to here this was the preparation for the protocol, the code from now on needs to be called from outside API
        let alice_context = BMPContext::new(alice_service, ProtocolRole::Seller, seller_amount, buyer_amount)?;

        let mut alice = BMPProtocol::new(alice_context)?;
        let bob_context = BMPContext::new(bob_service, ProtocolRole::Buyer, seller_amount, buyer_amount)?;
        let mut bob = BMPProtocol::new(bob_context)?;
        nigiri::tiktok();

        // Round 1--------
        let alice_response = alice.round1()?;
        let bob_response = bob.round1()?;

        // Round2 -------
        let alice_r2 = alice.round2(bob_response)?;
        let bob_r2 = bob.round2(alice_response)?;

        // Round 3 ----------
        let alice_r3 = alice.round3(bob_r2)?;
        let bob_r3 = bob.round3(alice_r2)?;

        assert_eq!(alice_r3.deposit_txid, bob_r3.deposit_txid);

        // Round 4 ---------------------------
        let alice_r4 = alice.round4(bob_r3)?;
        let bob_r4 = bob.round4(alice_r3)?;

        // Round 5 all is ok, broadcasting deposit-tx ---------------------------
        alice.round5(bob_r4)?;
        bob.round5(alice_r4)?;

        // done -----------------------------
        nigiri::tiktok();
        Ok((alice, bob))
    }

    #[test]
    fn test_swap() -> anyhow::Result<()> {
        // create all transaction and Broadcast DepositTx already
        let (mut alice, mut bob) = initial_tx_creation()?;
        dbg!(&alice.swap_tx.tx);
        dbg!(&bob.swap_tx.tx);

        // alice broadcasts SwapTx
        let alice_swap = alice.swap_tx.sign(&alice.p_tik)?;
        dbg!(alice.swap_tx.broadcast(&alice.ctx));
        nigiri::tiktok();
        // bob must find the transaction and retrieve P_a from it and then spend DepositTx-Output0 to his wallet.
        // TODO need to read the transaction from blockchain looking for bob.swap_tx.txid
        // cheating and using the transaction from alice directly
        bob.swap_tx.reveal(&alice_swap, &mut bob.p_tik)?;
        assert!(bob.p_tik.agg_sec.is_some(), "We should have the aggregated secret key now");
        assert_eq!(bob.p_tik.other_sec.unwrap(), alice.p_tik.sec, "Bob should have Alice secret key for p_tik");
        // TODO now make a arbitrary transaction with the key into own wallet.

        Ok(())
    }

    // TODO write a test where Bob does not sign DepositTx but Alice has it already. Bob needs to
    //  remove the funds from the INPUT OF DepositTx.

    #[test]
    fn test_warning() -> anyhow::Result<()> {
        // create all transaction and Broadcast DepositTx already
        let (alice, _bob) = initial_tx_creation()?;
        dbg!(&alice.warning_tx_me.tx);
        // alice broadcasts WarningTx
        dbg!(alice.warning_tx_me.broadcast(&alice.ctx));
        nigiri::tiktok();
        Ok(())
    }

    #[test]
    fn test_claim() -> anyhow::Result<()> {
        // create all transaction and Broadcast DepositTx already
        let (alice, _bob) = initial_tx_creation()?;
        // dbg!(&alice.warning_tx_me.tx);
        // alice broadcasts WarningTx
        alice.warning_tx_me.broadcast(&alice.ctx);
        nigiri::tiktok();
        nigiri::tiktok(); // we have set time-delay t2 to 2 Blocks
        dbg!(&alice.claim_tx_me.tx);

        // according to BIP-68 min time to wait is 512sec
        // let mut remaining_time = 532;
        // while remaining_time > 0 {
        //     println!("Remaining time: {} seconds", remaining_time);
        //     thread::sleep(Duration::from_secs(10));
        //     remaining_time -= 10;
        // }
        // thread::sleep(Duration::from_secs(512)); //otherwise non-BIP68-final error

        let tx = alice.claim_tx_me.broadcast(&alice.ctx)?;

        println!("http://localhost:5000/tx/{tx}");
        nigiri::tiktok();
        Ok(())
    }

    #[test]
    fn test_claim_too_early() -> anyhow::Result<()> {
        // create all transaction and Broadcast DepositTx already
        let (alice, _bob) = initial_tx_creation()?;
        alice.warning_tx_me.broadcast(&alice.ctx);
        // nigiri::tiktok();
        nigiri::tiktok(); // we have set time-delay t2 to 2 Blocks

        let rtx = alice.claim_tx_me.broadcast(&alice.ctx);
        match rtx {
            Ok(_) => panic!("ClaimTx should not go through, because its been broadcast too early.
            HINT: Do not run this test in parallel with other tests, use --test-threads=1"),
            Err(e) => {
                let error_message = format!("{e:?}");
                // println!("{}", error_message);
                assert!(error_message.contains("non-BIP68-final"),
                    "Wrong error message: {error_message}");
            }
        }
        nigiri::tiktok();
        Ok(())
    }

    #[test]
    fn test_redirect() -> anyhow::Result<()> {
        // create all transaction and Broadcast DepositTx already
        let (alice, bob) = initial_tx_creation()?;
        // dbg!(&alice.warning_tx_me.tx);
        // alice broadcasts WarningTx
        let bob_warn_id = bob.warning_tx_me.broadcast(&bob.ctx);
        nigiri::tiktok();
        dbg!(bob_warn_id);

        let tx = alice.redirect_tx_me.broadcast(&alice.ctx);
        dbg!(tx);
        nigiri::tiktok();
        Ok(())
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_q_tik() -> anyhow::Result<()> {
        // create all transaction and Broadcast DepositTx already
        let (alice, bob) = initial_tx_creation()?;
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
        let seckeys: Vec<Scalar>
            = if alice.q_tik.pub_point < bob.q_tik.pub_point {
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
        let sig1 = secp.sign_schnorr(&msg, &keypair); // will end up in Bad Signature
        // let sig1 = secp.sign_schnorr(&msg, &tweaked.to_inner());
        // Update the witness stack.
        let signature_secp = bitcoin::taproot::Signature { signature: sig1, sighash_type };
        let path1pubpoint = Point::from_slice(&keypair.public_key().serialize())?;
        let path1tweakpoint = Point::from_slice(&tweaked.to_keypair().public_key().serialize())?;

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
        dbg!(&newctx, &ac, &pks);
        let newaggkey: Point = newctx.aggregated_pubkey();
        let newctx2 = newctx.with_unspendable_taproot_tweak()?;
        let newtweaked: Point = newctx2.aggregated_pubkey();

        assert_eq!(newaggkey, newctx2.aggregated_pubkey_untweaked(), "newaggkey not equal");

        // verify ------------------------------------------
        dbg!(&path1pubpoint, &path1tweakpoint, &d, &aggkey, &old_d, &newtweaked, &newaggkey);

        assert_eq!(d.serialize(), tweaked.to_keypair().public_key().serialize(), "pubkey not equal");
        // assert_eq!(dser, my_agg_point.serialize(), "my pubkey not equal");

        // use signature and broadcast ------------------------------------------
        *sighasher.witness_mut(input_index).unwrap() = Witness::p2tr_key_spend(&signature_secp);

        // Get the signed transaction.
        let tx = sighasher.into_transaction();

        let txid = alice.ctx.funds.client.transaction_broadcast(&tx)?;
        dbg!(txid);
        nigiri::tiktok();
        Ok(())
    }
}
