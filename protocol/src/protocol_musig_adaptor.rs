use crate::wallet_service::WalletService;
use bdk_electrum::{BdkElectrumClient, electrum_client};
use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hashes::sha256t::Hash;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_wallet::bitcoin::taproot::Signature;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, KnownHrp, Network, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence,
    TapSighashTag, TapSighashType, Transaction, TxIn, TxOut, Txid, Weight, Witness, absolute,
    transaction,
};
use bdk_wallet::coin_selection::BranchAndBoundCoinSelection;
use bdk_wallet::miniscript::ToPublicKey;
use bdk_wallet::template::{Bip86, DescriptorTemplate};
use bdk_wallet::{AddressInfo, KeychainKind, SignOptions, TxBuilder, Wallet, bitcoin};
use musig2::secp::MaybePoint::Valid;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AdaptorSignature, AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce,
    SecNonce, SecNonceBuilder,
};
use rand::{Rng, RngCore};
use std::io::Write;
use std::ops::{Add, Sub};
use std::str::FromStr;

pub struct MemWallet {
    pub wallet: Wallet,
    pub client: BdkElectrumClient<electrum_client::Client>,
}

impl MemWallet {
    pub(crate) fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        let result = self.client.transaction_broadcast(tx);

        if let Err(e) = result {
            if e.to_string().contains("Transaction already in block chain") {
                return Ok(tx.compute_txid());
            }
            return Err(e.into());
        }

        Ok(result?)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ProtocolRole {
    Seller,
    Buyer,
}

impl ProtocolRole {
    fn other(&self) -> ProtocolRole {
        match self {
            ProtocolRole::Seller => ProtocolRole::Buyer,
            ProtocolRole::Buyer => ProtocolRole::Seller,
        }
    }
}
// TODO think about stop_gap and batch_size
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;
const ELECTRUM_URL: &str =
    // "ssl://electrum.blockstream.info:60002";
    "localhost:50000"; //TODO move to env
impl MemWallet {
    pub fn new() -> anyhow::Result<MemWallet> {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let network: Network = Network::Regtest;
        let xprv: Xpriv = Xpriv::new_master(network, &seed)?;
        println!(
            "Generated Master Private Key:\n{}\nWarning: be very careful with private keys when using MainNet! We are logging these values for convenience only because this is an example on RegTest.\n",
            xprv
        );

        let (descriptor, external_map, _) = Bip86(xprv, KeychainKind::External)
            .build(network)
            .expect("Failed to build external descriptor");

        let (change_descriptor, internal_map, _) = Bip86(xprv, KeychainKind::Internal)
            .build(network)
            .expect("Failed to build internal descriptor");

        let wallet = Wallet::create(descriptor, change_descriptor)
            .network(network)
            .keymap(KeychainKind::External, external_map)
            .keymap(KeychainKind::Internal, internal_map)
            .create_wallet_no_persist()?;
        let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL)?);

        Ok(MemWallet { wallet, client })
    }

    pub(crate) fn sync(&mut self) -> anyhow::Result<()> {
        // Populate the electrum client's transaction cache so it doesn't redownload transaction we
        // already have.
        self.client
            .populate_tx_cache(self.wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

        let request = self.wallet.start_full_scan().inspect({
            let mut stdout = std::io::stdout();
            // let mut once = HashSet::<KeychainKind>::new();
            move |_k, _spk_i, _| {
                // if once.insert(k) {
                //     print!("\nScanning keychain [{:?}]", k);
                // }
                // print!(" {:<3}", spk_i);
                stdout.flush().expect("must flush");
            }
        });
        eprintln!("requesting update...");
        let update = self
            .client
            .full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
        self.wallet.apply_update(update)?;
        Ok(())
    }

    pub(crate) fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    pub(crate) fn next_unused_address(&mut self) -> AddressInfo {
        self.wallet.next_unused_address(KeychainKind::External)
    }

    fn _transfer_to_address(
        &mut self,
        address: AddressInfo,
        amount: Amount,
    ) -> anyhow::Result<Txid> {
        let mut tx_builder = self.wallet.build_tx();
        tx_builder.add_recipient(address.script_pubkey(), amount);

        let mut psbt = tx_builder.finish()?;
        let finalized = self.wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized);

        let tx = psbt.extract_tx()?;
        self.client.transaction_broadcast(&tx)?;
        Ok(tx.compute_txid())
    }
}
#[derive(Debug)]
pub struct Round1Parameter {
    // DepositTx --------
    pub p_a: Point,
    pub q_a: Point,
    pub dep_part_psbt: Psbt,
    // Swap Tx -----
    // public nounce
    // Seller address where to send the swap amount to
    pub swap_script: Option<ScriptBuf>, // only set from Seller
    pub warn_anchor_spend: ScriptBuf,
    pub claim_spend: ScriptBuf,
    pub redirect_anchor_spend: ScriptBuf,
}

pub struct Round2Parameter {
    // DepositTx --------
    pub p_agg: Point,
    pub q_agg: Point,
    pub deposit_tx_signed: Psbt,
    // SwapTx --------------
    // partial adaptive  signature for SwapTx
    pub swap_pub_nonce: PubNonce,
    pub warn_alice_p_nonce: PubNonce,
    pub warn_alice_q_nonce: PubNonce,
    pub warn_bob_q_nonce: PubNonce,
    pub warn_bob_p_nonce: PubNonce,
    pub claim_alice_nonce: PubNonce,
    pub claim_bob_nonce: PubNonce,
    pub redirect_alice_nonce: PubNonce,
    pub redirect_bob_nonce: PubNonce,
}

#[derive(Debug)]
pub struct Round3Parameter {
    // DepositTx --------
    pub deposit_txid: Txid, // only for verification / fast fail
    // SwapTx --------------
    // aggregated adaptive signature for SwapTx,
    pub swap_part_sig: PartialSignature,
    pub p_part_peer: PartialSignature,
    pub q_part_peer: PartialSignature,
    pub claim_part_sig: PartialSignature,
    pub redirect_part_sig: PartialSignature,
}
#[derive(Debug)]
pub struct Round4Parameter {
    deposit_tx_signed: Psbt,
}
/**
this context is for the whole process and need to be persisted by the caller
*/
pub struct BMPContext {
    // first of all, everything which is general to the protcol itself
    pub funds: MemWallet,
    pub role: ProtocolRole,
    pub seller_amount: Amount,
    pub buyer_amount: Amount,
}
pub struct BMPProtocol {
    pub(crate) ctx: BMPContext,
    pub(crate) p_tik: AggKey, // Point securing Seller deposit and trade amount
    pub(crate) q_tik: AggKey, // Point securing Buyer deposit
    pub(crate) deposit_tx: DepositTx,
    round: u8, // which round are we in.
    pub(crate) swap_tx: SwapTx,
    pub(crate) warning_tx_me: WarningTx,
    pub(crate) warning_tx_peer: WarningTx,
    pub(crate) claim_tx_me: ClaimTx,
    pub claim_tx_peer: ClaimTx,
    pub redirect_tx_me: RedirectTx,
    pub redirect_tx_peer: RedirectTx,
}

impl BMPContext {
    pub fn new(
        wallet_service: WalletService,
        role: ProtocolRole,
        seller_amount: Amount,
        buyer_amount: Amount,
    ) -> anyhow::Result<BMPContext> {
        Ok(BMPContext {
            funds: wallet_service.retrieve_wallet(),
            role,
            seller_amount,
            buyer_amount,
        })
    }
}
impl BMPProtocol {
    pub fn new(ctx: BMPContext) -> anyhow::Result<BMPProtocol> {
        let role = ctx.role;
        Ok(BMPProtocol {
            ctx,
            p_tik: AggKey::new()?,
            q_tik: AggKey::new()?,
            deposit_tx: DepositTx::new(),
            round: 0,
            swap_tx: SwapTx::new(role),
            warning_tx_me: WarningTx::new(role),
            warning_tx_peer: WarningTx::new(role.other()),
            claim_tx_me: ClaimTx::new(),
            claim_tx_peer: ClaimTx::new(),
            redirect_tx_me: RedirectTx::new(),
            redirect_tx_peer: RedirectTx::new(),
        })
    }

    pub fn round1(&mut self) -> anyhow::Result<Round1Parameter> {
        self.check_round(1);

        let dep_part_psbt = self.deposit_tx.generate_part_tx(
            &mut self.ctx,
            &self.p_tik.pub_point,
            &self.q_tik.pub_point,
        )?;
        let swap_script = self.swap_tx.spend_condition(&mut self.ctx);
        let warn_anchor_spend = self
            .ctx
            .funds
            .wallet
            .next_unused_address(KeychainKind::External)
            .script_pubkey();
        self.warning_tx_me.anchor_spend = Some(warn_anchor_spend.clone());

        // ClaimTx
        let claim_spend = self
            .ctx
            .funds
            .wallet
            .next_unused_address(KeychainKind::External)
            .script_pubkey();
        self.claim_tx_me.claim_spend = Some(claim_spend.clone());

        // RedirectTx
        let redirect_anchor_spend = self
            .ctx
            .funds
            .wallet
            .next_unused_address(KeychainKind::External)
            .script_pubkey();
        self.redirect_tx_me.anchor_spend = Some(redirect_anchor_spend.clone());

        Ok(Round1Parameter {
            p_a: self.p_tik.pub_point,
            q_a: self.q_tik.pub_point,
            dep_part_psbt,
            swap_script,
            warn_anchor_spend,
            claim_spend,
            redirect_anchor_spend,
        })
    }

    pub fn round2(&mut self, bob: Round1Parameter) -> anyhow::Result<Round2Parameter> {
        self.check_round(2);
        assert_ne!(
            bob.p_a, bob.q_a,
            "Bob is sending the same point for P' and Q'."
        );
        println!(
            "The {:?} sellers secret for P_Tik is {:?}.",
            self.ctx.role, self.p_tik.sec
        );

        // key Aggregation -----\n        self.p_tik.other_point = Some(bob.p_a);
        self.q_tik.other_point = Some(bob.q_a);
        self.p_tik.aggregate_key(bob.p_a)?;
        self.q_tik.aggregate_key(bob.q_a)?;
        // now we have the aggregated key
        // so we can contruct the Deposit Tx
        let deposit_tx_signed = self.deposit_tx.build_and_merge_tx(
            &mut self.ctx,
            &bob.dep_part_psbt,
            &self.p_tik,
            &self.q_tik,
        )?;
        self.warning_tx_me
            .build(&mut self.ctx, &self.p_tik, &self.q_tik, &self.deposit_tx)?;
        self.warning_tx_peer.anchor_spend = Some(bob.warn_anchor_spend);
        self.warning_tx_peer
            .build(&mut self.ctx, &self.p_tik, &self.q_tik, &self.deposit_tx)?;
        let warn_alice_p_nonce = self.warning_tx_me.sig_p.as_ref().unwrap().pub_nonce.clone();
        let warn_alice_q_nonce = self.warning_tx_me.sig_q.as_ref().unwrap().pub_nonce.clone();
        let warn_bob_p_nonce = self
            .warning_tx_peer
            .sig_p
            .as_ref()
            .unwrap()
            .pub_nonce
            .clone();
        let warn_bob_q_nonce = self
            .warning_tx_peer
            .sig_q
            .as_ref()
            .unwrap()
            .pub_nonce
            .clone();

        // given the depositTx, we can create SwapTx for Alice.
        self.swap_tx.build(
            self.q_tik.clone(),
            &deposit_tx_signed.unsigned_tx,
            bob.swap_script,
        )?;
        // let start the signing process for swaptx already.
        let swap_pub_nonce = self.swap_tx.get_pub_nonce(); // could be one round earlier, if we solve secure nonce generation

        //ClaimTx
        let (tik, other_tik) = match self.ctx.role {
            ProtocolRole::Seller => (&self.q_tik, &self.p_tik),
            ProtocolRole::Buyer => (&self.p_tik, &self.q_tik),
        };
        self.claim_tx_me
            .build(&mut self.ctx, tik, &self.warning_tx_me)?;
        let claim_alice_nonce = self.claim_tx_me.sig.as_ref().unwrap().pub_nonce.clone();
        self.claim_tx_peer.claim_spend = Some(bob.claim_spend);
        self.claim_tx_peer
            .build(&mut self.ctx, other_tik, &self.warning_tx_peer)?;
        let claim_bob_nonce = self.claim_tx_peer.sig.as_ref().unwrap().pub_nonce.clone();

        // RedirectTX
        self.redirect_tx_me
            .build(&mut self.ctx, other_tik, &self.warning_tx_peer)?; // redirect TX is overcross alice reference Bob warningTx
        let redirect_alice_nonce = self.redirect_tx_me.sig.as_ref().unwrap().pub_nonce.clone();
        self.redirect_tx_peer.anchor_spend = Some(bob.redirect_anchor_spend);
        self.redirect_tx_peer
            .build(&mut self.ctx, tik, &self.warning_tx_me)?;
        let redirect_bob_nonce = self
            .redirect_tx_peer
            .sig
            .as_ref()
            .unwrap()
            .pub_nonce
            .clone();

        Ok(Round2Parameter {
            p_agg: self.p_tik.agg_point.unwrap(),
            q_agg: self.q_tik.agg_point.unwrap(),
            deposit_tx_signed,
            swap_pub_nonce,
            warn_alice_p_nonce,
            warn_alice_q_nonce,
            warn_bob_p_nonce,
            warn_bob_q_nonce,
            claim_alice_nonce,
            claim_bob_nonce,
            redirect_alice_nonce,
            redirect_bob_nonce,
        })
    }
    pub fn round3(&mut self, bob: Round2Parameter) -> anyhow::Result<Round3Parameter> {
        self.check_round(3);
        // actually this next test is not necessary, but double-checking and fast fail is always good
        // TODO since we are sending this only to validate, we could use a hash of it as well, optimization
        assert_eq!(
            bob.p_agg,
            self.p_tik.agg_point.unwrap(),
            "Bob is sending the wrong P' for his aggregated key."
        );
        assert_eq!(
            bob.q_agg,
            self.q_tik.agg_point.unwrap(),
            "Bob is sending the wrong Q' for his aggregated key."
        );

        let txid = self.deposit_tx.tx.as_ref().unwrap().compute_txid();
        let adaptor_point = match self.ctx.role {
            // the seller's key for payout of seller deposit and trade amount is in question
            ProtocolRole::Seller => self.p_tik.pub_point,
            ProtocolRole::Buyer => self.p_tik.other_point.unwrap(),
        };
        // here we are building the partial signature of the SwapTx, note that there is only one SwapTx (for Alice)
        let swap_part_sig = self.swap_tx.build_partial_sig(
            &self.ctx,
            bob.swap_pub_nonce,
            adaptor_point,
            &self.deposit_tx,
        )?;

        let (_p_part_me, _q_part_me) = self.warning_tx_me.build_partial_sig(
            &self.ctx,
            &bob.warn_bob_p_nonce,
            &bob.warn_bob_q_nonce,
            &self.deposit_tx,
        )?;

        let (p_part_peer, q_part_peer) = self.warning_tx_peer.build_partial_sig(
            &self.ctx,
            &bob.warn_alice_p_nonce,
            &bob.warn_alice_q_nonce,
            &self.deposit_tx,
        )?;
        //ClaimTx
        self.claim_tx_me
            .build_partial_sig(&self.ctx, &bob.claim_bob_nonce, &self.warning_tx_me)?; // no need to send my partial sig to peer
        let claim_part_sig = self.claim_tx_peer.build_partial_sig(
            &self.ctx,
            &bob.claim_alice_nonce,
            &self.warning_tx_peer,
        )?; // sign bobs transaction that I constructed

        //RedirectTx
        self.redirect_tx_me.build_partial_sig(
            &self.ctx,
            &bob.redirect_bob_nonce,
            &self.warning_tx_peer,
        )?;
        let redirect_part_sig = self.redirect_tx_peer.build_partial_sig(
            &self.ctx,
            &bob.redirect_alice_nonce,
            &self.warning_tx_me,
        )?; // sign bobs transaction that I constructed

        Ok(Round3Parameter {
            deposit_txid: txid, // only for verification that we actually are on the same page
            swap_part_sig,      // partial signature for SwapTx Alice (or None if we are Alice)
            p_part_peer,        // partial signature for WarningTx Bob, input of p_tik
            q_part_peer,
            claim_part_sig,
            redirect_part_sig,
        })
    }
    pub fn round4(&mut self, bob: Round3Parameter) -> anyhow::Result<Round4Parameter> {
        self.check_round(4);
        dbg!(&bob);
        self.swap_tx.aggregate_sigs(bob.swap_part_sig)?;
        self.warning_tx_me
            .aggregate_sigs(bob.p_part_peer, bob.q_part_peer)?;
        self.claim_tx_me.aggregate_sigs(bob.claim_part_sig)?;
        self.redirect_tx_me.aggregate_sigs(bob.redirect_part_sig)?;
        // TODO  final check
        self.deposit_tx.sign(&mut self.ctx)?;
        Ok(Round4Parameter {
            deposit_tx_signed: self.deposit_tx.merged_psbt.clone().unwrap(),
        })
    }
    pub(crate) fn round5(&mut self, bob: Round4Parameter) -> anyhow::Result<()> {
        self.check_round(5);
        self.deposit_tx
            .transfer_sig_and_broadcast(&mut self.ctx, bob.deposit_tx_signed)?;
        Ok(())
    }

    fn check_round(&mut self, round: u8) {
        if self.round != round - 1 {
            panic!("round already done");
        }
        self.round = round;
    }

    // ------- Debug --------
    pub(crate) fn get_p_tik_agg(&self) -> Address {
        let r = &(*self).p_tik;
        r.get_agg_adr().unwrap()
    }
}
/**
RedirectTx -- this redirects the funds from the WarningTx to the DAO.
This is expected if the traders have some sor of conflict, which they cannot resolve themselves.
One trader sends the WarningTx, the other trader answers by sending the RedirectTx.
If a redirectTx is not send within t_2, then the trader which sent the WarningTx can
send the ClaimTx and gets the hole funds for himself.
Since RedirectTx sends the funds to the DAO, it needs an anchors for the trader, so he
can raise the fees with CPFP to get it mined before ClaimTx can be broadcast.

RedirectTx Bob spends from WarningTx Alice, that's important.
Sending fnds to the DAO is done by having a list of addresses (from contributors) and percentages. (must add up to 100%)
*/
pub struct RedirectTx {
    pub sig: Option<TMuSig2>,
    pub tx: Option<Transaction>,
    pub anchor_spend: Option<ScriptBuf>,
}

impl RedirectTx {
    pub fn new() -> RedirectTx {
        RedirectTx {
            sig: None,
            tx: None,
            anchor_spend: None,
        }
    }
    fn build(
        &mut self,
        _ctx: &mut BMPContext,
        tik: &AggKey,
        warn_tx: &WarningTx,
    ) -> anyhow::Result<Transaction> {
        self.sig = Some(TMuSig2::new(tik.clone()));

        let warn_funds = &warn_tx.funds_as_output();
        let amount = warn_funds.value.sub(Amount::from_sat(1000)); //TODO calc fee rate.sub(); subtract ANCHOR_AMOUNT

        let dao_bm = Self::get_dao_bm();
        let mut outputs: Vec<TxOut> = dao_bm
            .iter()
            .map(|(address, ratio)| TxOut {
                value: Amount::from_sat((amount.to_sat() as f32 * *ratio) as u64), // Calculate proportional value
                script_pubkey: address.script_pubkey(), // Convert DAO address to script_pubkey
            })
            .collect();

        let anchor_output = TxOut {
            value: ANCHOR_AMOUNT,
            script_pubkey: self.anchor_spend.clone().unwrap(),
        };
        outputs.push(anchor_output);
        let t1 = Sequence::from_height(1); // TODO define as const and find a good value
        // let t1 = Sequence::from_seconds_ceil(1)?; // TODO define as const and find a good value
        let input0 = TxIn {
            previous_output: warn_tx.funds_as_outpoint(),
            script_sig: ScriptBuf::default(),
            sequence: t1,
            witness: Witness::default(), // will be changed when signing.
        };
        let tx = Transaction {
            version: Version::TWO,
            input: vec![input0],
            output: outputs,
            lock_time: LockTime::ZERO,
        };
        self.tx = Some(tx.clone());

        Ok(tx)
    }
    fn build_partial_sig(
        &mut self,
        _ctx: &BMPContext,
        peer_nonce: &PubNonce,
        warning_tx: &WarningTx,
    ) -> anyhow::Result<PartialSignature> {
        let tx = self.tx.as_ref().unwrap();
        let prevouts_warn_tx = warning_tx.get_tx().calc_prevouts(&tx.input)?;
        // let p_index = tx.output_index(p_)
        let musig = self.sig.as_mut().unwrap();
        let index = 0; //TODO calculate this, if input0 from warningtx
        let part_sig = musig.generate_partial_sig(index, peer_nonce, &prevouts_warn_tx, tx)?;
        Ok(part_sig)
    }

    pub fn aggregate_sigs(&mut self, part_sig: PartialSignature) -> anyhow::Result<()> {
        let sig = self.sig.as_mut().unwrap();
        sig.aggregate_sigs(part_sig)?;

        // now stuff those signatures into the transaction
        let mut tx = self.tx.clone().unwrap();
        // dbg!("before signing tx: {:?}");
        tx = sig.sign(MaybeScalar::Zero, tx)?;
        self.tx = Some(tx);
        // dbg!("signed tx {:?}");
        Ok(())
    }
    pub(crate) fn broadcast(&self, me: BMPContext) -> Txid {
        me.funds
            .client
            .transaction_broadcast(self.tx.as_ref().unwrap())
            .unwrap()
    }

    /**
    sum of all f32 must be 1
    */
    fn get_dao_bm() -> Vec<(Address, f32)> {
        // TODO this needs a real implementation, and check that sum of ratios is 1
        vec![
            (
                Address::from_str(
                    "bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk",
                )
                .unwrap()
                .assume_checked(),
                0.6,
            ),
            (
                Address::from_str(
                    "bcrt1phhl8d90r9haqwtvw2cv4ryjl8tlnqrv48nhpy7yyks5du6mr66xq5nlwhz",
                )
                .unwrap()
                .assume_checked(),
                0.4,
            ),
        ]
    }
}
/**
ClaimTx -- One version for Alice and one for Bob.
If the other side will not react on the WarningTx (by sending the RedirectTx)
then Alice can claim the total amounts for herself.
*/
pub struct ClaimTx {
    pub sig: Option<TMuSig2>,
    pub tx: Option<Transaction>,
    pub claim_spend: Option<ScriptBuf>,
}
impl ClaimTx {
    pub fn new() -> ClaimTx {
        ClaimTx {
            sig: None,
            tx: None,
            claim_spend: None,
        }
    }
    fn build(
        &mut self,
        _ctx: &mut BMPContext,
        tik: &AggKey,
        warn_tx: &WarningTx,
    ) -> anyhow::Result<Transaction> {
        self.sig = Some(TMuSig2::new(tik.clone()));

        let warn_funds = &warn_tx.funds_as_output();
        let amount = warn_funds.value.sub(Amount::from_sat(1000)); //TODO calc fee rate.sub();
        // let amount = w[0].value.sub(Amount::from_sat(1000)); //TODO calc fee rate.sub();

        let output0 = TxOut {
            value: amount,
            script_pubkey: self.claim_spend.clone().unwrap(),
        };
        let t2 = Sequence::from_height(2); // TODO define as const and find a good value
        // let t2 = Sequence::from_seconds_ceil(1)?;
        let input0 = TxIn {
            previous_output: warn_tx.funds_as_outpoint(),
            script_sig: ScriptBuf::default(),
            sequence: t2,
            witness: Witness::default(), // will be changed when signing.
        };
        let tx = Transaction {
            version: Version::TWO,
            input: vec![input0],
            output: vec![output0],
            lock_time: LockTime::ZERO,
        };
        self.tx = Some(tx.clone());

        Ok(tx)
    }
    fn build_partial_sig(
        &mut self,
        _ctx: &BMPContext,
        peer_nonce: &PubNonce,
        warning_tx: &WarningTx,
    ) -> anyhow::Result<PartialSignature> {
        let warn_tx = warning_tx.tx.as_ref().unwrap();
        let tx = self.tx.as_ref().unwrap();
        let prevouts_warn_tx = warn_tx.calc_prevouts(&tx.input)?;
        // let p_index = tx.output_index(p_)
        let musig = self.sig.as_mut().unwrap();
        let index = 0; //TODO calculate this, if input0 from warningtx
        let part_sig = musig.generate_partial_sig(index, peer_nonce, &prevouts_warn_tx, tx)?;
        Ok(part_sig)
    }

    pub fn aggregate_sigs(&mut self, part_sig: PartialSignature) -> anyhow::Result<()> {
        let sig = self.sig.as_mut().unwrap();
        sig.aggregate_sigs(part_sig)?;

        // now stuff those signatures into the transaction
        let mut tx = self.tx.clone().unwrap();
        // dbg!("before signing tx: {:?}");
        tx = sig.sign(MaybeScalar::Zero, tx)?;
        self.tx = Some(tx);
        // dbg!("signed tx {:?}");
        Ok(())
    }

    pub(crate) fn broadcast(&self, me: BMPContext) -> anyhow::Result<Txid> {
        Ok(me
            .funds
            .client
            .transaction_broadcast(self.tx.as_ref().unwrap())?)
    }
}

/**
* WarningTx -- there is one version for Alice and one for Bob.
That means each party generates both transaction and sign them.
*/
pub struct WarningTx {
    role: ProtocolRole, // is that my WarningTx? (mainly for safety checking)
    pub anchor_spend: Option<ScriptBuf>, // where to send the anchor sats to?
    pub sig_p: Option<TMuSig2>,
    pub sig_q: Option<TMuSig2>,
    pub key_spend: Option<AggKey>,
    pub tx: Option<Transaction>,
}

const ANCHOR_AMOUNT: Amount = Amount::from_sat(330); // 330 is std amount for anchors

impl WarningTx {
    pub fn get_tx(&self) -> &Transaction {
        self.tx.as_ref().unwrap()
    }
    pub fn funds_as_outpoint(&self) -> OutPoint {
        OutPoint::new(self.tx.as_ref().unwrap().compute_txid(), 0)
    }
    pub fn funds_as_output(&self) -> TxOut {
        let w = self.tx.as_ref().unwrap();
        let wout: &Vec<TxOut> = w.output.as_ref();
        wout[0].clone()
    }
    pub fn new(role: ProtocolRole) -> WarningTx {
        WarningTx {
            role,
            anchor_spend: None, // ctx.funds.wallet.next_unused_address(KeychainKind::External).script_pubkey(),
            sig_p: None,
            sig_q: None,
            key_spend: None,
            tx: None,
        }
    }

    fn build(
        &mut self,
        ctx: &mut BMPContext,
        p_tik: &AggKey,
        q_tik: &AggKey,
        deposit_tx: &DepositTx,
    ) -> anyhow::Result<Transaction> {
        self.sig_p = Some(TMuSig2::new(p_tik.clone()));
        self.sig_q = Some(TMuSig2::new(q_tik.clone()));

        //--------------------
        let key_spend = match self.role {
            ProtocolRole::Seller => q_tik,
            ProtocolRole::Buyer => p_tik,
        };
        self.key_spend = Some(key_spend.clone());

        let all_amount = ctx
            .buyer_amount
            .add(ctx.seller_amount)
            .sub(ANCHOR_AMOUNT)
            .sub(Amount::from_sat(1000)); //TODO calc fee rate.sub();
        let output0 = TxOut {
            value: all_amount,
            script_pubkey: key_spend.get_agg_script_pubkey()?,
        };
        let output1 = TxOut {
            value: ANCHOR_AMOUNT,
            script_pubkey: self.anchor_spend.clone().unwrap(),
        };
        let deposit_tx = deposit_tx.tx.as_ref().unwrap();
        let tx = Transaction {
            output: vec![output0.clone(), output1],
            input: vec![
                deposit_tx.get_txin_for(p_tik)?,
                deposit_tx.get_txin_for(q_tik)?,
            ],
            lock_time: absolute::LockTime::ZERO,
            version: transaction::Version::TWO,
        };
        self.tx = Some(tx.clone());
        dbg!(ctx.role, self.role, tx.clone().compute_txid()); //output0.script_pubkey); //
        Ok(tx)
    }
    fn build_partial_sig(
        &mut self,
        _ctx: &BMPContext,
        peer_nonce_p: &PubNonce,
        peer_nonce_q: &PubNonce,
        deposit_tx: &DepositTx,
    ) -> anyhow::Result<(PartialSignature, PartialSignature)> {
        let dep_tx = deposit_tx.tx.as_ref().unwrap();
        let tx = self.tx.as_ref().unwrap();
        let prevouts_deposittx = dep_tx.calc_prevouts(&tx.input)?;
        // let p_index = tx.output_index(p_)
        let p_musig = self.sig_p.as_mut().unwrap();
        let p_index = 0; //TODO calculate this
        dbg!("p", &p_index);
        let p_part =
            p_musig.generate_partial_sig(p_index, peer_nonce_p, &prevouts_deposittx, tx)?;
        let q_musig = self.sig_q.as_mut().unwrap();
        let q_index = 1; // TODO calculate this index
        dbg!("q", &q_index);
        let q_part =
            q_musig.generate_partial_sig(q_index, peer_nonce_q, &prevouts_deposittx, tx)?;

        Ok((p_part, q_part))
    }

    pub fn aggregate_sigs(
        &mut self,
        p_part_sig: PartialSignature,
        q_part_sig: PartialSignature,
    ) -> anyhow::Result<()> {
        dbg!("agg p");
        let sig_p = self.sig_p.as_mut().unwrap();
        sig_p.aggregate_sigs(p_part_sig)?;
        dbg!("agg q");
        let sig_q = self.sig_q.as_mut().unwrap();
        sig_q.aggregate_sigs(q_part_sig)?;
        // now stuff those signatures into the transaction
        let mut tx = self.tx.clone().unwrap();
        // dbg!("before signing tx: {:?}");
        tx = sig_p.sign(MaybeScalar::Zero, tx)?;
        tx = sig_q.sign(MaybeScalar::Zero, tx)?;
        self.tx = Some(tx);
        // dbg!("signed tx {:?}");
        Ok(())
    }

    pub(crate) fn broadcast(&self, me: &BMPContext) -> Txid {
        me.funds
            .client
            .transaction_broadcast(self.tx.as_ref().unwrap())
            .unwrap()
    }
}
/**
Only the seller gets a SwapTx, this is the only asymmetric part of the p3
*/
pub struct SwapTx {
    pub role: ProtocolRole, // this transaction is only for Alice, however even Bob will construct it for signing.
    pub swap_spend: Option<ScriptBuf>,
    // SwapTx get funded by a adaptor MuSig2 signature
    pub fund_sig: Option<TMuSig2>,
    pub tx: Option<Transaction>,
}

impl SwapTx {
    pub(crate) fn spend_condition(&mut self, ctx: &mut BMPContext) -> Option<ScriptBuf> {
        self.swap_spend = match self.role {
            ProtocolRole::Seller => Some(
                ctx.funds
                    .wallet
                    .next_unused_address(KeychainKind::External)
                    .script_pubkey(),
            ),
            ProtocolRole::Buyer => None,
        };
        self.swap_spend.clone()
    }
    /**
    even though only the seller gets a SwapTx transaction, both parties are constructing the transaction
    and only the buyer will send the seller the signature.
    */
    fn new(role: ProtocolRole) -> SwapTx {
        SwapTx {
            role,
            swap_spend: None,
            fund_sig: None,
            tx: None,
        }
    }

    pub fn get_pub_nonce(&self) -> PubNonce {
        self.fund_sig.as_ref().unwrap().pub_nonce.clone()
    }

    // round 1
    pub fn build(
        &mut self,
        q_tik: AggKey,
        deposit_tx: &Transaction,
        swap_spend_opt: Option<ScriptBuf>,
    ) -> anyhow::Result<Transaction> {
        let dep_index = deposit_tx.output_index(&q_tik);
        self.fund_sig = Some(TMuSig2::new(q_tik));
        let Some(use_spend) = (match self.role {
            ProtocolRole::Seller => self.swap_spend.clone(),
            ProtocolRole::Buyer => swap_spend_opt,
        }) else {
            panic!("No spend-consdition from role {:?}", self.role)
        };

        let buyer_deposit_out = OutPoint::new(deposit_tx.compute_txid(), dep_index);
        let buyer_deposit_amount = deposit_tx.output.get(dep_index as usize).unwrap().value;

        let input = TxIn {
            previous_output: buyer_deposit_out,
            script_sig: ScriptBuf::default(), // empty for p2tr
            sequence: Sequence::MAX,
            witness: Witness::default(), // will change after signing
        };
        // TODO do real calculation of fees
        let payout_amount = buyer_deposit_amount.sub(Amount::from_sat(1000)); // TODO fee calculation?
        // anchor output not neccessary, because Seller can spend the output for CPFP
        let output = TxOut {
            value: payout_amount,
            script_pubkey: use_spend,
        };
        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,  // Post BIP-68.
            lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
            input: vec![input],                  // Input goes into index 0.
            output: vec![output],                // Outputs, order does not matter.
        };
        self.tx = Some(unsigned_tx.clone());
        Ok(unsigned_tx)
    }

    pub fn build_partial_sig(
        &mut self,
        _ctx: &BMPContext,
        other_nonce: PubNonce,
        pubp_a: Point,
        deposit_tx: &DepositTx,
    ) -> anyhow::Result<PartialSignature> {
        let input_index: usize = 0; // SwapTx has only one input
        // SwapTx is asymetric, both parties need to agree on P_a being the public adaptor
        // P_a is the Public key which Alice (the seller) contributes to 2of2 Multisig to lock the deposit and trade amount in the DepositTx
        // if secrect key of P_a is revealed to Bob, then we has both partial keys to it and is able to spend it.
        let pub_adaptor = pubp_a;
        let swap_tx = self.tx.as_ref().unwrap();
        let prevouts_deposittx = &self.calc_prevouts(deposit_tx)?;
        let fund_sig = self.fund_sig.as_mut().unwrap();
        Ok(fund_sig.generate_adapted_partial_sig(
            input_index,
            Valid(pub_adaptor),
            &other_nonce,
            prevouts_deposittx,
            swap_tx,
        )?)
    }

    /**
    For Taproot signing, we need for all inputs of this transactions to look into the outpoint of TxIn and find the referenced transaction output (TxOut).
    this must be supplied for signing.
     */
    pub fn calc_prevouts(&self, deposit_tx: &DepositTx) -> anyhow::Result<Vec<TxOut>> {
        let swap_tx = self.tx.as_ref().unwrap();
        let dep_tx = deposit_tx.tx.as_ref().unwrap();
        let prevouts = dep_tx.calc_prevouts(&swap_tx.input)?;
        Ok(prevouts)
    }

    pub fn aggregate_sigs(&mut self, other_sig: PartialSignature) -> anyhow::Result<()> {
        self.fund_sig.as_mut().unwrap().aggregate_sigs(other_sig)?;
        Ok(())
    }

    pub fn sign(&mut self, p_tik: &AggKey) -> anyhow::Result<Transaction> {
        // only seller can do this
        if self.role == ProtocolRole::Seller {
            let old_tx = self.tx.clone().unwrap();
            let tx = self
                .fund_sig
                .as_mut()
                .unwrap()
                .sign(/* secret adaptor is*/ p_tik.sec.into(), old_tx)?;
            self.tx = Some(tx.clone()); // signed and ready to broadcast
            Ok(tx)
        } else {
            anyhow::bail!("Only the seller can complete the SwapTx.")
        }
    }
    /**
    if Bob finds a SwapTx on chain (or in mempool), we can (and should) extract Alice key for
    unlocking the seller's deposit and fund, which is as adaptive secret in the signature
    */
    pub fn reveal(&self, swap_tx: &Transaction, p_tik: &mut AggKey) -> anyhow::Result<()> {
        let signature = TMuSig2::extract_p2tr_key_path_signature(swap_tx, 0)?;
        // calculate the aggregated secret key as well.
        let fund_sig = self.fund_sig.as_ref().unwrap();
        // in swapTx reveal2Other makes only sense, when Seller gives to Buyer the secret key for p_tik
        if self.role == ProtocolRole::Buyer {
            fund_sig.reveal2other(&signature, p_tik)?;
            println!("revealed p_tik aggregated secret key: {:?}", p_tik.agg_sec);
            // p_tik shall have the other sec key and the aggregated secret key.
            // TODO Bob can import now the aggregated key into his wallet. there is no risc that Alice may
            // publish any transaction messing with it.
        }
        Ok(())
    }

    pub(crate) fn broadcast(&self, me: BMPContext) -> Txid {
        me.funds
            .client
            .transaction_broadcast(self.tx.as_ref().unwrap())
            .unwrap()
    }
}

pub struct DepositTx {
    pub part_psbt: Option<Psbt>,
    pub merged_psbt: Option<Psbt>,
    pub tx: Option<Transaction>,
}

impl DepositTx {
    fn new() -> DepositTx {
        DepositTx {
            part_psbt: None,
            merged_psbt: None,
            tx: None,
        }
    }

    pub fn generate_part_tx(
        &mut self,
        ctx: &mut BMPContext,
        p_a: &Point,
        q_a: &Point,
    ) -> anyhow::Result<Psbt> {
        // we are using our point as receipient address, but it will be changed to the musig address later.
        let (funded_by_me, amount) = match ctx.role {
            ProtocolRole::Seller => (p_a, ctx.seller_amount), // pub
            ProtocolRole::Buyer => (q_a, ctx.buyer_amount),
        };
        // create and fund a (virtual) transaction which funds Alice part of the Deposit Tx
        let mut builder = ctx.funds.wallet.build_tx();
        builder.add_recipient(
            funded_by_me.key_spend_no_merkle_address()?.script_pubkey(),
            amount,
        );
        builder.fee_rate(FeeRate::from_sat_per_vb(20).unwrap()); // TODO feerates shall come from pricenodes
        let pbst = builder.finish()?;
        self.part_psbt = Some(pbst.clone());
        // dbg!(&pbst.unsigned_tx.output);
        Ok(pbst)
    }

    pub fn build_and_merge_tx(
        &mut self,
        ctx: &mut BMPContext,
        other_psbt: &Psbt,
        p_tik: &AggKey,
        q_tik: &AggKey,
    ) -> anyhow::Result<Psbt> {
        let my_psbt = self.part_psbt.as_ref().unwrap();
        //sanity check that Bob doesn't send UTXOs owned by alice.
        for pbst_input in other_psbt.inputs.iter() {
            let scriptbuf = pbst_input.witness_utxo.clone().unwrap().script_pubkey;
            if ctx.funds.wallet.is_mine(scriptbuf.clone()) {
                // bob is trying to trick me.
                panic!(
                    "Fraud detected. Bob send me my own scriptbuf {:?}",
                    scriptbuf
                )
            }
        }
        // TODO sanity check if bobs transaction actually calculate the fee correctly, otherwise he could save on fess at the expense of alice

        // recreate combined ty from scratch
        let mut builder = ctx.funds.wallet.build_tx();
        builder.manually_selected_only(); // only use inputs we have already identified.
        builder.set_exact_sequence(Sequence::MAX); // no RBF, RBF disabled for foreign utxos anyway.
        // keep track of the fees, as total fees is not equal to sum of fess from alice and bob psbts.
        let mut total: i64 = 0; // measured in sats
        // add deposit outputs first.

        builder.add_recipient(p_tik.get_agg_script_pubkey()?, ctx.seller_amount);
        total = total - ctx.seller_amount.to_sat() as i64;

        builder.add_recipient(q_tik.get_agg_script_pubkey()?, ctx.buyer_amount);
        total = total - ctx.buyer_amount.to_sat() as i64;

        // in the following merge, we want to copy the funding inputs and the change outputs
        // so we disregard basically all known scripts.
        // technically, only the script created in the 'generate_part_tx()' should appear
        let disregard_scripts = &[
            p_tik
                .pub_point
                .key_spend_no_merkle_address()?
                .script_pubkey(),
            q_tik
                .pub_point
                .key_spend_no_merkle_address()?
                .script_pubkey(),
            p_tik
                .other_point
                .unwrap()
                .key_spend_no_merkle_address()?
                .script_pubkey(),
            q_tik
                .other_point
                .unwrap()
                .key_spend_no_merkle_address()?
                .script_pubkey(),
            p_tik
                .agg_point
                .unwrap()
                .key_spend_no_merkle_address()?
                .script_pubkey(), // technically these 2 script should not appear
            q_tik
                .agg_point
                .unwrap()
                .key_spend_no_merkle_address()?
                .script_pubkey(), // but don't let the other side do some fancy stuff
        ];
        total = builder.merge(my_psbt, false, total, disregard_scripts)?;
        total = builder.merge(other_psbt, true, total, disregard_scripts)?;

        builder.fee_absolute(Amount::from_sat(total as u64));
        builder.nlocktime(LockTime::ZERO);

        // Attempt to finish and return the merged PSBT
        let mut merged_psbt = builder.finish()?;

        // We need to sort the order of inputs and output to make the TXid of alice nd bod equal
        // TODO come up with a randomized sort to preserve privacy
        // TODO use builder.ordering() with custom alg.
        sort(&mut merged_psbt);

        // sign my psbt
        self.merged_psbt = Some(merged_psbt.clone());
        self.sign(ctx)?; // TODO move this signing to the end!
        self.part_psbt = None; // make sure not reused.
        self.tx = Some(self.merged_psbt.clone().unwrap().extract_tx()?);
        Ok(self.merged_psbt.clone().unwrap())
    }

    fn sign(&mut self, ctx: &mut BMPContext) -> anyhow::Result<()> {
        ctx.funds.wallet.sign(
            &mut self.merged_psbt.as_mut().unwrap(),
            SignOptions::default(),
        )?;
        Ok(())
    }

    fn transfer_sig_and_broadcast(
        &mut self,
        ctx: &mut BMPContext,
        psbt_bob: Psbt, // bobs psbt should be same as mine but have bob's sig
    ) -> anyhow::Result<Txid> {
        // I expect to find all sigs missing in psbt_alice to be in psbt_bob
        // also I expect that both psbts are the same exect for the sigs.
        let mut my_psbt = self.merged_psbt.as_ref().unwrap().clone();

        // dbg!(&my_psbt.unsigned_tx);
        // dbg!(&psbt_bob.unsigned_tx);
        assert!(my_psbt.unsigned_tx == psbt_bob.unsigned_tx);

        for (i, alice_input) in my_psbt.inputs.iter_mut().enumerate() {
            if alice_input.final_script_witness.is_none() {
                alice_input.final_script_witness =
                    Some(psbt_bob.inputs[i].final_script_witness.clone().unwrap()); //must exist
            }
        }
        let tx = my_psbt.extract_tx()?;
        self.tx = Some(tx.clone());
        self.merged_psbt = None; // remove used data
        // TODO both alice and bob will broadcast, is that a bug or a feature?
        let depo_txid = ctx.funds.transaction_broadcast(&tx)?;
        dbg!("DepositTx txid: {:?}", &depo_txid);
        Ok(depo_txid)
    }

    fn _get_outpoint_for(self, script: ScriptBuf) -> anyhow::Result<OutPoint> {
        let tx = self.tx.unwrap();

        for (index, output) in tx.output.iter().enumerate() {
            if output.script_pubkey == script {
                return Ok(OutPoint {
                    txid: tx.compute_txid(),
                    vout: index as u32,
                });
            }
        }

        Err(anyhow::anyhow!(
            "No matching output found for the provided script"
        ))
    }
}

/**
MuSig2 interaction, it represents the Key not only our side of the equation
*/

#[derive(PartialEq, Clone, Debug)]
pub struct AggKey {
    pub sec: Scalar,
    pub other_sec: Option<Scalar>,
    pub agg_sec: Option<Scalar>,
    pub pub_point: Point,
    pub other_point: Option<Point>,
    pub(crate) agg_point: Option<Point>,
    pub(crate) key_agg_context: Option<KeyAggContext>,
}

impl AggKey {
    pub fn new() -> anyhow::Result<AggKey> {
        //TODO is this random sufficient?
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);

        let sec: Scalar = Scalar::from_slice(&seed)?;
        let point = sec.base_point_mul();
        Ok(AggKey {
            sec,
            other_sec: None,
            agg_sec: None,
            pub_point: point,
            other_point: None,
            agg_point: None,
            key_agg_context: None,
        })
    }

    pub fn aggregate_key(&mut self, point_from_bob: Point) -> anyhow::Result<Point> {
        assert_ne!(
            point_from_bob, self.pub_point,
            "Bob is sending my point back."
        );
        // order of pubkeys must be the same as order of secret keys.
        // we use the smaller pubkey-value first. see reveal_other for secret keys.
        let pubkeys = if self.pub_point < point_from_bob {
            [self.pub_point, point_from_bob]
        } else {
            [point_from_bob, self.pub_point]
        };
        // dbg!(&pubkeys);
        let ctx1 = KeyAggContext::new(pubkeys)?;
        let ctx = ctx1.with_unspendable_taproot_tweak()?;
        let result = ctx.aggregated_pubkey();
        self.key_agg_context = Some(ctx);
        self.agg_point = Some(result);
        self.other_point = Some(point_from_bob);
        Ok(result)
    }
    // check https://bitcoin.stackexchange.com/questions/116384/what-are-the-steps-to-convert-a-private-key-to-a-taproot-address
    pub(crate) fn get_agg_adr(&self) -> anyhow::Result<Address> {
        self.key_agg_context
            .as_ref()
            .unwrap()
            .aggregated_pubkey_untweaked::<Point>()
            .key_spend_no_merkle_address()
    }
    pub(crate) fn get_agg_script_pubkey(&self) -> anyhow::Result<ScriptBuf> {
        Ok(self.get_agg_adr()?.script_pubkey())
    }
}
/**
 MuSig2 (non-adaptive), constructing a signature

round n: new(agg_key) -> pub_nonce
round n+1: generate partial adapted sig -> part-sig
round n+2: aggregate sig (and publish)
*/
/**
adaptive MuSig2, constructing a signature

round n: new(agg_key) -> pub_nonce
round n+1: generate partial adapted sig -> part-sig
round n+2: aggregate sig (and publish)
*/
pub struct TMuSig2 {
    pub agg_key: AggKey,
    sec_nonce: SecNonce,
    pub_nonce: PubNonce,
    agg_nonce: Option<AggNonce>,
    other_nonce: Option<PubNonce>,
    pub adaptor_sig: Option<Adaptor>,
}

#[derive(Debug)]
pub struct Adaptor {
    pub partial_sig: PartialSignature,
    pub input_index: usize, // which input in our transaction is going to use this signature?
    pub pub_adaptor: MaybePoint, // this is the image for which the other party must provide the pre-image in order to use this sig.
    pub msg: Hash<TapSighashTag>, // message to be signed
    pub adaptor_signature: Option<AdaptorSignature>,
}

impl TMuSig2 {
    pub fn new(agg_key: AggKey) -> TMuSig2 {
        // there must be the aggregated key at this point
        assert!(agg_key.agg_point.is_some());
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);
        let mut seed2 = [0u8; 32];
        rand::rng().fill(&mut seed2);
        let sec_nonce = SecNonceBuilder::new(seed)
            .with_aggregated_pubkey(agg_key.agg_point.unwrap())
            .with_extra_input(&seed2) //TODO does this help? Or do we need more random?
            // TODO check  BIP327 for nonce generation.
            .build();
        let pub_nonce = sec_nonce.public_nonce();
        TMuSig2 {
            agg_key,
            sec_nonce,
            pub_nonce,
            agg_nonce: None,
            other_nonce: None,
            adaptor_sig: None,
        }
    }

    pub fn generate_partial_sig(
        &mut self,
        input_index: usize, // which input in our transaction is going to use this signature?
        other_nonce: &PubNonce, // the public nonce from the other side to calc the aggregated nonce
        prevouts: &Vec<TxOut>, // the TxOuts from the previous transaction is part of the sig-alg in taproot
        tx: &Transaction,
    ) -> anyhow::Result<PartialSignature> {
        // the partial transaction with adaptor to be sent to the other party.
        // sign_partial()
        self.generate_adapted_partial_sig(
            input_index,
            MaybePoint::Infinity,
            other_nonce,
            prevouts,
            tx,
        )
    }

    pub fn generate_adapted_partial_sig(
        &mut self,
        input_index: usize, // which input in our transaction is going to use this signature?
        pub_adaptor: MaybePoint, // this is the image for which the other party must provide the pre-image in order to use this sig.
        other_nonce: &PubNonce, // the public nonce from the other side to calc the aggregated nonce
        prevouts: &Vec<TxOut>, // the TxOuts from the previous transaction is part of the sig-alg in taproot
        tx: &Transaction,
    ) -> anyhow::Result<PartialSignature> {
        // the partial transaction with adaptor to be sent to the other party.
        // calculate aggregated nonce first.
        let total_nonce = [self.pub_nonce.clone(), other_nonce.clone()];
        let agg_nonce = AggNonce::sum(total_nonce);
        self.agg_nonce = Some(agg_nonce.clone());
        self.other_nonce = Some(other_nonce.clone());

        let msg = Self::extract_message_from_tx(input_index, prevouts, tx);

        // see also trader:wallet::create_keyspend_payout_signature
        // BIP-341: "the message commits to the scriptPubKeys of all outputs spent by the transaction."
        let partial_signature = musig2::adaptor::sign_partial(
            self.agg_key.key_agg_context.as_ref().unwrap(),
            self.agg_key.sec,
            self.sec_nonce.clone(),
            &agg_nonce,
            pub_adaptor,
            msg,
        )?;

        self.adaptor_sig = Some(Adaptor {
            partial_sig: partial_signature,
            input_index,
            pub_adaptor,
            msg,
            adaptor_signature: None,
        });

        // secure nonce is used, delete it to protect against reuse
        self.sec_nonce = SecNonce::new(Scalar::one(), Scalar::one());

        Ok(partial_signature)
    }

    fn _get_part_sig(&self) -> PartialSignature {
        self.adaptor_sig.as_ref().unwrap().partial_sig.clone()
    }
    /**
    this is probably only called by Alice, the seller as the swapTx is only contructed by her.
    the aggregated sig is still not valid, needs to be adapted.
    */
    pub fn aggregate_sigs(&mut self, other_sig: PartialSignature) -> anyhow::Result<()> {
        let my_adaptor = self.adaptor_sig.as_mut().unwrap();
        // verify other_sig is strictly not necessary but fail fast is always good
        musig2::adaptor::verify_partial(
            self.agg_key.key_agg_context.as_ref().unwrap(),
            other_sig,
            self.agg_nonce.as_ref().unwrap(),
            my_adaptor.pub_adaptor,
            self.agg_key.other_point.unwrap(),
            self.other_nonce.as_ref().unwrap(),
            my_adaptor.msg,
        )
        .expect("invalid partial signature");

        let my_sig = my_adaptor.partial_sig.clone();

        let agg_signature = musig2::adaptor::aggregate_partial_signatures(
            self.agg_key.key_agg_context.as_ref().unwrap(),
            self.agg_nonce.as_ref().unwrap(),
            my_adaptor.pub_adaptor,
            [my_sig, other_sig],
            my_adaptor.msg,
        )?;
        my_adaptor.adaptor_signature = Some(agg_signature);

        // Verify the adaptor signature is valid for the given adaptor point and pubkey.
        musig2::adaptor::verify_single(
            *self.agg_key.agg_point.as_ref().unwrap(),
            &agg_signature,
            my_adaptor.msg,
            my_adaptor.pub_adaptor,
        )
        .expect("invalid aggregated adaptor signature");
        Ok(())
    }
    pub fn sign(
        &mut self,
        sec_adaptor: MaybeScalar,
        tx: Transaction,
    ) -> anyhow::Result<Transaction> {
        let my_adaptor = self.adaptor_sig.as_mut().unwrap();
        // Decrypt the signature with the adaptor secret.
        let valid_signature: LiftedSignature = my_adaptor
            .adaptor_signature
            .unwrap()
            .adapt(sec_adaptor)
            .unwrap();

        // this check shall be authoritative
        musig2::verify_single(
            self.agg_key.agg_point.unwrap(),
            valid_signature,
            my_adaptor.msg,
        )
        .expect("invalid decrypted adaptor signature");

        // valid_signature must be made into Taprrot signature, means we need to tweak with merkle_root (even if we don't have a merkle root)
        // stuff the valid signature into the transaction
        let ts = bitcoin::taproot::Signature::from_slice(valid_signature.serialize().as_ref())?;

        let mut sighasher = SighashCache::new(tx);
        *sighasher.witness_mut(my_adaptor.input_index).unwrap() = Witness::p2tr_key_spend(&ts);
        let tx = sighasher.into_transaction();
        // dbg!(&tx);
        Ok(tx)
    }
    /**
    Now let say Alice has posted the SwapTx, then Bob wants to reveal the secret for the public adaptor from the Transaction.
    */
    pub fn reveal(&self, final_sig: &Signature) -> anyhow::Result<Scalar> {
        // LiftedSignature::from_bytes(Sign)
        let sig = self
            .adaptor_sig
            .as_ref()
            .unwrap()
            .adaptor_signature
            .unwrap();
        let lifted_sig = &LiftedSignature::from_bytes(final_sig.serialize().as_ref())?;
        let revealed: MaybeScalar = sig.reveal_secret(lifted_sig).unwrap();
        let sec_adaptor = revealed.unwrap();
        Ok(sec_adaptor)
    }

    pub fn reveal2other(&self, final_sig: &Signature, tik: &mut AggKey) -> anyhow::Result<()> {
        let sec_adaptor = self.reveal(final_sig)?;
        tik.other_sec = Some(sec_adaptor);
        // calculate combined key as well.
        // array of seckeys must have same order as pubkeys. sort by pubkey
        let seckeys = if tik.pub_point < tik.other_point.unwrap() {
            [tik.sec, sec_adaptor]
        } else {
            [sec_adaptor, tik.sec]
        };
        let agg_sec = tik
            .key_agg_context
            .as_mut()
            .unwrap()
            .aggregated_seckey(seckeys)?;
        // lib has checked that the aggregated generated key actually works
        tik.agg_sec = Some(agg_sec);
        Ok(())
    }
    pub fn extract_p2tr_key_path_signature(
        tx: &Transaction,
        input_index: usize,
    ) -> anyhow::Result<Signature> {
        // Ensure the input index is valid
        if input_index >= tx.input.len() {
            anyhow::bail!("Invalid input index: {}", input_index);
        }

        let input: &TxIn = &tx.input[input_index];
        let witness = &input.witness;

        // For key path spending, the witness should contain exactly one element
        if witness.len() != 1 {
            anyhow::bail!(
                "The witness does not contain the correct structure for P2TR key path spending"
            );
        }

        // The first (and only) element in the witness should be the Schnorr signature
        let raw_signature = &witness[0];

        // Ensure the signature is 64 bytes long (we use only SigHash::Default)
        if raw_signature.len() != 64 {
            anyhow::bail!("Invalid Schnorr signature size (expected 64 bytes)");
        }

        // Parse the Schnorr signature
        let schnorr_sig = Signature::from_slice(raw_signature)?;

        Ok(schnorr_sig)
    }

    pub fn extract_message_from_tx(
        input_index: usize,
        prevouts: &Vec<TxOut>,
        unsigned_tx: &Transaction,
    ) -> Hash<TapSighashTag> {
        let sighash_type = TapSighashType::Default; // we are using in Musig only Default which is effectively equiv. to SIGHASH_ALL
        let prevouts = Prevouts::All(&prevouts);

        let mut sighasher = SighashCache::new(unsigned_tx);
        let sighash = sighasher
            // TODO report missing validation to rust-bitcoin if index is not correct.
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .expect("failed to construct sighash");
        sighash.to_raw_hash()
    }
}
trait PointExt {
    fn key_spend_no_merkle_address(&self) -> anyhow::Result<Address>;
}
impl PointExt for Point {
    fn key_spend_no_merkle_address(&self) -> anyhow::Result<Address> {
        let pubkey = PublicKey::from_slice(&self.serialize())?.to_x_only_pubkey();
        let secp = Secp256k1::new(); // TODO make it static?
        let adr = Address::p2tr(&secp, pubkey, None, KnownHrp::Regtest); // TODO parameterize Network
        Ok(adr)
    }
}

trait TransactionExt {
    fn output_index(&self, key: &AggKey) -> u32;
    fn get_outpoint_for(&self, key: &AggKey) -> anyhow::Result<OutPoint>;
    fn get_txin_for(&self, key: &AggKey) -> anyhow::Result<TxIn>;
    /**
    For Taproot signing, we need for all inputs of this transactions to look into the outpoint of TxIn and find the referenced transaction output (TxOut).
    this must be supplied for signing.
     */
    fn calc_prevouts(&self, inputs: &Vec<TxIn>) -> anyhow::Result<Vec<TxOut>>;
}
impl TransactionExt for Transaction {
    fn output_index(&self, key: &AggKey) -> u32 {
        let s = key.get_agg_script_pubkey().unwrap(); // TODO change unwrp into anyhow::Result
        self.output
            .iter()
            .position(|output| output.script_pubkey == s)
            .unwrap() as u32
    }
    fn get_outpoint_for(&self, key: &AggKey) -> anyhow::Result<OutPoint> {
        Ok(OutPoint {
            txid: self.compute_txid(),
            vout: self.output_index(key),
        })
    }

    fn get_txin_for(&self, key: &AggKey) -> anyhow::Result<TxIn> {
        Ok(TxIn {
            previous_output: self.get_outpoint_for(key)?,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        })
    }

    /**
    For Taproot signing, we need for all inputs of this transactions to look into the outpoint of TxIn and find the referenced transaction output (TxOut).
    this must be supplied for signing.
     */
    fn calc_prevouts(&self, inputs: &Vec<TxIn>) -> anyhow::Result<Vec<TxOut>> {
        // TODO use TransactionExt::calc_prevouts instead
        // TODO this is subject to performance optimization
        let mut prevouts = Vec::new();

        for input in inputs {
            let outpoint = input.previous_output;
            if self.compute_txid() == outpoint.txid {
                if let Some(output) = self.output.get(outpoint.vout as usize) {
                    prevouts.push(output.clone());
                } else {
                    anyhow::bail!(
                        "Output index {} not found in transaction for OutPoint: {:?}",
                        outpoint.vout,
                        outpoint
                    );
                }
            } else {
                anyhow::bail!("Transaction not found for OutPoint: {:?}", outpoint);
            }
        }
        Ok(prevouts)
    }
}
/*
why sort the inputs and outputs?
Alice and Bob both create the transaction, if the transaction hasn't the exact same Txid, the trnasactions will not be viewed as the same.
And for the Txid the ordering of inputs and output does count.
Note: This sort algo needs some care to make it privacy preserving.
*/
fn sort(psbt: &mut Psbt) {
    // need to sort unconfirmed tx as well
    let psbt2 = psbt.clone();
    // Sort the inputs in `psbt.inputs` and `psbt.unsigned_tx.input` while ensuring their indexes stay aligned
    let mut input_pairs: Vec<_> = psbt2
        .inputs
        .iter()
        .zip(psbt2.unsigned_tx.input.iter())
        .collect();
    input_pairs.sort_by_key(|(_, tx_input)| tx_input.previous_output); // TODO sort criteria should be random for more privacy

    // Reassign the sorted pairs back to their respective components
    psbt.inputs = input_pairs
        .iter()
        .map(|(input, _)| (*input).clone())
        .collect();
    psbt.unsigned_tx.input = input_pairs
        .iter()
        .map(|(_, tx_input)| (*tx_input).clone())
        .collect();

    // Sort the output in `psbt.inputs` and `psbt.unsigned_tx.output` while ensuring their indexes stay aligned
    let mut output_pair: Vec<_> = psbt2
        .outputs
        .iter()
        .zip(psbt2.unsigned_tx.output.iter())
        .collect();
    output_pair.sort_by_key(|(_, tx_output)| tx_output.script_pubkey.clone()); // TODO sort criteria should be random for more privacy

    // Reassign the sorted pairs back to their respective components
    psbt.outputs = output_pair
        .iter()
        .map(|(output, _)| (*output).clone())
        .collect();
    psbt.unsigned_tx.output = output_pair
        .iter()
        .map(|(_, tx_output)| (*tx_output).clone())
        .collect();
}

trait Merge {
    fn merge(
        &mut self,
        psbt: &Psbt,
        foreign: bool,
        total: i64,
        disregard_scripts: &[ScriptBuf],
    ) -> anyhow::Result<i64>;
}

impl Merge for TxBuilder<'_, BranchAndBoundCoinSelection> {
    fn merge(
        &mut self,
        psbt: &Psbt,
        foreign: bool,
        mut total: i64,
        disregard_scripts: &[ScriptBuf],
    ) -> anyhow::Result<i64> {
        for (index, psbt_input) in psbt.inputs.iter().enumerate() {
            let op = psbt.unsigned_tx.input[index].previous_output; // yes, you are seeing right, index in tx and psbt_input must match
            if foreign {
                self.add_foreign_utxo(op, psbt_input.clone(), Weight::from_wu(3))?;
                // TODO: how to calculate the satisfaction weight?
            } else {
                self.add_utxo(op)?;
            }
            let utxo = psbt_input
                .clone()
                .witness_utxo
                .expect("witness_utxo missing in psbt"); // Dump if not present! TODO error handling?
            total = total + utxo.value.to_sat() as i64;
        }

        // find the change TxOut from Bob and add them
        for txout in psbt.unsigned_tx.output.iter() {
            let scriptbuf = txout.script_pubkey.clone();
            if !disregard_scripts.contains(&scriptbuf) {
                self.add_recipient(scriptbuf, txout.value);
                total = total - txout.value.to_sat() as i64;
            }
        }
        Ok(total)
    }
}

