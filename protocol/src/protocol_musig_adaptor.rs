use std::io::Write as _;
use std::str::FromStr as _;

use crate::receiver::{Receiver, ReceiverList};
use crate::transaction::{
    DepositTxBuilder, ForwardingTxBuilder, RedirectTxBuilder, WarningTxBuilder, WithWitnesses as _,
};
use crate::wallet_service::WalletService;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hashes::sha256t::Hash;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::taproot::Signature;
use bdk_wallet::bitcoin::{
    relative, Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, TapSighashTag,
    Transaction, TxOut, Txid, XOnlyPublicKey,
};
use bdk_wallet::template::{Bip86, DescriptorTemplate as _};
use bdk_wallet::{AddressInfo, KeychainKind, SignOptions, Wallet};
use musig2::secp::MaybePoint::Valid;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AdaptorSignature, AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce,
    SecNonce, SecNonceBuilder,
};
use rand::{Rng as _, RngCore as _};
use testenv::TestEnv;


pub struct MemWallet {
    wallet: Wallet,
    testenv: TestEnv,
}

impl MemWallet {
    pub fn transaction_broadcast(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        let result = self.testenv.bdk_electrum_client().transaction_broadcast(tx);

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
#[expect(clippy::exhaustive_enums)]
pub enum ProtocolRole {
    Seller,
    Buyer,
}

impl ProtocolRole {
    const fn other(self) -> Self {
        match self {
            Self::Seller => Self::Buyer,
            Self::Buyer => Self::Seller,
        }
    }
}

// TODO think about stop_gap and batch_size
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

impl MemWallet {
    pub fn new() -> anyhow::Result<Self> {
        let mut seed: [u8; 32] = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        let network: Network = Network::Regtest;
        let xprv: Xpriv = Xpriv::new_master(network, &seed)?;
        println!("Generated Master Private Key:\n{xprv}\nWarning: be very careful with private \
            keys when using MainNet! We are logging these values for convenience only because this \
            is an example on RegTest.\n");

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

        // this is a test wallet, it should live in TestEnv or better be abandoned altogether
        let testenv = TestEnv::new()?;
        Ok(Self { wallet, testenv })
    }

    // test functionality for getting some coins in here
    pub fn funded_wallet() -> anyhow::Result<Self> {
        let mut me = MemWallet::new()?;
        let adr = me.next_unused_address();
        me.testenv.fund_address(&adr, Amount::from_btc(1f64)?)?;
        me.testenv.mine_block()?;
        me.sync()?;
        Ok(me)
    }

    pub fn sync(&mut self) -> anyhow::Result<()> {
        // Populate the electrum client's transaction cache so it doesn't re-download transaction we
        // already have.
        self.testenv.bdk_electrum_client()
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
                .testenv.bdk_electrum_client()
            .full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
        self.wallet.apply_update(update)?;
        Ok(())
    }

    pub fn balance(&self) -> Amount {
        self.wallet.balance().trusted_spendable()
    }

    pub fn next_unused_address(&mut self) -> AddressInfo {
        self.wallet.next_unused_address(KeychainKind::External)
    }

    fn _transfer_to_address(
        &mut self,
        address: &AddressInfo,
        amount: Amount,
    ) -> anyhow::Result<Txid> {
        let mut tx_builder = self.wallet.build_tx();
        tx_builder.add_recipient(address.script_pubkey(), amount);

        let mut psbt = tx_builder.finish()?;
        let finalized = self.wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized);

        let tx = psbt.extract_tx()?;
        self.testenv.bdk_electrum_client().transaction_broadcast(&tx)?;
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
    // public nonce
    // Seller address where to send the swap amount to -- only set from Seller:
    pub swap_script: Option<ScriptBuf>,
    pub warn_anchor_spend: ScriptBuf,
    pub claim_spend: ScriptBuf,
    pub redirect_anchor_spend: ScriptBuf,
}

#[derive(Debug)]
pub struct Round2Parameter {
    // DepositTx --------
    pub p_agg: Point,
    pub q_agg: Point,
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
    pub deposit_tx_signed: Psbt,
}

/**
this context is for the whole process and need to be persisted by the caller
 */
pub struct BMPContext {
    // first of all, everything which is general to the protocol itself
    pub funds: MemWallet,
    pub role: ProtocolRole,
    pub seller_amount: Amount,
    pub buyer_amount: Amount,
}

pub struct BMPProtocol {
    pub ctx: BMPContext,
    // Point securing Seller deposit and trade amount:
    pub p_tik: AggKey,
    // Point securing Buyer deposit:
    pub q_tik: AggKey,
    deposit_tx: DepositTx,
    // which round are we in:
    round: u8,
    pub swap_tx: SwapTx,
    pub warning_tx_me: WarningTx,
    warning_tx_peer: WarningTx,
    pub claim_tx_me: ClaimTx,
    claim_tx_peer: ClaimTx,
    pub redirect_tx_me: RedirectTx,
    redirect_tx_peer: RedirectTx,
}

impl BMPContext {
    pub fn new(wallet_service: WalletService, role: ProtocolRole, seller_amount: Amount, buyer_amount: Amount) -> anyhow::Result<Self> {
        Ok(Self {
            funds: wallet_service.retrieve_wallet(),
            role,
            seller_amount,
            buyer_amount,
        })
    }

    const fn am_buyer(&self) -> bool { matches!(self.role, ProtocolRole::Buyer) }
}

impl BMPProtocol {
    pub fn new(ctx: BMPContext) -> anyhow::Result<Self> {
        let role = ctx.role;
        Ok(Self {
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

        let dep_part_psbt = self.deposit_tx.generate_part_tx(&mut self.ctx)?;
        let swap_script = self.swap_tx.spend_condition(&mut self.ctx);
        let warn_anchor_spend = self.ctx.funds.wallet.next_unused_address(KeychainKind::External).script_pubkey();
        self.warning_tx_me.anchor_spend = Some(warn_anchor_spend.clone());

        // ClaimTx
        let claim_spend = self.ctx.funds.wallet.next_unused_address(KeychainKind::External).script_pubkey();
        self.claim_tx_me.claim_spend = Some(claim_spend.clone());

        // RedirectTx
        let redirect_anchor_spend = self.ctx.funds.wallet.next_unused_address(KeychainKind::External).script_pubkey();
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

    #[expect(clippy::similar_names, reason = "easy to distinguish local variable names in this case")]
    pub fn round2(&mut self, bob: Round1Parameter) -> anyhow::Result<Round2Parameter> {
        self.check_round(2);
        assert_ne!(bob.p_a, bob.q_a, "Bob is sending the same point for P' and Q'.");
        println!("The {:?} sellers secret for P_Tik is {:?}.", self.ctx.role, self.p_tik.sec);

        // key Aggregation -----
        self.p_tik.other_point = Some(bob.p_a);
        self.q_tik.other_point = Some(bob.q_a);
        self.p_tik.aggregate_key(bob.p_a)?;
        self.q_tik.aggregate_key(bob.q_a)?;
        // now we have the aggregated key
        // so we can construct the Deposit Tx
        self.deposit_tx.build_and_merge_tx(&mut self.ctx, bob.dep_part_psbt, &self.p_tik, &self.q_tik)?;
        self.warning_tx_me.build(&mut self.ctx, &self.p_tik, &self.q_tik, &self.deposit_tx)?;
        self.warning_tx_peer.anchor_spend = Some(bob.warn_anchor_spend);
        self.warning_tx_peer.build(&mut self.ctx, &self.p_tik, &self.q_tik, &self.deposit_tx)?;
        let warn_alice_p_nonce = self.warning_tx_me.sig_p.as_ref().unwrap().pub_nonce.clone();
        let warn_alice_q_nonce = self.warning_tx_me.sig_q.as_ref().unwrap().pub_nonce.clone();
        let warn_bob_p_nonce = self.warning_tx_peer.sig_p.as_ref().unwrap().pub_nonce.clone();
        let warn_bob_q_nonce = self.warning_tx_peer.sig_q.as_ref().unwrap().pub_nonce.clone();

        // given the DepositTx, we can create SwapTx for Alice.
        self.swap_tx.build(self.q_tik.clone(), &self.deposit_tx, bob.swap_script.as_ref())?;
        // let start the signing process for SwapTx already.
        let swap_pub_nonce = self.swap_tx.get_pub_nonce(); // could be one round earlier, if we solve secure nonce generation

        // ClaimTx
        let (tik, other_tik) = match self.ctx.role {
            ProtocolRole::Seller => (&self.q_tik, &self.p_tik),
            ProtocolRole::Buyer => (&self.p_tik, &self.q_tik)
        };
        self.claim_tx_me.build(tik, &self.warning_tx_me)?;
        let claim_alice_nonce = self.claim_tx_me.sig.as_ref().unwrap().pub_nonce.clone();
        self.claim_tx_peer.claim_spend = Some(bob.claim_spend);
        self.claim_tx_peer.build(other_tik, &self.warning_tx_peer)?;
        let claim_bob_nonce = self.claim_tx_peer.sig.as_ref().unwrap().pub_nonce.clone();

        // RedirectTx
        self.redirect_tx_me.build(other_tik, &self.warning_tx_peer)?; // RedirectTx overcrosses; Alice references Bob's WarningTx
        let redirect_alice_nonce = self.redirect_tx_me.sig.as_ref().unwrap().pub_nonce.clone();
        self.redirect_tx_peer.anchor_spend = Some(bob.redirect_anchor_spend);
        self.redirect_tx_peer.build(tik, &self.warning_tx_me)?;
        let redirect_bob_nonce = self.redirect_tx_peer.sig.as_ref().unwrap().pub_nonce.clone();

        Ok(Round2Parameter {
            p_agg: self.p_tik.agg_point.unwrap(),
            q_agg: self.q_tik.agg_point.unwrap(),
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

    #[expect(clippy::needless_pass_by_value, reason = "gives a safer & more consistent API")]
    pub fn round3(&mut self, bob: Round2Parameter) -> anyhow::Result<Round3Parameter> {
        self.check_round(3);
        // actually this next test is not necessary, but double-checking and fast fail is always good
        // TODO since we are sending this only to validate, we could use a hash of it as well, optimization
        assert_eq!(bob.p_agg, self.p_tik.agg_point.unwrap(), "Bob is sending the wrong P' for his aggregated key.");
        assert_eq!(bob.q_agg, self.q_tik.agg_point.unwrap(), "Bob is sending the wrong Q' for his aggregated key.");

        // let txid = self.deposit_tx.transfer_sig_and_broadcast(&mut self.ctx, bob.deposit_tx_merged)?;
        let txid = self.deposit_tx.tx()?.compute_txid();
        let adaptor_point = match self.ctx.role { // the seller's key for payout of seller deposit and trade amount is in question
            ProtocolRole::Seller => self.p_tik.pub_point,
            ProtocolRole::Buyer => self.p_tik.other_point.unwrap(),
        };
        // here we are building the partial signature of the SwapTx, note that there is only one SwapTx (for Alice)
        let swap_part_sig = self.swap_tx.build_partial_sig(&bob.swap_pub_nonce, adaptor_point)?;

        let [_p_part_me, _q_part_me] = self.warning_tx_me.build_partial_sig(&bob.warn_bob_p_nonce, &bob.warn_bob_q_nonce)?;

        let [p_part_peer, q_part_peer] = self.warning_tx_peer.build_partial_sig(&bob.warn_alice_p_nonce, &bob.warn_alice_q_nonce)?;
        // ClaimTx
        self.claim_tx_me.build_partial_sig(&bob.claim_bob_nonce)?; // no need to send my partial sig to peer
        let claim_part_sig = self.claim_tx_peer.build_partial_sig(&bob.claim_alice_nonce)?; // sign bobs transaction that I constructed

        // RedirectTx
        self.redirect_tx_me.build_partial_sig(&bob.redirect_bob_nonce)?;
        let redirect_part_sig = self.redirect_tx_peer.build_partial_sig(&bob.redirect_alice_nonce)?; // sign bobs transaction that I constructed

        Ok(Round3Parameter {
            deposit_txid: txid, // only for verification that we actually are on the same page
            swap_part_sig, // partial signature for SwapTx Alice (or None if we are Alice)
            p_part_peer, // partial signature for WarningTx Bob, input of p_tik
            q_part_peer,
            claim_part_sig,
            redirect_part_sig,
        })
    }

    #[expect(clippy::needless_pass_by_value, reason = "gives a safer & more consistent API")]
    pub fn round4(&mut self, bob: Round3Parameter) -> anyhow::Result<Round4Parameter> {
        self.check_round(4);
        dbg!(&bob);
        self.swap_tx.aggregate_sigs(bob.swap_part_sig)?;
        self.warning_tx_me.aggregate_sigs(bob.p_part_peer, bob.q_part_peer)?;
        self.claim_tx_me.aggregate_sigs(bob.claim_part_sig)?;
        self.redirect_tx_me.aggregate_sigs(bob.redirect_part_sig)?;
        // TODO final check
        self.deposit_tx.sign(&mut self.ctx)?;
        Ok(Round4Parameter {
            deposit_tx_signed: self.deposit_tx.merged_psbt()?.clone()
        })
    }

    pub fn round5(&mut self, bob: Round4Parameter) -> anyhow::Result<()> {
        self.check_round(5);
        self.deposit_tx.transfer_sig_and_broadcast(&mut self.ctx, bob.deposit_tx_signed)?;
        Ok(())
    }

    fn check_round(&mut self, round: u8) {
        assert_eq!(self.round, round - 1, "round already done");
        self.round = round;
    }

    // ------- Debug --------
    pub(crate) fn _get_p_tik_agg(&self) -> Address {
        let r = &self.p_tik;
        r.get_agg_adr().unwrap()
    }
}

/**
`RedirectTx` -- this redirects the funds from the `WarningTx` to the DAO.
This is expected if the traders have some sor of conflict, which they cannot resolve themselves.
One trader sends the `WarningTx`, the other trader answers by sending the `RedirectTx`.
If a redirectTx is not send within `t_2`, then the trader which sent the `WarningTx` can
send the `ClaimTx` and gets the hole funds for himself.
Since `RedirectTx` sends the funds to the DAO, it needs an anchors for the trader, so he
can raise the fees with CPFP to get it mined before `ClaimTx` can be broadcast.

`RedirectTx` Bob spends from `WarningTx` Alice, that's important.
Sending funds to the DAO is done by having a list of addresses (from contributors) and percentages. (must add up to 100%)
 */
#[derive(Default)]
pub struct RedirectTx {
    pub sig: Option<TMuSig2>,
    pub builder: RedirectTxBuilder,
    pub anchor_spend: Option<ScriptBuf>,
}

impl RedirectTx {
    pub fn new() -> Self { Self::default() }

    fn build(&mut self, tik: &AggKey, warn_tx: &WarningTx) -> anyhow::Result<()> {
        self.sig = Some(TMuSig2::new(tik.clone()));

        let receiver_shares = Self::get_dao_bm();
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10); // TODO: feerates shall come from pricenodes

        let escrow_amount = warn_tx.builder.escrow()?.prevout.value;
        let available_amount_msat = RedirectTxBuilder::available_amount_msat(escrow_amount, fee_rate)
            .ok_or(anyhow::anyhow!("Overflow computing available amount for receivers"))?;

        let receivers = Receiver::compute_receivers_from_shares(receiver_shares, available_amount_msat, fee_rate)
            .ok_or(anyhow::anyhow!("Could not compute receiver list"))?;

        let t1 = relative::LockTime::from_height(1); // TODO: define as const and find a good value
        self.builder
            .set_input(warn_tx.builder.escrow()?)
            .set_receivers(receivers)
            .set_anchor_address(Address::from_script(self.anchor_spend.as_ref().unwrap(), Network::Regtest)?) // TODO: Improve.
            .set_lock_time(t1)
            .compute_unsigned_tx()?;
        Ok(())
    }

    fn build_partial_sig(&mut self, peer_nonce: &PubNonce) -> anyhow::Result<PartialSignature> {
        let musig = self.sig.as_mut().unwrap();
        let msg = self.builder.input_sighash()?.into();
        musig.generate_partial_sig(peer_nonce, msg)
    }

    pub fn aggregate_sigs(&mut self, part_sig: PartialSignature) -> anyhow::Result<()> {
        let sig = self.sig.as_mut().unwrap();
        sig.aggregate_sigs(part_sig)?;

        // now stuff those signatures into the transaction
        self.builder
            .set_input_signature(sig.taproot_signature(MaybeScalar::Zero)?)
            .compute_signed_tx()?;
        Ok(())
    }

    pub fn broadcast(&self, me: &BMPContext) -> anyhow::Result<Txid> {
        Ok(me.funds.testenv.bdk_electrum_client().transaction_broadcast(self.builder.signed_tx()?)?)
    }

    /**
    sum of all f64 must be 1
     */
    //noinspection SpellCheckingInspection
    fn get_dao_bm() -> Vec<(Address, f64)> {
        // TODO this needs a real implementation, and check that sum of ratios is 1
        vec![
            (Address::from_str("bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk").unwrap().assume_checked(), 0.6),
            (Address::from_str("bcrt1phhl8d90r9haqwtvw2cv4ryjl8tlnqrv48nhpy7yyks5du6mr66xq5nlwhz").unwrap().assume_checked(), 0.4),
        ]
    }
}

/**
`ClaimTx` -- One version for Alice and one for Bob.
If the other side will not react on the `WarningTx` (by sending the `RedirectTx`)
then Alice can claim the total amounts for herself.
 */
#[derive(Default)]
pub struct ClaimTx {
    pub sig: Option<TMuSig2>,
    pub builder: ForwardingTxBuilder,
    pub claim_spend: Option<ScriptBuf>,
}

impl ClaimTx {
    pub fn new() -> Self { Self::default() }

    pub fn signed_tx(&self) -> anyhow::Result<&Transaction> { Ok(self.builder.signed_tx()?) }

    fn build(&mut self, tik: &AggKey, warn_tx: &WarningTx) -> anyhow::Result<()> {
        self.sig = Some(TMuSig2::new(tik.clone()));

        let t2 = relative::LockTime::from_height(2); // TODO: define as const and find a good value
        self.builder
            .set_input(warn_tx.builder.escrow()?)
            .set_payout_address(Address::from_script(self.claim_spend.as_ref().unwrap(), Network::Regtest)?) // TODO: Improve.
            .set_lock_time(t2)
            .set_fee_rate(FeeRate::from_sat_per_vb_unchecked(10)) // TODO: feerates shall come from pricenodes
            .compute_unsigned_tx()?;
        Ok(())
    }

    fn build_partial_sig(&mut self, peer_nonce: &PubNonce) -> anyhow::Result<PartialSignature> {
        let musig = self.sig.as_mut().unwrap();
        let msg = self.builder.input_sighash()?.into();
        musig.generate_partial_sig(peer_nonce, msg)
    }

    pub fn aggregate_sigs(&mut self, part_sig: PartialSignature) -> anyhow::Result<()> {
        let sig = self.sig.as_mut().unwrap();
        sig.aggregate_sigs(part_sig)?;

        // now stuff those signatures into the transaction
        self.builder
            .set_input_signature(sig.taproot_signature(MaybeScalar::Zero)?)
            .compute_signed_tx()?;
        Ok(())
    }

    pub fn broadcast(&self, me: &BMPContext) -> anyhow::Result<Txid> {
        Ok(me.funds.testenv.bdk_electrum_client().transaction_broadcast(self.signed_tx()?)?)
    }
}

/**
`WarningTx` -- there is one version for Alice and one for Bob.
That means each party generates both transaction and sign them.
 */
pub struct WarningTx {
    // is that my WarningTx? (mainly for safety checking):
    role: ProtocolRole,
    pub builder: WarningTxBuilder,
    // where to send the anchor sats to:
    pub anchor_spend: Option<ScriptBuf>,
    pub sig_p: Option<TMuSig2>,
    pub sig_q: Option<TMuSig2>,
}

impl WarningTx {
    pub fn unsigned_tx(&self) -> anyhow::Result<&Transaction> { Ok(self.builder.unsigned_tx()?) }

    pub fn signed_tx(&self) -> anyhow::Result<&Transaction> { Ok(self.builder.signed_tx()?) }

    pub fn funds_as_outpoint(&self) -> OutPoint {
        OutPoint::new(self.unsigned_tx().unwrap().compute_txid(), 0)
    }

    pub fn funds_as_output(&self) -> TxOut {
        let w = self.unsigned_tx().unwrap();
        let wout: &Vec<TxOut> = w.output.as_ref();
        wout[0].clone()
    }

    pub fn new(role: ProtocolRole) -> Self {
        Self {
            role,
            builder: WarningTxBuilder::default(),
            anchor_spend: None, // ctx.funds.wallet.next_unused_address(KeychainKind::External).script_pubkey(),
            sig_p: None,
            sig_q: None,
        }
    }

    fn build(&mut self, ctx: &mut BMPContext, p_tik: &AggKey, q_tik: &AggKey, deposit_tx: &DepositTx) -> anyhow::Result<()> {
        self.sig_p = Some(TMuSig2::new(p_tik.clone()));
        self.sig_q = Some(TMuSig2::new(q_tik.clone()));

        //--------------------
        let key_spend = match self.role {
            ProtocolRole::Seller => q_tik,
            ProtocolRole::Buyer => p_tik
        };

        let tx = self.builder
            .set_buyer_input(deposit_tx.builder.buyer_payout()?.clone())
            .set_seller_input(deposit_tx.builder.seller_payout()?.clone())
            .set_escrow_address(key_spend.get_agg_adr()?)
            .set_anchor_address(Address::from_script(self.anchor_spend.as_ref().unwrap(), Network::Regtest)?) // TODO: Improve.
            .set_lock_time(relative::LockTime::ZERO)
            .set_fee_rate(FeeRate::from_sat_per_vb_unchecked(10)) // TODO: feerates shall come from pricenodes
            .compute_unsigned_tx()?
            .unsigned_tx()?;

        dbg!(ctx.role, self.role, tx.compute_txid());
        Ok(())
    }

    fn build_partial_sig(&mut self, peer_nonce_p: &PubNonce, peer_nonce_q: &PubNonce) -> anyhow::Result<[PartialSignature; 2]> {
        let p_musig = self.sig_p.as_mut().unwrap();
        let p_msg = self.builder.buyer_input_sighash()?.into();
        let p_part = p_musig.generate_partial_sig(peer_nonce_p, p_msg)?;

        let q_musig = self.sig_q.as_mut().unwrap();
        let q_msg = self.builder.seller_input_sighash()?.into();
        let q_part = q_musig.generate_partial_sig(peer_nonce_q, q_msg)?;

        Ok([p_part, q_part])
    }

    pub fn aggregate_sigs(&mut self, p_part_sig: PartialSignature, q_part_sig: PartialSignature) -> anyhow::Result<()> {
        dbg!("agg p");
        let sig_p = self.sig_p.as_mut().unwrap();
        sig_p.aggregate_sigs(p_part_sig)?;
        dbg!("agg q");
        let sig_q = self.sig_q.as_mut().unwrap();
        sig_q.aggregate_sigs(q_part_sig)?;

        // now stuff those signatures into the transaction
        self.builder
            .set_buyer_input_signature(sig_p.taproot_signature(MaybeScalar::Zero)?)
            .set_seller_input_signature(sig_q.taproot_signature(MaybeScalar::Zero)?)
            .compute_signed_tx()?;
        Ok(())
    }

    pub fn broadcast(&self, me: &BMPContext) -> anyhow::Result<Txid> {
        Ok(me.funds.testenv.bdk_electrum_client().transaction_broadcast(self.signed_tx()?)?)
    }
}

/**
Only the seller gets a `SwapTx`, this is the only asymmetric part of the p3
 */
pub struct SwapTx {
    // this transaction is only for Alice, however even Bob will construct it for signing:
    pub role: ProtocolRole,
    pub builder: ForwardingTxBuilder,
    pub swap_spend: Option<ScriptBuf>,
    // SwapTx get funded by a adaptor MuSig2 signature
    pub fund_sig: Option<TMuSig2>,
}

impl SwapTx {
    pub(crate) fn spend_condition(&mut self, ctx: &mut BMPContext) -> Option<ScriptBuf> {
        self.swap_spend = match self.role {
            ProtocolRole::Seller => Some(ctx.funds.wallet.next_unused_address(KeychainKind::External).script_pubkey()),
            ProtocolRole::Buyer => None,
        };
        self.swap_spend.clone()
    }

    /**
    even though only the seller gets a `SwapTx` transaction, both parties are constructing the transaction
    and only the buyer will send the seller the signature.
     */
    fn new(role: ProtocolRole) -> Self {
        Self {
            role,
            builder: ForwardingTxBuilder::default(),
            swap_spend: None,
            fund_sig: None,
        }
    }

    pub fn unsigned_tx(&self) -> anyhow::Result<&Transaction> { Ok(self.builder.unsigned_tx()?) }

    pub fn get_pub_nonce(&self) -> PubNonce {
        self.fund_sig.as_ref().unwrap().pub_nonce.clone()
    }

    // round 1
    pub fn build(&mut self, q_tik: AggKey, deposit_tx: &DepositTx, swap_spend_opt: Option<&ScriptBuf>) -> anyhow::Result<()> {
        self.fund_sig = Some(TMuSig2::new(q_tik));
        let Some(use_spend) = (match self.role {
            ProtocolRole::Seller => self.swap_spend.as_ref(),
            ProtocolRole::Buyer => swap_spend_opt,
        }) else { panic!("No spend-condition from role {:?}", self.role) };

        self.builder
            .set_input(deposit_tx.builder.seller_payout()?.clone())
            .set_payout_address(Address::from_script(use_spend, Network::Regtest)?) // TODO: Improve.
            .disable_lock_time()
            .set_fee_rate(FeeRate::from_sat_per_vb_unchecked(10)) // TODO: feerates shall come from pricenodes
            .compute_unsigned_tx()?;
        Ok(())
    }

    pub fn build_partial_sig(&mut self, other_nonce: &PubNonce, p_a: Point) -> anyhow::Result<PartialSignature> {
        // SwapTx is asymmetric, both parties need to agree on P_a being the public adaptor
        // P_a is the Public key which Alice (the seller) contributes to 2of2 Multisig to lock the deposit and trade amount in the DepositTx
        // if secret key of P_a is revealed to Bob, then we has both partial keys to it and is able to spend it.
        let pub_adaptor = Valid(p_a);
        let fund_sig = self.fund_sig.as_mut().unwrap();
        let msg = self.builder.input_sighash()?.into();
        fund_sig.generate_adapted_partial_sig(pub_adaptor, other_nonce, msg)
    }

    pub fn aggregate_sigs(&mut self, other_sig: PartialSignature) -> anyhow::Result<()> {
        self.fund_sig.as_mut().unwrap().aggregate_sigs(other_sig)?;
        Ok(())
    }

    pub fn sign(&mut self, p_tik: &AggKey) -> anyhow::Result<Transaction> {
        // only seller can do this
        if self.role == ProtocolRole::Seller {
            let fund_sig = self.fund_sig.as_mut().unwrap();
            let tx = self.builder
                .set_input_signature(fund_sig.taproot_signature(/* secret adaptor is*/p_tik.sec.into())?)
                .compute_signed_tx()?
                .signed_tx()?;
            // signed and ready to broadcast
            Ok(tx.clone())
        } else {
            anyhow::bail!("Only the seller can complete the SwapTx.")
        }
    }

    /**
    if Bob finds a `SwapTx` on chain (or in mempool), we can (and should) extract Alice key for
    unlocking the seller's deposit and fund, which is as adaptive secret in the signature
     */
    pub fn reveal(&self, swap_tx: &Transaction, p_tik: &mut AggKey) -> anyhow::Result<()> {
        let signature = swap_tx.key_spend_signature(0)?;
        // calculate the aggregated secret key as well.
        let fund_sig = self.fund_sig.as_ref().unwrap();
        // in swapTx reveal2Other makes only sense, when Seller gives to Buyer the secret key for p_tik
        if self.role == ProtocolRole::Buyer {
            fund_sig.reveal2other(&signature, p_tik)?;
            println!("revealed p_tik aggregated secret key: {:?}", p_tik.agg_sec);
            // p_tik shall have the other sec key and the aggregated secret key.
            // TODO Bob can import now the aggregated key into his wallet. there is no risk that
            //  Alice may publish any transaction messing with it.
        }
        Ok(())
    }

    pub fn broadcast(&self, me: &BMPContext) -> anyhow::Result<Txid> {
        Ok(me.funds.testenv.bdk_electrum_client().transaction_broadcast(self.builder.signed_tx()?)?)
    }
}

#[derive(Default)]
pub struct DepositTx {
    pub builder: DepositTxBuilder,
}

impl DepositTx {
    pub fn new() -> Self { Self::default() }

    fn merged_psbt(&self) -> anyhow::Result<&Psbt> { Ok(self.builder.psbt()?) }

    fn tx(&self) -> anyhow::Result<&Transaction> { Ok(&self.merged_psbt()?.unsigned_tx) }

    pub fn generate_part_tx(&mut self, ctx: &mut BMPContext) -> anyhow::Result<Psbt> {
        self.builder
            .set_trade_amount(ctx.seller_amount - ctx.buyer_amount)
            .set_buyers_security_deposit(ctx.buyer_amount)
            .set_sellers_security_deposit(ctx.buyer_amount)
            .set_trade_fee_receivers(ReceiverList::default())
            .set_fee_rate(FeeRate::from_sat_per_vb_unchecked(20)); // TODO: feerates shall come from pricenodes

        let psbt = if ctx.am_buyer() {
            self.builder
                .init_buyers_half_psbt(&mut ctx.funds.wallet, &mut rand::rng())?
                .buyers_half_psbt()?
        } else {
            self.builder
                .init_sellers_half_psbt(&mut ctx.funds.wallet, &mut rand::rng())?
                .sellers_half_psbt()?
        };
        Ok(psbt.clone())
    }

    pub fn build_and_merge_tx(&mut self, ctx: &mut BMPContext, other_psbt: Psbt, p_tik: &AggKey, q_tik: &AggKey) -> anyhow::Result<()> {
        if ctx.am_buyer() {
            self.builder.set_sellers_half_psbt(other_psbt);
        } else {
            self.builder.set_buyers_half_psbt(other_psbt);
        }
        self.builder
            .set_buyer_payout_address(p_tik.get_agg_adr()?)
            .set_seller_payout_address(q_tik.get_agg_adr()?)
            .compute_unsigned_tx()?;
        Ok(())
    }

    fn sign(&mut self, ctx: &mut BMPContext) -> anyhow::Result<()> {
        if ctx.am_buyer() {
            self.builder.sign_buyer_inputs(&ctx.funds.wallet)?;
        } else {
            self.builder.sign_seller_inputs(&ctx.funds.wallet)?;
        }
        Ok(())
    }

    fn transfer_sig_and_broadcast(&mut self, ctx: &mut BMPContext,
                                  psbt_bob: Psbt,   // bobs psbt should be same as mine but have bob's sig
    ) -> anyhow::Result<Txid> {
        self.builder.combine_psbts(psbt_bob)?;

        let tx = self.builder.signed_tx()?;
        // TODO both alice and bob will broadcast, is that a bug or a feature?
        let deposit_txid = ctx.funds.transaction_broadcast(&tx)?;
        dbg!("DepositTx txid: {:?}", &deposit_txid);
        Ok(deposit_txid)
    }

    fn _get_outpoint_for(self, script: &ScriptBuf) -> anyhow::Result<OutPoint> {
        let tx = self.tx()?;

        for (index, output) in tx.output.iter().enumerate() {
            if output.script_pubkey == *script {
                return Ok(OutPoint {
                    txid: tx.compute_txid(),
                    vout: u32::try_from(index)?,
                });
            }
        }

        Err(anyhow::anyhow!("No matching output found for the provided script"))
    }
}

/**
`MuSig2` interaction, it represents the Key not only our side of the equation
 */
#[derive(PartialEq, Clone)]
#[derive(Debug)]
pub struct AggKey {
    pub sec: Scalar,
    pub other_sec: Option<Scalar>,
    pub agg_sec: Option<Scalar>,
    pub pub_point: Point,
    pub other_point: Option<Point>,
    pub agg_point: Option<Point>,
    pub key_agg_context: Option<KeyAggContext>,
}

impl AggKey {
    pub fn new() -> anyhow::Result<Self> {
        //TODO is this random sufficient?
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);

        let sec: Scalar = Scalar::from_slice(&seed)?;
        let point = sec.base_point_mul();
        Ok(Self { sec, other_sec: None, agg_sec: None, pub_point: point, other_point: None, agg_point: None, key_agg_context: None })
    }

    pub fn aggregate_key(&mut self, point_from_bob: Point) -> anyhow::Result<Point> {
        assert_ne!(point_from_bob, self.pub_point, "Bob is sending my point back.");
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
        self.key_agg_context.as_ref().unwrap().aggregated_pubkey_untweaked::<Point>().key_spend_no_merkle_address()
    }
}

/**
 `MuSig2` (non-adaptive), constructing a signature

round n: `new(agg_key)` -> `pub_nonce`
round n+1: generate partial adapted sig -> part-sig
round n+2: aggregate sig (and publish)
 *//**
adaptive `MuSig2`, constructing a signature

round n: `new(agg_key)` -> `pub_nonce`
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
    // this is the image for which the other party must provide the pre-image in order to use this sig:
    pub pub_adaptor: MaybePoint,
    // message to be signed:
    pub msg: Hash<TapSighashTag>,
    pub adaptor_signature: Option<AdaptorSignature>,
}

impl TMuSig2 {
    pub fn new(agg_key: AggKey) -> Self {
        // there must be the aggregated key at this point
        assert!(agg_key.agg_point.is_some());
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);
        let mut seed2 = [0u8; 32];
        rand::rng().fill(&mut seed2);
        let sec_nonce = SecNonceBuilder::new(seed)
            .with_aggregated_pubkey(agg_key.agg_point.unwrap())
            .with_extra_input(&seed2) //TODO does this help? Or do we need more random?
            // TODO check BIP327 for nonce generation.
            .build();
        let pub_nonce = sec_nonce.public_nonce();
        Self { agg_key, sec_nonce, pub_nonce, agg_nonce: None, other_nonce: None, adaptor_sig: None }
    }

    pub fn generate_partial_sig(
        &mut self,
        other_nonce: &PubNonce,   // the public nonce from the other side to calc the aggregated nonce
        msg: Hash<TapSighashTag>, // the computed sighash of the transaction input
    ) -> anyhow::Result<PartialSignature> { // the partial transaction with adaptor to be sent to the other party.
        self.generate_adapted_partial_sig(MaybePoint::Infinity, other_nonce, msg)
    }

    pub fn generate_adapted_partial_sig(
        &mut self,
        pub_adaptor: MaybePoint,  // this is the image for which the other party must provide the pre-image in order to use this sig.
        other_nonce: &PubNonce,   // the public nonce from the other side to calc the aggregated nonce
        msg: Hash<TapSighashTag>, // the computed sighash of the transaction input
    ) -> anyhow::Result<PartialSignature> { // the partial transaction with adaptor to be sent to the other party.
        // calculate aggregated nonce first.
        let total_nonce = [self.pub_nonce.clone(), other_nonce.clone()];
        let agg_nonce = AggNonce::sum(total_nonce);
        self.agg_nonce = Some(agg_nonce.clone());
        self.other_nonce = Some(other_nonce.clone());

        let partial_signature = musig2::adaptor::sign_partial(
            self.agg_key.key_agg_context.as_ref().unwrap(),
            self.agg_key.sec,
            self.sec_nonce.clone(),
            &agg_nonce,
            pub_adaptor,
            msg)?;

        self.adaptor_sig = Some(Adaptor {
            partial_sig: partial_signature,
            pub_adaptor,
            msg,
            adaptor_signature: None,
        });

        // secure nonce is used, delete it to protect against reuse
        self.sec_nonce = SecNonce::new(Scalar::one(), Scalar::one());

        Ok(partial_signature)
    }

    const fn _get_part_sig(&self) -> PartialSignature {
        self.adaptor_sig.as_ref().unwrap().partial_sig
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
        ).expect("invalid partial signature");

        let my_sig = my_adaptor.partial_sig;

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
        ).expect("invalid aggregated adaptor signature");
        Ok(())
    }

    pub fn taproot_signature(&self, sec_adaptor: MaybeScalar) -> anyhow::Result<Signature> {
        let my_adaptor = self.adaptor_sig.as_ref().unwrap();
        // Decrypt the signature with the adaptor secret.
        let valid_signature: LiftedSignature = my_adaptor.adaptor_signature.unwrap()
            .adapt(sec_adaptor)
            .unwrap();

        // this check shall be authoritative
        musig2::verify_single(
            self.agg_key.agg_point.unwrap(),
            valid_signature,
            my_adaptor.msg,
        ).expect("invalid decrypted adaptor signature");

        Ok(Signature::from_slice(valid_signature.serialize().as_ref())?)
    }

    /**
    Now let say Alice has posted the `SwapTx`, then Bob wants to reveal the secret for the public adaptor from the Transaction.
     */
    pub fn reveal(&self, final_sig: &Signature) -> anyhow::Result<Scalar> {
        // LiftedSignature::from_bytes(Sign)
        let sig = self.adaptor_sig.as_ref().unwrap().adaptor_signature.unwrap();
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
        let agg_sec = tik.key_agg_context.as_mut().unwrap().aggregated_seckey(seckeys)?;
        // lib has checked that the aggregated generated key actually works
        tik.agg_sec = Some(agg_sec);
        Ok(())
    }
}

trait PointExt {
    fn key_spend_no_merkle_address(&self) -> anyhow::Result<Address>;
}

impl PointExt for Point {
    fn key_spend_no_merkle_address(&self) -> anyhow::Result<Address> {
        let point_pub = self.serialize_xonly(); // convert from secp256k1 version 0.29.1 to secp256k1 version 0.30.1
        let untweaked_pubkey = XOnlyPublicKey::from_slice(&point_pub)?; // TODO unify versions of musig2 and bdk_wallet!
        let secp = Secp256k1::new(); // TODO make it static?
        // Convert to a taproot address with no scripts
        Ok(Address::p2tr(&secp, untweaked_pubkey, None, Network::Regtest))
    }
}
