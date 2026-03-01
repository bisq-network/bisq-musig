use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};

use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Psbt, TapSighash, Transaction, Txid};
use guardian::ArcMutexGuardian;
use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::{PartialSignature, PubNonce};
use protocol::multisig::{KeyCtx, KeyPair, PointExt as _, SigCtx};
use protocol::psbt::{mock_buyer_trade_wallet, mock_seller_trade_wallet, TradeWallet};
use protocol::receiver::{Receiver, ReceiverList};
use protocol::transaction::{
    DepositTxBuilder, ForwardingTxBuilder, NetworkParams as _, RedirectTxBuilder, WarningTxBuilder,
    WithWitnesses as _,
};
use thiserror::Error;

use crate::storage::{ByRef, ByVal, Storage};

pub trait TradeModelStore {
    fn add_trade_model(&self, trade_model: TradeModel);
    fn get_trade_model(&self, trade_id: &str) -> Option<Arc<Mutex<TradeModel>>>;
}

type TradeModelMemoryStore = Mutex<BTreeMap<String, Arc<Mutex<TradeModel>>>>;

impl TradeModelStore for TradeModelMemoryStore {
    fn add_trade_model(&self, trade_model: TradeModel) {
        // TODO: Maybe use try_insert (or similar), to disallow overwriting a trade model with the same ID.
        self.lock().unwrap().insert(trade_model.trade_id.clone(), Arc::new(Mutex::new(trade_model)));
    }

    fn get_trade_model(&self, trade_id: &str) -> Option<Arc<Mutex<TradeModel>>> {
        self.lock().unwrap().get(trade_id).map(Arc::clone)
    }
}

pub static TRADE_MODELS: LazyLock<TradeModelMemoryStore> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

#[derive(Default)]
pub struct TradeModel {
    trade_id: String,
    my_role: Role,
    trade_wallet: Option<Arc<Mutex<dyn TradeWallet + Send + 'static>>>,
    prepared_tx_fee_rate: Option<FeeRate>,
    redirection_receivers: Option<ReceiverList>,
    buyer_output_key_ctx: KeyCtx,
    seller_output_key_ctx: KeyCtx,
    deposit_tx: DepositTx,
    swap_tx: SwapTx,
    buyer_txs: ArbitrationTxs,
    seller_txs: ArbitrationTxs,
}

#[derive(Default, Eq, PartialEq)]
pub enum Role {
    #[default] SellerAsMaker,
    SellerAsTaker,
    BuyerAsMaker,
    BuyerAsTaker,
}

#[derive(Default)]
struct ArbitrationTxs {
    warning: WarningTx,
    redirect: RedirectTx,
    claim: ClaimTx,
}

#[derive(Default)]
struct DepositTx {
    builder: DepositTxBuilder,
}

#[derive(Default)]
struct SwapTx {
    builder: ForwardingTxBuilder,
    input_sighash: Option<TapSighash>,
    input_sig_ctx: SigCtx,
}

#[derive(Default)]
struct WarningTx {
    builder: WarningTxBuilder,
    buyer_input_sig_ctx: SigCtx,
    seller_input_sig_ctx: SigCtx,
}

#[derive(Default)]
struct RedirectTx {
    builder: RedirectTxBuilder,
    input_sig_ctx: SigCtx,
}

#[derive(Default)]
struct ClaimTx {
    builder: ForwardingTxBuilder,
    input_sig_ctx: SigCtx,
}

pub struct ExchangedAddresses<'a, S: Storage, V: NetworkValidation + 'a = NetworkChecked> {
    pub warning_tx_fee_bump: S::Store<'a, Address<V>>,
    pub redirect_tx_fee_bump: S::Store<'a, Address<V>>,
    pub claim_tx_payout: S::Store<'a, Address<V>>,
}

impl<'a> ExchangedAddresses<'a, ByVal, NetworkUnchecked> {
    fn require_network(self, required: Network) -> Result<ExchangedAddresses<'a, ByVal>> {
        Ok(ExchangedAddresses {
            warning_tx_fee_bump: self.warning_tx_fee_bump.require_network(required)?,
            redirect_tx_fee_bump: self.redirect_tx_fee_bump.require_network(required)?,
            claim_tx_payout: self.claim_tx_payout.require_network(required)?,
        })
    }
}

#[expect(clippy::struct_field_names,
reason = "removing common suffix probably wouldn't make things clearer")]
pub struct ExchangedNonces<'a, S: Storage> {
    pub swap_tx_input: S::Store<'a, PubNonce>,
    pub buyers_warning_tx_buyer_input: S::Store<'a, PubNonce>,
    pub buyers_warning_tx_seller_input: S::Store<'a, PubNonce>,
    pub sellers_warning_tx_buyer_input: S::Store<'a, PubNonce>,
    pub sellers_warning_tx_seller_input: S::Store<'a, PubNonce>,
    pub buyers_redirect_tx_input: S::Store<'a, PubNonce>,
    pub sellers_redirect_tx_input: S::Store<'a, PubNonce>,
    pub buyers_claim_tx_input: S::Store<'a, PubNonce>,
    pub sellers_claim_tx_input: S::Store<'a, PubNonce>,
}

pub struct ExchangedSigs<'a, S: Storage> {
    pub peers_warning_tx_buyer_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_warning_tx_seller_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_redirect_tx_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_claim_tx_input_partial_signature: S::Store<'a, PartialSignature>,
    pub swap_tx_input_partial_signature: Option<S::Store<'a, PartialSignature>>,
    pub swap_tx_input_sighash: Option<S::Store<'a, TapSighash>>,
    pub contractual_txids: Option<ContractualTxids>,
}

pub struct ContractualTxids {
    pub deposit: Txid,
    pub buyers_warning: Txid,
    pub sellers_warning: Txid,
    pub buyers_redirect: Txid,
    pub sellers_redirect: Txid,
}

impl TradeModel {
    pub fn new(trade_id: String, my_role: Role) -> Self {
        let mut trade_model = Self { trade_id, my_role, ..Default::default() };
        let network = trade_model.trade_wallet.insert(if trade_model.am_buyer() {
            Arc::new(Mutex::new(mock_buyer_trade_wallet()))
        } else {
            Arc::new(Mutex::new(mock_seller_trade_wallet()))
        }).lock().unwrap().network();
        for txs in [&mut trade_model.buyer_txs, &mut trade_model.seller_txs] {
            txs.warning.builder.set_lock_time(network.warning_lock_time());
            txs.redirect.builder.set_lock_time(network.redirect_lock_time());
            txs.claim.builder.set_lock_time(network.claim_lock_time());
        }
        trade_model.swap_tx.builder.disable_lock_time();
        trade_model
    }

    pub const fn am_buyer(&self) -> bool {
        matches!(self.my_role, Role::BuyerAsMaker | Role::BuyerAsTaker)
    }

    fn trade_wallet(&self) -> Result<ArcMutexGuardian<dyn TradeWallet + Send + 'static>> {
        Ok(ArcMutexGuardian::take(self.trade_wallet.clone()
            .ok_or(ProtocolErrorKind::MissingTradeWallet)?).unwrap())
    }

    pub fn set_trade_amount(&mut self, trade_amount: Amount) {
        self.deposit_tx.builder.set_trade_amount(trade_amount);
    }

    pub fn set_buyers_security_deposit(&mut self, buyers_security_deposit: Amount) {
        self.deposit_tx.builder.set_buyers_security_deposit(buyers_security_deposit);
    }

    pub fn set_sellers_security_deposit(&mut self, sellers_security_deposit: Amount) {
        self.deposit_tx.builder.set_sellers_security_deposit(sellers_security_deposit);
    }

    pub fn set_deposit_tx_fee_rate(&mut self, fee_rate: FeeRate) {
        self.deposit_tx.builder.set_fee_rate(fee_rate);
    }

    pub fn set_prepared_tx_fee_rate(&mut self, fee_rate: FeeRate) {
        for txs in [&mut self.buyer_txs, &mut self.seller_txs] {
            txs.warning.builder.set_fee_rate(fee_rate);
            txs.claim.builder.set_fee_rate(fee_rate);
        }
        self.prepared_tx_fee_rate.get_or_insert(fee_rate);
        self.swap_tx.builder.set_fee_rate(fee_rate);
    }

    pub fn set_trade_fee_receiver(&mut self, receiver: Option<Receiver<NetworkUnchecked>>) -> Result<()> {
        let network = self.trade_wallet()?.network();
        self.deposit_tx.builder.set_trade_fee_receivers(receiver
            .map(|r| r.require_network(network)).transpose()?
            .into_iter().collect());
        Ok(())
    }

    pub fn redirection_amount_msat(&self) -> Option<u64> {
        let split_input_amounts = [
            *self.deposit_tx.builder.trade_amount().ok()?,
            *self.deposit_tx.builder.buyers_security_deposit().ok()?,
            *self.deposit_tx.builder.sellers_security_deposit().ok()?,
        ];
        let escrow_amount =
            WarningTxBuilder::escrow_amount(split_input_amounts, self.prepared_tx_fee_rate?)?;

        RedirectTxBuilder::available_amount_msat(escrow_amount, self.prepared_tx_fee_rate?)
    }

    pub fn init_my_key_shares(&mut self) {
        self.buyer_output_key_ctx.init_my_key_share();
        self.seller_output_key_ctx.init_my_key_share();
    }

    pub fn get_my_key_shares(&self) -> Option<[&KeyPair; 2]> {
        Some([
            self.buyer_output_key_ctx.my_key_share().ok()?,
            self.seller_output_key_ctx.my_key_share().ok()?
        ])
    }

    pub fn set_peer_key_shares(&mut self, buyer_output_pub_key: Point, seller_output_pub_key: Point) {
        self.buyer_output_key_ctx.set_peers_pub_key(buyer_output_pub_key);
        self.seller_output_key_ctx.set_peers_pub_key(seller_output_pub_key);
    }

    pub fn aggregate_key_shares(&mut self) -> Result<()> {
        let network = self.trade_wallet()?.network();
        self.buyer_output_key_ctx.aggregate_pub_key_shares()?;
        self.seller_output_key_ctx.aggregate_pub_key_shares()?;

        let buyer_output_tweaked_key_ctx = self.buyer_output_key_ctx.with_taproot_tweak(None)?;
        let seller_output_tweaked_key_ctx = self.seller_output_key_ctx.with_taproot_tweak(None)?;

        let buyer_payout_address = buyer_output_tweaked_key_ctx.p2tr_address(network);
        let seller_payout_address = seller_output_tweaked_key_ctx.p2tr_address(network);
        self.deposit_tx.builder.set_buyer_payout_address(buyer_payout_address);
        self.deposit_tx.builder.set_seller_payout_address(seller_payout_address);

        self.buyer_txs.warning.buyer_input_sig_ctx.set_tweaked_key_ctx(buyer_output_tweaked_key_ctx.clone());
        self.seller_txs.warning.buyer_input_sig_ctx.set_tweaked_key_ctx(buyer_output_tweaked_key_ctx);
        self.swap_tx.input_sig_ctx.set_adaptor_point(*self.adaptor_key_share()?.pub_key())?;
        self.swap_tx.input_sig_ctx.set_tweaked_key_ctx(seller_output_tweaked_key_ctx.clone());
        self.buyer_txs.warning.seller_input_sig_ctx.set_tweaked_key_ctx(seller_output_tweaked_key_ctx.clone());
        self.seller_txs.warning.seller_input_sig_ctx.set_tweaked_key_ctx(seller_output_tweaked_key_ctx);

        let [buyer_claim_merkle_root, seller_claim_merkle_root] = self.claim_key_shares()?
            .map(|p| network.warning_output_merkle_root(&p.pub_key().to_public_key().into()));
        let buyers_warning_output_tweaked_key_ctx = self.seller_output_key_ctx.with_taproot_tweak(
            Some(&buyer_claim_merkle_root))?;
        let sellers_warning_output_tweaked_key_ctx = self.buyer_output_key_ctx.with_taproot_tweak(
            Some(&seller_claim_merkle_root))?;

        let buyers_warning_escrow_address = buyers_warning_output_tweaked_key_ctx.p2tr_address(network);
        let sellers_warning_escrow_address = sellers_warning_output_tweaked_key_ctx.p2tr_address(network);
        self.buyer_txs.warning.builder.set_escrow_address(buyers_warning_escrow_address);
        self.seller_txs.warning.builder.set_escrow_address(sellers_warning_escrow_address);

        self.buyer_txs.claim.input_sig_ctx.set_tweaked_key_ctx(buyers_warning_output_tweaked_key_ctx.clone());
        self.seller_txs.redirect.input_sig_ctx.set_tweaked_key_ctx(buyers_warning_output_tweaked_key_ctx);
        self.seller_txs.claim.input_sig_ctx.set_tweaked_key_ctx(sellers_warning_output_tweaked_key_ctx.clone());
        self.buyer_txs.redirect.input_sig_ctx.set_tweaked_key_ctx(sellers_warning_output_tweaked_key_ctx);
        Ok(())
    }

    fn adaptor_key_share(&self) -> Result<&KeyPair> {
        Ok(if self.am_buyer() {
            self.buyer_output_key_ctx.peers_key_share()?
        } else {
            self.buyer_output_key_ctx.my_key_share()?
        })
    }

    fn claim_key_shares(&self) -> Result<[&KeyPair; 2]> {
        let [buyer_key_ctx, seller_key_ctx] = [&self.buyer_output_key_ctx, &self.seller_output_key_ctx];
        Ok(if self.am_buyer() {
            [buyer_key_ctx.my_key_share()?, seller_key_ctx.peers_key_share()?]
        } else {
            [buyer_key_ctx.peers_key_share()?, seller_key_ctx.my_key_share()?]
        })
    }

    pub fn init_my_addresses(&mut self) -> Result<()> {
        let mut wallet = self.trade_wallet()?;
        let my_txs = if self.am_buyer() { &mut self.buyer_txs } else { &mut self.seller_txs };
        my_txs.warning.builder.set_anchor_address(wallet.new_address()?);
        my_txs.redirect.builder.set_anchor_address(wallet.new_address()?);
        my_txs.claim.builder.set_payout_address(wallet.new_address()?);
        if !self.am_buyer() {
            self.swap_tx.builder.set_payout_address(wallet.new_address()?);
        }
        drop(wallet);
        Ok(())
    }

    pub fn get_my_addresses(&self) -> Option<ExchangedAddresses<'_, ByRef>> {
        let my_txs = if self.am_buyer() { &self.buyer_txs } else { &self.seller_txs };
        Some(ExchangedAddresses {
            warning_tx_fee_bump: my_txs.warning.builder.anchor_address().ok()?,
            redirect_tx_fee_bump: my_txs.redirect.builder.anchor_address().ok()?,
            claim_tx_payout: my_txs.claim.builder.payout_address().ok()?,
        })
    }

    pub fn set_peer_addresses(&mut self, addresses: ExchangedAddresses<ByVal, NetworkUnchecked>) -> Result<()> {
        let addresses = addresses.require_network(self.trade_wallet()?.network())?;
        let peer_txs = if self.am_buyer() { &mut self.seller_txs } else { &mut self.buyer_txs };
        peer_txs.warning.builder.set_anchor_address(addresses.warning_tx_fee_bump);
        peer_txs.redirect.builder.set_anchor_address(addresses.redirect_tx_fee_bump);
        peer_txs.claim.builder.set_payout_address(addresses.claim_tx_payout);
        Ok(())
    }

    pub fn init_my_half_deposit_psbt(&mut self) -> Result<()> {
        if self.am_buyer() {
            self.deposit_tx.builder.init_buyers_half_psbt(&mut *self.trade_wallet()?, &mut rand::rng())?;
        } else {
            self.deposit_tx.builder.init_sellers_half_psbt(&mut *self.trade_wallet()?, &mut rand::rng())?;
        }
        Ok(())
    }

    pub fn get_my_half_deposit_psbt(&self) -> Option<&Psbt> {
        if self.am_buyer() {
            self.deposit_tx.builder.buyers_half_psbt().ok()
        } else {
            self.deposit_tx.builder.sellers_half_psbt().ok()
        }
    }

    pub fn set_peer_half_deposit_psbt(&mut self, half_deposit_psbt: Psbt) {
        if self.am_buyer() {
            self.deposit_tx.builder.set_sellers_half_psbt(half_deposit_psbt);
        } else {
            self.deposit_tx.builder.set_buyers_half_psbt(half_deposit_psbt);
        }
    }

    pub fn compute_unsigned_deposit_tx(&mut self) -> Result<()> {
        self.deposit_tx.builder.compute_unsigned_tx()?;
        let buyer_payout = self.deposit_tx.builder.buyer_payout()?;
        let seller_payout = self.deposit_tx.builder.seller_payout()?;

        for txs in [&mut self.buyer_txs, &mut self.seller_txs] {
            txs.warning.builder.set_buyer_input(buyer_payout.clone());
            txs.warning.builder.set_seller_input(seller_payout.clone());
        }
        self.swap_tx.builder.set_input(seller_payout.clone());
        Ok(())
    }

    pub fn compute_unsigned_prepared_txs(&mut self) -> Result<()> {
        if !self.am_buyer() {
            // Only the seller has all the params necessary to compute the unsigned swap tx.
            self.swap_tx.builder.compute_unsigned_tx()?;
        }
        let [mut txs, mut peer_txs] = [&mut self.buyer_txs, &mut self.seller_txs];
        txs.warning.builder.compute_unsigned_tx()?;
        peer_txs.warning.builder.compute_unsigned_tx()?;
        for _ in 0..2 {
            txs.redirect.builder.set_input(peer_txs.warning.builder.escrow()?.clone());
            txs.redirect.builder.compute_unsigned_tx()?;
            txs.claim.builder.set_input(txs.warning.builder.escrow()?.clone());
            txs.claim.builder.compute_unsigned_tx()?;
            std::mem::swap(&mut txs, &mut peer_txs);
        }
        Ok(())
    }

    fn contractual_txids(&self) -> Result<ContractualTxids> {
        Ok(ContractualTxids {
            deposit: *self.deposit_tx.builder.txid()?,
            buyers_warning: *self.buyer_txs.warning.builder.txid()?,
            sellers_warning: *self.seller_txs.warning.builder.txid()?,
            buyers_redirect: *self.buyer_txs.redirect.builder.txid()?,
            sellers_redirect: *self.seller_txs.redirect.builder.txid()?,
        })
    }

    pub fn set_redirection_receivers<I, E>(&mut self, receivers: I) -> Result<(), E>
        where I: IntoIterator<Item=Result<Receiver<NetworkUnchecked>, E>>,
              E: From<ProtocolErrorKind>
    {
        let network = self.trade_wallet()?.network();
        let mut vec = Vec::new();
        for receiver in receivers {
            vec.push(receiver?.require_network(network).map_err(ProtocolErrorKind::from)?);
        }
        let receivers: ReceiverList = vec.into();
        self.redirection_receivers = Some(receivers.clone());
        self.buyer_txs.redirect.builder.set_receivers(receivers.clone());
        self.seller_txs.redirect.builder.set_receivers(receivers);
        Ok(())
    }

    pub fn check_redirect_tx_params(&self) -> Result<()> {
        // FIXME: Don't falsely report overflows & invalid params as missing-param errors:
        let receivers = &self.redirection_receivers.as_ref()
            .ok_or(ProtocolErrorKind::MissingTxParams)?[..];
        let fee_rate = self.prepared_tx_fee_rate
            .ok_or(ProtocolErrorKind::MissingTxParams)?;
        let available_msat = self.redirection_amount_msat()
            .ok_or(ProtocolErrorKind::MissingTxParams)?;
        let used_msat = Receiver::total_output_cost_msat(receivers, fee_rate, 1)
            .ok_or(ProtocolErrorKind::MissingTxParams)?;

        if used_msat > available_msat {
            return Err(ProtocolErrorKind::InsufficientRedirectionFunds { available_msat, used_msat });
        }
        if used_msat.saturating_add(999) < available_msat {
            return Err(ProtocolErrorKind::ExcessRedirectionFunds { available_msat, used_msat });
        }
        Ok(())
    }

    pub fn init_my_nonce_shares(&mut self) -> Result<()> {
        for ctx in self.all_sig_ctxs_mut() {
            ctx.init_my_nonce_share()?;
        }
        Ok(())
    }

    pub fn get_my_nonce_shares(&self) -> Option<ExchangedNonces<'_, ByRef>> {
        Some(ExchangedNonces {
            swap_tx_input:
            self.swap_tx.input_sig_ctx.my_nonce_share().ok()?,
            buyers_warning_tx_buyer_input:
            self.buyer_txs.warning.buyer_input_sig_ctx.my_nonce_share().ok()?,
            buyers_warning_tx_seller_input:
            self.buyer_txs.warning.seller_input_sig_ctx.my_nonce_share().ok()?,
            sellers_warning_tx_buyer_input:
            self.seller_txs.warning.buyer_input_sig_ctx.my_nonce_share().ok()?,
            sellers_warning_tx_seller_input:
            self.seller_txs.warning.seller_input_sig_ctx.my_nonce_share().ok()?,
            buyers_redirect_tx_input:
            self.buyer_txs.redirect.input_sig_ctx.my_nonce_share().ok()?,
            sellers_redirect_tx_input:
            self.seller_txs.redirect.input_sig_ctx.my_nonce_share().ok()?,
            buyers_claim_tx_input:
            self.buyer_txs.claim.input_sig_ctx.my_nonce_share().ok()?,
            sellers_claim_tx_input:
            self.seller_txs.claim.input_sig_ctx.my_nonce_share().ok()?,
        })
    }

    const fn all_sig_ctxs_mut(&mut self) -> [&mut SigCtx; 9] {
        [
            &mut self.swap_tx.input_sig_ctx,
            &mut self.buyer_txs.warning.buyer_input_sig_ctx,
            &mut self.buyer_txs.warning.seller_input_sig_ctx,
            &mut self.seller_txs.warning.buyer_input_sig_ctx,
            &mut self.seller_txs.warning.seller_input_sig_ctx,
            &mut self.buyer_txs.redirect.input_sig_ctx,
            &mut self.seller_txs.redirect.input_sig_ctx,
            &mut self.buyer_txs.claim.input_sig_ctx,
            &mut self.seller_txs.claim.input_sig_ctx
        ]
    }

    pub fn set_peer_nonce_shares(&mut self, nonce_shares: ExchangedNonces<ByVal>) {
        let sig_ctxs = self.all_sig_ctxs_mut();
        sig_ctxs[0].set_peers_nonce_share(nonce_shares.swap_tx_input);
        sig_ctxs[1].set_peers_nonce_share(nonce_shares.buyers_warning_tx_buyer_input);
        sig_ctxs[2].set_peers_nonce_share(nonce_shares.buyers_warning_tx_seller_input);
        sig_ctxs[3].set_peers_nonce_share(nonce_shares.sellers_warning_tx_buyer_input);
        sig_ctxs[4].set_peers_nonce_share(nonce_shares.sellers_warning_tx_seller_input);
        sig_ctxs[5].set_peers_nonce_share(nonce_shares.buyers_redirect_tx_input);
        sig_ctxs[6].set_peers_nonce_share(nonce_shares.sellers_redirect_tx_input);
        sig_ctxs[7].set_peers_nonce_share(nonce_shares.buyers_claim_tx_input);
        sig_ctxs[8].set_peers_nonce_share(nonce_shares.sellers_claim_tx_input);
    }

    pub fn aggregate_nonce_shares(&mut self) -> Result<()> {
        for ctx in self.all_sig_ctxs_mut() {
            ctx.aggregate_nonce_shares()?;
        }
        Ok(())
    }

    pub fn sign_partial(&mut self) -> Result<()> {
        for txs in [&mut self.buyer_txs, &mut self.seller_txs] {
            txs.warning.buyer_input_sig_ctx
                .sign_partial(txs.warning.builder.buyer_input_sighash()?)?;
            txs.warning.seller_input_sig_ctx
                .sign_partial(txs.warning.builder.seller_input_sighash()?)?;
            txs.redirect.input_sig_ctx
                .sign_partial(txs.redirect.builder.input_sighash()?)?;
            txs.claim.input_sig_ctx
                .sign_partial(txs.claim.builder.input_sighash()?)?;
        }
        if !self.am_buyer() {
            // Unlike the other multisig sighashes, only the seller is able to independently compute
            // the swap-tx-input sighash. The buyer must wait for the next round, when the deposit
            // tx is signed, to partially sign the swap tx using the sighash passed by the seller.
            self.sign_swap_tx_input_partial(self.swap_tx.builder.input_sighash()?)?;
        }
        Ok(())
    }

    pub fn sign_swap_tx_input_partial(&mut self, sighash: TapSighash) -> Result<()> {
        let sighash = self.swap_tx.input_sighash.insert(sighash);
        self.swap_tx.input_sig_ctx.sign_partial(*sighash)?;
        Ok(())
    }

    pub fn get_my_partial_signatures_on_peer_txs(&self, buyer_ready_to_release: bool) -> Option<ExchangedSigs<'_, ByRef>> {
        let peer_txs = if self.am_buyer() { &self.seller_txs } else { &self.buyer_txs };
        let ready_to_release = buyer_ready_to_release || !self.am_buyer();

        Some(ExchangedSigs {
            peers_warning_tx_buyer_input_partial_signature:
            peer_txs.warning.buyer_input_sig_ctx.my_partial_sig().ok()?,
            peers_warning_tx_seller_input_partial_signature:
            peer_txs.warning.seller_input_sig_ctx.my_partial_sig().ok()?,
            peers_redirect_tx_input_partial_signature:
            peer_txs.redirect.input_sig_ctx.my_partial_sig().ok()?,
            peers_claim_tx_input_partial_signature:
            peer_txs.claim.input_sig_ctx.my_partial_sig().ok()?,
            swap_tx_input_partial_signature:
            self.swap_tx.input_sig_ctx.my_partial_sig().ok().filter(|_| ready_to_release),
            swap_tx_input_sighash:
            self.swap_tx.input_sighash.as_ref(),
            contractual_txids:
            self.contractual_txids().ok().filter(|_| !buyer_ready_to_release),
        })
    }

    pub fn set_peer_partial_signatures_on_my_txs(&mut self, sigs: &ExchangedSigs<ByVal>) {
        let my_txs = if self.am_buyer() { &mut self.buyer_txs } else { &mut self.seller_txs };
        my_txs.warning.buyer_input_sig_ctx
            .set_peers_partial_sig(sigs.peers_warning_tx_buyer_input_partial_signature);
        my_txs.warning.seller_input_sig_ctx
            .set_peers_partial_sig(sigs.peers_warning_tx_seller_input_partial_signature);
        my_txs.redirect.input_sig_ctx
            .set_peers_partial_sig(sigs.peers_redirect_tx_input_partial_signature);
        my_txs.claim.input_sig_ctx
            .set_peers_partial_sig(sigs.peers_claim_tx_input_partial_signature);

        // NOTE: This passed field would normally be 'None' for the seller, as the buyer should redact the field
        // at the trade start and reveal it later, after payment is started, to prevent premature trade closure:
        sigs.swap_tx_input_partial_signature.map(|s| self.swap_tx.input_sig_ctx.set_peers_partial_sig(s));
    }

    pub fn aggregate_partial_signatures(&mut self) -> Result<()> {
        let my_txs = if self.am_buyer() { &mut self.buyer_txs } else { &mut self.seller_txs };
        my_txs.warning.buyer_input_sig_ctx.aggregate_partial_signatures()?;
        my_txs.warning.seller_input_sig_ctx.aggregate_partial_signatures()?;
        my_txs.redirect.input_sig_ctx.aggregate_partial_signatures()?;
        my_txs.claim.input_sig_ctx.aggregate_partial_signatures()?;
        if self.am_buyer() {
            // This forms a validated adaptor signature on the swap tx for the buyer, ensuring that the seller's
            // private key share is revealed if the swap tx is published. The seller doesn't get the full adaptor
            // signature (or the ordinary signature) until later on in the trade, when the buyer confirms payment:
            self.swap_tx.input_sig_ctx.aggregate_partial_signatures()?;
        }
        Ok(())
    }

    pub fn compute_my_signed_prepared_txs(&mut self) -> Result<()> {
        use MaybeScalar::Zero;
        let my_txs = if self.am_buyer() { &mut self.buyer_txs } else { &mut self.seller_txs };
        my_txs.warning.builder
            .set_buyer_input_signature(my_txs.warning.buyer_input_sig_ctx.compute_taproot_signature(Zero)?)
            .set_seller_input_signature(my_txs.warning.seller_input_sig_ctx.compute_taproot_signature(Zero)?)
            .compute_signed_tx()?;
        my_txs.redirect.builder
            .set_input_signature(my_txs.redirect.input_sig_ctx.compute_taproot_signature(Zero)?)
            .compute_signed_tx()?;
        my_txs.claim.builder
            .set_input_signature(my_txs.claim.input_sig_ctx.compute_taproot_signature(Zero)?)
            .compute_signed_tx()?;
        Ok(())
    }

    pub fn sign_deposit_psbt(&mut self) -> Result<()> {
        // Check that we have all the prepared tx data we need:
        let my_txs = if self.am_buyer() { &self.buyer_txs } else { &self.seller_txs };
        my_txs.warning.builder.signed_tx()?;
        my_txs.redirect.builder.signed_tx()?;
        my_txs.claim.builder.signed_tx()?;
        if self.am_buyer() {
            self.swap_tx.input_sig_ctx.aggregated_sig()?;
        }
        // FIXME: This is the first point in the protocol that a real commitment is made.
        //  It is CRITICAL that the trade data is persisted and backed up at this point.
        if self.am_buyer() {
            self.deposit_tx.builder.sign_buyer_inputs(&*self.trade_wallet()?)?;
        } else {
            self.deposit_tx.builder.sign_seller_inputs(&*self.trade_wallet()?)?;
        }
        Ok(())
    }

    pub fn get_deposit_psbt(&self) -> Option<&Psbt> {
        self.deposit_tx.builder.psbt().ok()
    }

    pub fn combine_deposit_psbts(&mut self, other: Psbt) -> Result<()> {
        self.deposit_tx.builder.combine_psbts(other)?;
        Ok(())
    }

    pub fn get_signed_deposit_tx(&self) -> Option<Transaction> {
        self.deposit_tx.builder.signed_tx().ok()
    }

    pub fn set_swap_tx_input_peers_partial_signature(&mut self, sig: PartialSignature) {
        self.swap_tx.input_sig_ctx.set_peers_partial_sig(sig);
    }

    pub fn aggregate_swap_tx_partial_signatures(&mut self) -> Result<()> {
        self.swap_tx.input_sig_ctx.aggregate_partial_signatures()?;
        Ok(())
    }

    pub fn get_my_private_key_share_for_peer_output(&self) -> Option<&Scalar> {
        // FIXME: Check that it's actually safe to release the funds at this point.
        let peer_key_ctx = if self.am_buyer() {
            &self.seller_output_key_ctx
        } else {
            &self.buyer_output_key_ctx
        };
        peer_key_ctx.my_key_share().ok()?.prv_key().ok()
    }

    const fn get_my_key_ctx_mut(&mut self) -> &mut KeyCtx {
        if self.am_buyer() {
            &mut self.buyer_output_key_ctx
        } else {
            &mut self.seller_output_key_ctx
        }
    }

    pub fn set_peer_private_key_share_for_my_output(&mut self, prv_key_share: Scalar) -> Result<()> {
        self.get_my_key_ctx_mut().set_peers_prv_key(prv_key_share)?;
        Ok(())
    }

    pub fn aggregate_private_keys_for_my_output(&mut self) -> Result<&Scalar> {
        Ok(self.get_my_key_ctx_mut().aggregate_prv_key_shares()?)
    }

    pub fn compute_signed_swap_tx(&mut self) -> Result<()> {
        let adaptor_secret = (*self.adaptor_key_share()?.prv_key()?).into();
        self.swap_tx.builder
            .set_input_signature(self.swap_tx.input_sig_ctx.compute_taproot_signature(adaptor_secret)?)
            .compute_signed_tx()?;
        Ok(())
    }

    pub fn get_signed_swap_tx(&self) -> Option<&Transaction> {
        self.swap_tx.builder.signed_tx().ok()
    }

    pub fn recover_seller_private_key_share_for_buyer_output(&mut self, swap_tx: &Transaction) -> Result<()> {
        if self.am_buyer() {
            let swap_tx_input = self.deposit_tx.builder.seller_payout()?;
            let input_signature = swap_tx.find_key_spend_signature(swap_tx_input)?;
            let adaptor_secret = self.swap_tx.input_sig_ctx.reveal_adaptor_secret(input_signature)?;
            self.buyer_output_key_ctx.set_peers_prv_key(adaptor_secret)?;
        }
        Ok(())
    }
}

type Result<T, E = ProtocolErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ProtocolErrorKind {
    #[error("missing tx params")]
    MissingTxParams,
    #[error("missing trade wallet")]
    MissingTradeWallet,
    #[error("insufficient redirection funds (available {available_msat:?} msat, used {used_msat:?} msat)")]
    InsufficientRedirectionFunds {
        available_msat: u64,
        used_msat: u64,
    },
    #[error("excess redirection funds (available {available_msat:?} msat, used {used_msat:?} msat)")]
    ExcessRedirectionFunds {
        available_msat: u64,
        used_msat: u64,
    },
    AddressParse(#[from] bdk_wallet::bitcoin::address::ParseError),
    Transaction(#[from] protocol::transaction::TransactionErrorKind),
    Multisig(#[from] protocol::multisig::MultisigErrorKind),
}
