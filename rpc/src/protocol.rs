use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};

use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Psbt, TapSighash, Transaction};
use guardian::ArcMutexGuardian;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{PartialSignature, PubNonce};
use protocol::multisig::{KeyCtx, KeyPair, OptKeyPair, SigCtx};
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
    deposit_tx_builder: DepositTxBuilder,
    swap_tx_builder: ForwardingTxBuilder,
    prepared_tx_fee_rate: Option<FeeRate>,
    buyer_output_key_ctx: KeyCtx,
    seller_output_key_ctx: KeyCtx,
    redirection_receivers: Option<ReceiverList>,
    buyers_warning_tx_builder: WarningTxBuilder,
    sellers_warning_tx_builder: WarningTxBuilder,
    buyers_redirect_tx_builder: RedirectTxBuilder,
    sellers_redirect_tx_builder: RedirectTxBuilder,
    buyers_claim_tx_builder: ForwardingTxBuilder,
    sellers_claim_tx_builder: ForwardingTxBuilder,
    swap_tx_input_sighash: Option<TapSighash>,
    swap_tx_input_sig_ctx: SigCtx,
    buyers_warning_tx_buyer_input_sig_ctx: SigCtx,
    buyers_warning_tx_seller_input_sig_ctx: SigCtx,
    sellers_warning_tx_buyer_input_sig_ctx: SigCtx,
    sellers_warning_tx_seller_input_sig_ctx: SigCtx,
    buyers_redirect_tx_input_sig_ctx: SigCtx,
    sellers_redirect_tx_input_sig_ctx: SigCtx,
    buyers_claim_tx_input_sig_ctx: SigCtx,
    sellers_claim_tx_input_sig_ctx: SigCtx,
}

#[derive(Default, Eq, PartialEq)]
pub enum Role {
    #[default] SellerAsMaker,
    SellerAsTaker,
    BuyerAsMaker,
    BuyerAsTaker,
}

#[expect(clippy::struct_field_names,
reason = "not sure removing common postfix would make things clearer")] // TODO: Consider further.
pub struct ExchangedAddresses<'a, S: Storage, V: NetworkValidation + 'a = NetworkChecked> {
    pub warning_tx_fee_bump_address: S::Store<'a, Address<V>>,
    pub redirect_tx_fee_bump_address: S::Store<'a, Address<V>>,
    pub claim_tx_payout_address: S::Store<'a, Address<V>>,
}

impl<'a> ExchangedAddresses<'a, ByVal, NetworkUnchecked> {
    fn require_network(self, required: Network) -> Result<ExchangedAddresses<'a, ByVal>> {
        Ok(ExchangedAddresses {
            warning_tx_fee_bump_address: self.warning_tx_fee_bump_address.require_network(required)?,
            redirect_tx_fee_bump_address: self.redirect_tx_fee_bump_address.require_network(required)?,
            claim_tx_payout_address: self.claim_tx_payout_address.require_network(required)?,
        })
    }
}

#[expect(clippy::struct_field_names,
reason = "not sure removing common postfix would make things clearer")] // TODO: Consider further.
pub struct ExchangedNonces<'a, S: Storage> {
    pub swap_tx_input_nonce_share: S::Store<'a, PubNonce>,
    pub buyers_warning_tx_buyer_input_nonce_share: S::Store<'a, PubNonce>,
    pub buyers_warning_tx_seller_input_nonce_share: S::Store<'a, PubNonce>,
    pub sellers_warning_tx_buyer_input_nonce_share: S::Store<'a, PubNonce>,
    pub sellers_warning_tx_seller_input_nonce_share: S::Store<'a, PubNonce>,
    pub buyers_redirect_tx_input_nonce_share: S::Store<'a, PubNonce>,
    pub sellers_redirect_tx_input_nonce_share: S::Store<'a, PubNonce>,
    pub buyers_claim_tx_input_nonce_share: S::Store<'a, PubNonce>,
    pub sellers_claim_tx_input_nonce_share: S::Store<'a, PubNonce>,
}

pub struct ExchangedSigs<'a, S: Storage> {
    pub peers_warning_tx_buyer_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_warning_tx_seller_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_redirect_tx_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_claim_tx_input_partial_signature: S::Store<'a, PartialSignature>,
    pub swap_tx_input_partial_signature: Option<S::Store<'a, PartialSignature>>,
    pub swap_tx_input_sighash: Option<S::Store<'a, TapSighash>>,
}

impl TradeModel {
    pub fn new(trade_id: String, my_role: Role) -> Self {
        let mut trade_model = Self { trade_id, my_role, ..Default::default() };
        let am_buyer = trade_model.am_buyer();
        let network = trade_model.trade_wallet.insert(if am_buyer {
            Arc::new(Mutex::new(mock_buyer_trade_wallet()))
        } else {
            Arc::new(Mutex::new(mock_seller_trade_wallet()))
        }).lock().unwrap().network();
        trade_model.buyer_output_key_ctx.am_buyer = am_buyer;
        trade_model.seller_output_key_ctx.am_buyer = am_buyer;
        trade_model.swap_tx_builder.disable_lock_time();
        trade_model.buyers_warning_tx_builder.set_lock_time(network.warning_lock_time());
        trade_model.sellers_warning_tx_builder.set_lock_time(network.warning_lock_time());
        trade_model.buyers_redirect_tx_builder.set_lock_time(network.redirect_lock_time());
        trade_model.sellers_redirect_tx_builder.set_lock_time(network.redirect_lock_time());
        trade_model.buyers_claim_tx_builder.set_lock_time(network.claim_lock_time());
        trade_model.sellers_claim_tx_builder.set_lock_time(network.claim_lock_time());
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
        self.deposit_tx_builder.set_trade_amount(trade_amount);
    }

    pub fn set_buyers_security_deposit(&mut self, buyers_security_deposit: Amount) {
        self.deposit_tx_builder.set_buyers_security_deposit(buyers_security_deposit);
    }

    pub fn set_sellers_security_deposit(&mut self, sellers_security_deposit: Amount) {
        self.deposit_tx_builder.set_sellers_security_deposit(sellers_security_deposit);
    }

    pub fn set_deposit_tx_fee_rate(&mut self, fee_rate: FeeRate) {
        self.deposit_tx_builder.set_fee_rate(fee_rate);
    }

    pub fn set_prepared_tx_fee_rate(&mut self, fee_rate: FeeRate) {
        self.prepared_tx_fee_rate.get_or_insert(fee_rate);
        self.swap_tx_builder.set_fee_rate(fee_rate);
        self.buyers_warning_tx_builder.set_fee_rate(fee_rate);
        self.sellers_warning_tx_builder.set_fee_rate(fee_rate);
        self.buyers_claim_tx_builder.set_fee_rate(fee_rate);
        self.sellers_claim_tx_builder.set_fee_rate(fee_rate);
    }

    pub fn set_trade_fee_receiver(&mut self, receiver: Option<Receiver<NetworkUnchecked>>) -> Result<()> {
        let network = self.trade_wallet()?.network();
        self.deposit_tx_builder.set_trade_fee_receivers(receiver
            .map(|r| r.require_network(network)).transpose()?
            .into_iter().collect());
        Ok(())
    }

    pub fn redirection_amount_msat(&self) -> Option<u64> {
        let split_input_amounts = [
            *self.deposit_tx_builder.trade_amount().ok()?,
            *self.deposit_tx_builder.buyers_security_deposit().ok()?,
            *self.deposit_tx_builder.sellers_security_deposit().ok()?,
        ];
        let escrow_amount =
            WarningTxBuilder::escrow_amount(split_input_amounts, self.prepared_tx_fee_rate?)?;

        RedirectTxBuilder::available_amount_msat(escrow_amount, self.prepared_tx_fee_rate?)
    }

    pub fn init_my_key_shares(&mut self) -> Result<()> {
        let network = self.trade_wallet()?.network();
        let buyer_output_pub_key = self.buyer_output_key_ctx.init_my_key_share().pub_key;
        let seller_output_pub_key = self.seller_output_key_ctx.init_my_key_share().pub_key;
        if self.am_buyer() {
            self.buyers_redirect_tx_input_sig_ctx.set_warning_output_merkle_root(&seller_output_pub_key, network);
            self.sellers_claim_tx_input_sig_ctx.set_warning_output_merkle_root(&seller_output_pub_key, network);
        } else {
            self.swap_tx_input_sig_ctx.adaptor_point = MaybePoint::Valid(buyer_output_pub_key);
            self.sellers_redirect_tx_input_sig_ctx.set_warning_output_merkle_root(&buyer_output_pub_key, network);
            self.buyers_claim_tx_input_sig_ctx.set_warning_output_merkle_root(&buyer_output_pub_key, network);
        }
        Ok(())
    }

    pub fn get_my_key_shares(&self) -> Option<[&KeyPair; 2]> {
        Some([
            self.buyer_output_key_ctx.my_key_share.as_ref()?,
            self.seller_output_key_ctx.my_key_share.as_ref()?
        ])
    }

    pub fn set_peer_key_shares(&mut self, buyer_output_pub_key: Point, seller_output_pub_key: Point) -> Result<()> {
        let network = self.trade_wallet()?.network();
        self.buyer_output_key_ctx.peers_key_share = Some(OptKeyPair::from_public(buyer_output_pub_key));
        self.seller_output_key_ctx.peers_key_share = Some(OptKeyPair::from_public(seller_output_pub_key));
        if self.am_buyer() {
            // TODO: Should check that signing hasn't already begun before setting an adaptor point.
            self.swap_tx_input_sig_ctx.adaptor_point = MaybePoint::Valid(buyer_output_pub_key);
            self.sellers_redirect_tx_input_sig_ctx.set_warning_output_merkle_root(&buyer_output_pub_key, network);
            self.buyers_claim_tx_input_sig_ctx.set_warning_output_merkle_root(&buyer_output_pub_key, network);
        } else {
            self.buyers_redirect_tx_input_sig_ctx.set_warning_output_merkle_root(&seller_output_pub_key, network);
            self.sellers_claim_tx_input_sig_ctx.set_warning_output_merkle_root(&seller_output_pub_key, network);
        }
        Ok(())
    }

    pub fn aggregate_key_shares(&mut self) -> Result<()> {
        let network = self.trade_wallet()?.network();
        self.buyer_output_key_ctx.aggregate_key_shares()?;
        self.seller_output_key_ctx.aggregate_key_shares()?;

        let buyer_payout_address = self.buyer_output_key_ctx.compute_p2tr_address(None, network)?;
        let seller_payout_address = self.seller_output_key_ctx.compute_p2tr_address(None, network)?;
        self.deposit_tx_builder.set_buyer_payout_address(buyer_payout_address);
        self.deposit_tx_builder.set_seller_payout_address(seller_payout_address);

        // FIXME: A little hacky to pull the merkle root from redirect tx SigCtx -- refactor:
        let buyers_warning_output_merkle_root = self.sellers_redirect_tx_input_sig_ctx.merkle_root.as_ref();
        let sellers_warning_output_merkle_root = self.buyers_redirect_tx_input_sig_ctx.merkle_root.as_ref();

        let buyers_warning_escrow_address = self.seller_output_key_ctx.compute_p2tr_address(
            buyers_warning_output_merkle_root, network)?;
        let sellers_warning_escrow_address = self.buyer_output_key_ctx.compute_p2tr_address(
            sellers_warning_output_merkle_root, network)?;
        self.buyers_warning_tx_builder.set_escrow_address(buyers_warning_escrow_address);
        self.sellers_warning_tx_builder.set_escrow_address(sellers_warning_escrow_address);
        Ok(())
    }

    pub fn init_my_addresses(&mut self) -> Result<()> {
        let mut wallet = self.trade_wallet()?;
        if self.am_buyer() {
            self.buyers_warning_tx_builder.set_anchor_address(wallet.new_address()?);
            self.buyers_redirect_tx_builder.set_anchor_address(wallet.new_address()?);
            self.buyers_claim_tx_builder.set_payout_address(wallet.new_address()?);
        } else {
            self.sellers_warning_tx_builder.set_anchor_address(wallet.new_address()?);
            self.sellers_redirect_tx_builder.set_anchor_address(wallet.new_address()?);
            self.sellers_claim_tx_builder.set_payout_address(wallet.new_address()?);
            self.swap_tx_builder.set_payout_address(wallet.new_address()?);
        }
        drop(wallet);
        Ok(())
    }

    pub fn get_my_addresses(&self) -> Option<ExchangedAddresses<'_, ByRef>> {
        Some(if self.am_buyer() {
            ExchangedAddresses {
                warning_tx_fee_bump_address: self.buyers_warning_tx_builder.anchor_address().ok()?,
                redirect_tx_fee_bump_address: self.buyers_redirect_tx_builder.anchor_address().ok()?,
                claim_tx_payout_address: self.buyers_claim_tx_builder.payout_address().ok()?,
            }
        } else {
            ExchangedAddresses {
                warning_tx_fee_bump_address: self.sellers_warning_tx_builder.anchor_address().ok()?,
                redirect_tx_fee_bump_address: self.sellers_redirect_tx_builder.anchor_address().ok()?,
                claim_tx_payout_address: self.sellers_claim_tx_builder.payout_address().ok()?,
            }
        })
    }

    pub fn set_peer_addresses(&mut self, addresses: ExchangedAddresses<ByVal, NetworkUnchecked>) -> Result<()> {
        let addresses = addresses.require_network(self.trade_wallet()?.network())?;
        if self.am_buyer() {
            self.sellers_warning_tx_builder.set_anchor_address(addresses.warning_tx_fee_bump_address);
            self.sellers_redirect_tx_builder.set_anchor_address(addresses.redirect_tx_fee_bump_address);
            self.sellers_claim_tx_builder.set_payout_address(addresses.claim_tx_payout_address);
        } else {
            self.buyers_warning_tx_builder.set_anchor_address(addresses.warning_tx_fee_bump_address);
            self.buyers_redirect_tx_builder.set_anchor_address(addresses.redirect_tx_fee_bump_address);
            self.buyers_claim_tx_builder.set_payout_address(addresses.claim_tx_payout_address);
        }
        Ok(())
    }

    pub fn init_my_half_deposit_psbt(&mut self) -> Result<()> {
        if self.am_buyer() {
            self.deposit_tx_builder.init_buyers_half_psbt(&mut *self.trade_wallet()?, &mut rand::rng())?;
        } else {
            self.deposit_tx_builder.init_sellers_half_psbt(&mut *self.trade_wallet()?, &mut rand::rng())?;
        }
        Ok(())
    }

    pub fn get_my_half_deposit_psbt(&self) -> Option<&Psbt> {
        if self.am_buyer() {
            self.deposit_tx_builder.buyers_half_psbt().ok()
        } else {
            self.deposit_tx_builder.sellers_half_psbt().ok()
        }
    }

    pub fn set_peer_half_deposit_psbt(&mut self, half_deposit_psbt: Psbt) {
        if self.am_buyer() {
            self.deposit_tx_builder.set_sellers_half_psbt(half_deposit_psbt);
        } else {
            self.deposit_tx_builder.set_buyers_half_psbt(half_deposit_psbt);
        }
    }

    pub fn compute_unsigned_deposit_tx(&mut self) -> Result<()> {
        self.deposit_tx_builder.compute_unsigned_tx()?;
        let buyer_payout = self.deposit_tx_builder.buyer_payout()?;
        let seller_payout = self.deposit_tx_builder.seller_payout()?;

        self.swap_tx_builder.set_input(seller_payout.clone());
        self.buyers_warning_tx_builder.set_buyer_input(buyer_payout.clone());
        self.buyers_warning_tx_builder.set_seller_input(seller_payout.clone());
        self.sellers_warning_tx_builder.set_buyer_input(buyer_payout.clone());
        self.sellers_warning_tx_builder.set_seller_input(seller_payout.clone());
        Ok(())
    }

    pub fn compute_unsigned_prepared_txs(&mut self) -> Result<()> {
        if !self.am_buyer() {
            // Only the seller has all the params necessary to compute the unsigned swap tx.
            self.swap_tx_builder.compute_unsigned_tx()?;
        }
        self.buyers_warning_tx_builder.compute_unsigned_tx()?;
        self.sellers_warning_tx_builder.compute_unsigned_tx()?;
        let buyers_warning_escrow = self.buyers_warning_tx_builder.escrow()?;
        let sellers_warning_escrow = self.sellers_warning_tx_builder.escrow()?;

        self.buyers_redirect_tx_builder.set_input(sellers_warning_escrow.clone());
        self.sellers_redirect_tx_builder.set_input(buyers_warning_escrow.clone());
        self.buyers_claim_tx_builder.set_input(buyers_warning_escrow);
        self.sellers_claim_tx_builder.set_input(sellers_warning_escrow);

        self.buyers_redirect_tx_builder.compute_unsigned_tx()?;
        self.sellers_redirect_tx_builder.compute_unsigned_tx()?;
        self.buyers_claim_tx_builder.compute_unsigned_tx()?;
        self.sellers_claim_tx_builder.compute_unsigned_tx()?;
        Ok(())
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
        self.buyers_redirect_tx_builder.set_receivers(receivers.clone());
        self.sellers_redirect_tx_builder.set_receivers(receivers);
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
        for ctx in [
            &mut self.buyers_warning_tx_buyer_input_sig_ctx,
            &mut self.sellers_warning_tx_buyer_input_sig_ctx,
            &mut self.buyers_redirect_tx_input_sig_ctx,
            &mut self.sellers_claim_tx_input_sig_ctx
        ] {
            ctx.init_my_nonce_share(&self.buyer_output_key_ctx)?;
        }
        for ctx in [
            &mut self.swap_tx_input_sig_ctx,
            &mut self.buyers_warning_tx_seller_input_sig_ctx,
            &mut self.sellers_warning_tx_seller_input_sig_ctx,
            &mut self.sellers_redirect_tx_input_sig_ctx,
            &mut self.buyers_claim_tx_input_sig_ctx
        ] {
            ctx.init_my_nonce_share(&self.seller_output_key_ctx)?;
        }
        Ok(())
    }

    pub fn get_my_nonce_shares(&self) -> Option<ExchangedNonces<'_, ByRef>> {
        Some(ExchangedNonces {
            swap_tx_input_nonce_share:
            &(self.swap_tx_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            buyers_warning_tx_buyer_input_nonce_share:
            &(self.buyers_warning_tx_buyer_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            buyers_warning_tx_seller_input_nonce_share:
            &(self.buyers_warning_tx_seller_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            sellers_warning_tx_buyer_input_nonce_share:
            &(self.sellers_warning_tx_buyer_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            sellers_warning_tx_seller_input_nonce_share:
            &(self.sellers_warning_tx_seller_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            buyers_redirect_tx_input_nonce_share:
            &(self.buyers_redirect_tx_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            sellers_redirect_tx_input_nonce_share:
            &(self.sellers_redirect_tx_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            buyers_claim_tx_input_nonce_share:
            &(self.buyers_claim_tx_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
            sellers_claim_tx_input_nonce_share:
            &(self.sellers_claim_tx_input_sig_ctx.my_nonce_share.as_ref()?.pub_nonce),
        })
    }

    pub const fn set_peer_nonce_shares(&mut self, nonce_shares: ExchangedNonces<ByVal>) {
        self.swap_tx_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.swap_tx_input_nonce_share);
        self.buyers_warning_tx_buyer_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.buyers_warning_tx_buyer_input_nonce_share);
        self.buyers_warning_tx_seller_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.buyers_warning_tx_seller_input_nonce_share);
        self.sellers_warning_tx_buyer_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.sellers_warning_tx_buyer_input_nonce_share);
        self.sellers_warning_tx_seller_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.sellers_warning_tx_seller_input_nonce_share);
        self.buyers_redirect_tx_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.buyers_redirect_tx_input_nonce_share);
        self.sellers_redirect_tx_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.sellers_redirect_tx_input_nonce_share);
        self.buyers_claim_tx_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.buyers_claim_tx_input_nonce_share);
        self.sellers_claim_tx_input_sig_ctx.peers_nonce_share =
            Some(nonce_shares.sellers_claim_tx_input_nonce_share);
    }

    pub fn aggregate_nonce_shares(&mut self) -> Result<()> {
        self.swap_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_warning_tx_buyer_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_warning_tx_seller_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_warning_tx_buyer_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_warning_tx_seller_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_redirect_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_redirect_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_claim_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_claim_tx_input_sig_ctx.aggregate_nonce_shares()?;
        Ok(())
    }

    pub fn sign_partial(&mut self) -> Result<()> {
        let [buyer_key_ctx, seller_key_ctx] = [&self.buyer_output_key_ctx, &self.seller_output_key_ctx];

        self.buyers_warning_tx_buyer_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.buyers_warning_tx_builder.buyer_input_sighash()?)?;
        self.sellers_warning_tx_buyer_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.sellers_warning_tx_builder.buyer_input_sighash()?)?;
        self.buyers_redirect_tx_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.buyers_redirect_tx_builder.input_sighash()?)?;
        self.sellers_claim_tx_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.sellers_claim_tx_builder.input_sighash()?)?;

        self.buyers_warning_tx_seller_input_sig_ctx
            .sign_partial(seller_key_ctx, self.buyers_warning_tx_builder.seller_input_sighash()?)?;
        self.sellers_warning_tx_seller_input_sig_ctx
            .sign_partial(seller_key_ctx, self.sellers_warning_tx_builder.seller_input_sighash()?)?;
        self.sellers_redirect_tx_input_sig_ctx
            .sign_partial(seller_key_ctx, self.sellers_redirect_tx_builder.input_sighash()?)?;
        self.buyers_claim_tx_input_sig_ctx
            .sign_partial(seller_key_ctx, self.buyers_claim_tx_builder.input_sighash()?)?;

        if !self.am_buyer() {
            // Unlike the other multisig sighashes, only the seller is able to independently compute
            // the swap-tx-input sighash. The buyer must wait for the next round, when the deposit
            // tx is signed, to partially sign the swap tx using the sighash passed by the seller.
            self.sign_swap_tx_input_partial(self.swap_tx_builder.input_sighash()?)?;
        }
        Ok(())
    }

    pub fn sign_swap_tx_input_partial(&mut self, sighash: TapSighash) -> Result<()> {
        let sighash = self.swap_tx_input_sighash.insert(sighash);
        self.swap_tx_input_sig_ctx
            .sign_partial(&self.seller_output_key_ctx, *sighash)?;
        Ok(())
    }

    pub fn get_my_partial_signatures_on_peer_txs(&self, buyer_ready_to_release: bool) -> Option<ExchangedSigs<'_, ByRef>> {
        Some(if self.am_buyer() {
            ExchangedSigs {
                peers_warning_tx_buyer_input_partial_signature: self.sellers_warning_tx_buyer_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_warning_tx_seller_input_partial_signature: self.sellers_warning_tx_seller_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_redirect_tx_input_partial_signature: self.sellers_redirect_tx_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_claim_tx_input_partial_signature: self.sellers_claim_tx_input_sig_ctx.my_partial_sig.as_ref()?,
                swap_tx_input_partial_signature: self.swap_tx_input_sig_ctx.my_partial_sig.as_ref().filter(|_| buyer_ready_to_release),
                swap_tx_input_sighash: self.swap_tx_input_sighash.as_ref(),
            }
        } else {
            ExchangedSigs {
                peers_warning_tx_buyer_input_partial_signature: self.buyers_warning_tx_buyer_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_warning_tx_seller_input_partial_signature: self.buyers_warning_tx_seller_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_redirect_tx_input_partial_signature: self.buyers_redirect_tx_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_claim_tx_input_partial_signature: self.buyers_claim_tx_input_sig_ctx.my_partial_sig.as_ref()?,
                swap_tx_input_partial_signature: self.swap_tx_input_sig_ctx.my_partial_sig.as_ref(),
                swap_tx_input_sighash: self.swap_tx_input_sighash.as_ref(),
            }
        })
    }

    pub const fn set_peer_partial_signatures_on_my_txs(&mut self, sigs: &ExchangedSigs<ByVal>) {
        if self.am_buyer() {
            self.buyers_warning_tx_buyer_input_sig_ctx.peers_partial_sig = Some(sigs.peers_warning_tx_buyer_input_partial_signature);
            self.buyers_warning_tx_seller_input_sig_ctx.peers_partial_sig = Some(sigs.peers_warning_tx_seller_input_partial_signature);
            self.buyers_redirect_tx_input_sig_ctx.peers_partial_sig = Some(sigs.peers_redirect_tx_input_partial_signature);
            self.buyers_claim_tx_input_sig_ctx.peers_partial_sig = Some(sigs.peers_claim_tx_input_partial_signature);
        } else {
            self.sellers_warning_tx_buyer_input_sig_ctx.peers_partial_sig = Some(sigs.peers_warning_tx_buyer_input_partial_signature);
            self.sellers_warning_tx_seller_input_sig_ctx.peers_partial_sig = Some(sigs.peers_warning_tx_seller_input_partial_signature);
            self.sellers_redirect_tx_input_sig_ctx.peers_partial_sig = Some(sigs.peers_redirect_tx_input_partial_signature);
            self.sellers_claim_tx_input_sig_ctx.peers_partial_sig = Some(sigs.peers_claim_tx_input_partial_signature);
        }
        // NOTE: This passed field would normally be 'None' for the seller, as the buyer should redact the field
        // at the trade start and reveal it later, after payment is started, to prevent premature trade closure:
        self.swap_tx_input_sig_ctx.peers_partial_sig = sigs.swap_tx_input_partial_signature;
    }

    pub fn aggregate_partial_signatures(&mut self) -> Result<()> {
        if self.am_buyer() {
            self.buyers_warning_tx_buyer_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
            self.buyers_warning_tx_seller_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
            self.buyers_redirect_tx_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
            self.buyers_claim_tx_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;

            // This forms a validated adaptor signature on the swap tx for the buyer, ensuring that the seller's
            // private key share is revealed if the swap tx is published. The seller doesn't get the full adaptor
            // signature (or the ordinary signature) until later on in the trade, when the buyer confirms payment:
            self.swap_tx_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
        } else {
            self.sellers_warning_tx_buyer_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
            self.sellers_warning_tx_seller_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
            self.sellers_redirect_tx_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
            self.sellers_claim_tx_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
        }
        Ok(())
    }

    pub fn compute_my_signed_prepared_txs(&mut self) -> Result<()> {
        use MaybeScalar::Zero;
        if self.am_buyer() {
            self.buyers_warning_tx_builder
                .set_buyer_input_signature(self.buyers_warning_tx_buyer_input_sig_ctx.compute_taproot_signature(Zero)?)
                .set_seller_input_signature(self.buyers_warning_tx_seller_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
            self.buyers_redirect_tx_builder
                .set_input_signature(self.buyers_redirect_tx_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
            self.buyers_claim_tx_builder
                .set_input_signature(self.buyers_claim_tx_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
        } else {
            self.sellers_warning_tx_builder
                .set_buyer_input_signature(self.sellers_warning_tx_buyer_input_sig_ctx.compute_taproot_signature(Zero)?)
                .set_seller_input_signature(self.sellers_warning_tx_seller_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
            self.sellers_redirect_tx_builder
                .set_input_signature(self.sellers_redirect_tx_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
            self.sellers_claim_tx_builder
                .set_input_signature(self.sellers_claim_tx_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
        }
        Ok(())
    }

    pub fn sign_deposit_psbt(&mut self) -> Result<()> {
        // Check that we have all the prepared tx data we need:
        if self.am_buyer() {
            self.buyers_warning_tx_builder.signed_tx()?;
            self.buyers_redirect_tx_builder.signed_tx()?;
            self.buyers_claim_tx_builder.signed_tx()?;
            self.swap_tx_input_sig_ctx.aggregated_sig()?;
        } else {
            self.sellers_warning_tx_builder.signed_tx()?;
            self.sellers_redirect_tx_builder.signed_tx()?;
            self.sellers_claim_tx_builder.signed_tx()?;
        }
        // FIXME: This is the first point in the protocol that a real commitment is made.
        //  It is CRITICAL that the trade data is persisted and backed up at this point.
        if self.am_buyer() {
            self.deposit_tx_builder.sign_buyer_inputs(&*self.trade_wallet()?)?;
        } else {
            self.deposit_tx_builder.sign_seller_inputs(&*self.trade_wallet()?)?;
        }
        Ok(())
    }

    pub fn get_deposit_psbt(&self) -> Option<&Psbt> {
        self.deposit_tx_builder.psbt().ok()
    }

    pub fn combine_deposit_psbts(&mut self, other: Psbt) -> Result<()> {
        self.deposit_tx_builder.combine_psbts(other)?;
        Ok(())
    }

    pub fn get_signed_deposit_tx(&self) -> Option<Transaction> {
        self.deposit_tx_builder.signed_tx().ok()
    }

    pub const fn set_swap_tx_input_peers_partial_signature(&mut self, sig: PartialSignature) {
        self.swap_tx_input_sig_ctx.peers_partial_sig = Some(sig);
    }

    pub fn aggregate_swap_tx_partial_signatures(&mut self) -> Result<()> {
        let my_key_ctx = if self.am_buyer() {
            &self.buyer_output_key_ctx
        } else {
            &self.seller_output_key_ctx
        };
        self.swap_tx_input_sig_ctx.aggregate_partial_signatures(my_key_ctx)?;
        Ok(())
    }

    pub fn get_my_private_key_share_for_peer_output(&self) -> Option<&Scalar> {
        // TODO: Check that it's actually safe to release the funds at this point.
        let peer_key_ctx = if self.am_buyer() {
            &self.seller_output_key_ctx
        } else {
            &self.buyer_output_key_ctx
        };
        Some(&peer_key_ctx.my_key_share.as_ref()?.prv_key)
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
        if !self.am_buyer() {
            let adaptor_secret = self.buyer_output_key_ctx.my_prv_key()?.into();
            self.swap_tx_builder
                .set_input_signature(self.swap_tx_input_sig_ctx.compute_taproot_signature(adaptor_secret)?)
                .compute_signed_tx()?;
        }
        Ok(())
    }

    pub fn get_signed_swap_tx(&self) -> Option<&Transaction> {
        self.swap_tx_builder.signed_tx().ok()
    }

    pub fn recover_seller_private_key_share_for_buyer_output(&mut self, swap_tx: &Transaction) -> Result<()> {
        if self.am_buyer() {
            let swap_tx_input = self.deposit_tx_builder.seller_payout()?;
            let input_signature = swap_tx.find_key_spend_signature(swap_tx_input)?;
            let adaptor_secret = self.swap_tx_input_sig_ctx.reveal_adaptor_secret(input_signature)?;
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
