use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::key::TweakedPublicKey;
use bdk_wallet::bitcoin::taproot::Signature;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, Network, Psbt, PublicKey, TapNodeHash, TapSighash, Transaction,
};
use guardian::ArcMutexGuardian;
use musig2::adaptor::AdaptorSignature;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, LiftedSignature, NonceSeed, PartialSignature, PubNonce, SecNonce,
    SecNonceBuilder,
};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};
use thiserror::Error;
use tracing::{error, instrument, warn};

use crate::psbt::{mock_buyer_trade_wallet, mock_seller_trade_wallet, TradeWallet};
use crate::storage::{ByOptVal, ByRef, ByVal, Storage, ValStorage};
use crate::transaction::{
    DepositTxBuilder, ForwardingTxBuilder, NetworkParams as _, Receiver, ReceiverList,
    RedirectTxBuilder, WarningTxBuilder, WithWitnesses as _, ANCHOR_AMOUNT,
    SIGNED_REDIRECT_TX_BASE_WEIGHT,
};

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
    pub claim_tx_payout_address: Option<S::Store<'a, Address<V>>>,
}

impl<'a> ExchangedAddresses<'a, ByVal, NetworkUnchecked> {
    fn require_network(self, required: Network) -> Result<ExchangedAddresses<'a, ByVal>> {
        Ok(ExchangedAddresses {
            warning_tx_fee_bump_address: self.warning_tx_fee_bump_address.require_network(required)?,
            redirect_tx_fee_bump_address: self.redirect_tx_fee_bump_address.require_network(required)?,
            claim_tx_payout_address: self.claim_tx_payout_address
                .map(|a| a.require_network(required)).transpose()?,
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
    pub buyers_claim_tx_input_nonce_share: Option<S::Store<'a, PubNonce>>,
    pub sellers_claim_tx_input_nonce_share: Option<S::Store<'a, PubNonce>>,
}

pub struct ExchangedSigs<'a, S: Storage> {
    pub peers_warning_tx_buyer_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_warning_tx_seller_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_redirect_tx_input_partial_signature: S::Store<'a, PartialSignature>,
    pub peers_claim_tx_input_partial_signature: Option<S::Store<'a, PartialSignature>>,
    pub swap_tx_input_partial_signature: Option<S::Store<'a, PartialSignature>>,
    pub swap_tx_input_sighash: Option<S::Store<'a, TapSighash>>,
}

pub struct KeyPair<PrvKey: ValStorage = ByVal> {
    pub pub_key: Point,
    pub prv_key: PrvKey::Store<Scalar>,
}

pub struct NoncePair {
    pub pub_nonce: PubNonce,
    pub sec_nonce: Option<SecNonce>,
}

#[derive(Default)]
struct KeyCtx {
    am_buyer: bool,
    my_key_share: Option<KeyPair>,
    peers_key_share: Option<KeyPair<ByOptVal>>,
    aggregated_key: Option<KeyPair<ByOptVal>>,
    key_agg_ctx: Option<KeyAggContext>,
}

// TODO: For safety, this should hold a reference to the KeyCtx our nonce & signature share (& final
//  aggregation) are built from, so that we don't have to pass it repeatedly as a method parameter.
#[derive(Default)]
struct SigCtx {
    am_buyer: bool,
    merkle_root: Option<TapNodeHash>,
    adaptor_point: MaybePoint,
    my_nonce_share: Option<NoncePair>,
    peers_nonce_share: Option<PubNonce>,
    aggregated_nonce: Option<AggNonce>,
    message: Option<TapSighash>,
    my_partial_sig: Option<PartialSignature>,
    peers_partial_sig: Option<PartialSignature>,
    aggregated_sig: Option<AdaptorSignature>,
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
        trade_model.swap_tx_input_sig_ctx.am_buyer = am_buyer;
        trade_model.buyers_warning_tx_buyer_input_sig_ctx.am_buyer = am_buyer;
        trade_model.buyers_warning_tx_seller_input_sig_ctx.am_buyer = am_buyer;
        trade_model.sellers_warning_tx_buyer_input_sig_ctx.am_buyer = am_buyer;
        trade_model.sellers_warning_tx_seller_input_sig_ctx.am_buyer = am_buyer;
        trade_model.buyers_redirect_tx_input_sig_ctx.am_buyer = am_buyer;
        trade_model.sellers_redirect_tx_input_sig_ctx.am_buyer = am_buyer;
        trade_model.buyers_claim_tx_input_sig_ctx.am_buyer = am_buyer;
        trade_model.sellers_claim_tx_input_sig_ctx.am_buyer = am_buyer;
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
        // TODO: Should this logic be moved into `transaction`?
        let split_input_amounts = [
            *self.deposit_tx_builder.trade_amount().ok()?,
            *self.deposit_tx_builder.buyers_security_deposit().ok()?,
            *self.deposit_tx_builder.sellers_security_deposit().ok()?,
        ];
        let redirection_tx_base_fee = self.prepared_tx_fee_rate?.to_sat_per_kwu()
            .checked_mul(SIGNED_REDIRECT_TX_BASE_WEIGHT.to_wu())?;

        WarningTxBuilder::escrow_amount(split_input_amounts, self.prepared_tx_fee_rate?)?
            .checked_sub(ANCHOR_AMOUNT)?
            .to_sat().checked_mul(1000)?
            .checked_sub(redirection_tx_base_fee)
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
        self.buyer_output_key_ctx.peers_key_share = Some(KeyPair::from_public(buyer_output_pub_key));
        self.seller_output_key_ctx.peers_key_share = Some(KeyPair::from_public(seller_output_pub_key));
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
                claim_tx_payout_address: self.buyers_claim_tx_builder.payout_address().ok(),
            }
        } else {
            ExchangedAddresses {
                warning_tx_fee_bump_address: self.sellers_warning_tx_builder.anchor_address().ok()?,
                redirect_tx_fee_bump_address: self.sellers_redirect_tx_builder.anchor_address().ok()?,
                claim_tx_payout_address: self.sellers_claim_tx_builder.payout_address().ok(),
            }
        })
    }

    pub fn set_peer_addresses(&mut self, addresses: ExchangedAddresses<ByVal, NetworkUnchecked>) -> Result<()> {
        let addresses = addresses.require_network(self.trade_wallet()?.network())?;
        if self.am_buyer() {
            self.sellers_warning_tx_builder.set_anchor_address(addresses.warning_tx_fee_bump_address);
            self.sellers_redirect_tx_builder.set_anchor_address(addresses.redirect_tx_fee_bump_address);
            if let Some(payout_address) = addresses.claim_tx_payout_address {
                self.sellers_claim_tx_builder.set_payout_address(payout_address);
            }
        } else {
            self.buyers_warning_tx_builder.set_anchor_address(addresses.warning_tx_fee_bump_address);
            self.buyers_redirect_tx_builder.set_anchor_address(addresses.redirect_tx_fee_bump_address);
            if let Some(payout_address) = addresses.claim_tx_payout_address {
                self.buyers_claim_tx_builder.set_payout_address(payout_address);
            }
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

        // Only compute the unsigned claim txs if _both_ claim payout addresses are set, to avoid breaking
        // the Bisq2 client, until it has been updated to exchange the extra claim-tx-related fields.
        if self.buyers_claim_tx_builder.payout_address().is_ok() && self.sellers_claim_tx_builder.payout_address().is_ok() {
            self.buyers_claim_tx_builder.compute_unsigned_tx()?;
            self.sellers_claim_tx_builder.compute_unsigned_tx()?;
        }
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

    #[instrument(skip_all)]
    pub fn check_redirect_tx_params(&self) -> Result<()> {
        // FIXME: Don't falsely report overflows & invalid params as missing-param errors:
        let receivers = &self.redirection_receivers.as_ref()
            .ok_or(ProtocolErrorKind::MissingTxParams)?[..];
        let fee_rate = self.prepared_tx_fee_rate
            .ok_or(ProtocolErrorKind::MissingTxParams)?;
        let expected_redirection_amount_msat = self.redirection_amount_msat()
            .ok_or(ProtocolErrorKind::MissingTxParams)?;
        let actual_redirection_amount_msat = Receiver::total_output_cost_msat(receivers, fee_rate, 1)
            .ok_or(ProtocolErrorKind::MissingTxParams)?;

        // For now, just log the amount-check failures, to give the Bisq2 client a chance to update.
        // TODO: Make these both hard errors:
        if actual_redirection_amount_msat > expected_redirection_amount_msat {
            error!(expected_redirection_amount_msat, actual_redirection_amount_msat,
                "Insufficient redirection funds.");
        }
        if actual_redirection_amount_msat.saturating_add(999) < expected_redirection_amount_msat {
            warn!(expected_redirection_amount_msat, actual_redirection_amount_msat,
                "Excess redirection funds.");
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
            self.buyers_claim_tx_input_sig_ctx.my_nonce_share.as_ref().map(|n| &n.pub_nonce),
            sellers_claim_tx_input_nonce_share:
            self.sellers_claim_tx_input_sig_ctx.my_nonce_share.as_ref().map(|n| &n.pub_nonce),
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
            nonce_shares.buyers_claim_tx_input_nonce_share;
        self.sellers_claim_tx_input_sig_ctx.peers_nonce_share =
            nonce_shares.sellers_claim_tx_input_nonce_share;
    }

    #[instrument(skip_all)]
    pub fn aggregate_nonce_shares(&mut self) -> Result<()> {
        self.swap_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_warning_tx_buyer_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_warning_tx_seller_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_warning_tx_buyer_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_warning_tx_seller_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_redirect_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.sellers_redirect_tx_input_sig_ctx.aggregate_nonce_shares()?;
        self.buyers_claim_tx_input_sig_ctx.aggregate_nonce_shares()
            .map_or_else(ProtocolErrorKind::skip_missing, |_| Ok(()))?;
        self.sellers_claim_tx_input_sig_ctx.aggregate_nonce_shares()
            .map_or_else(ProtocolErrorKind::skip_missing, |_| Ok(()))?;
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn sign_partial(&mut self) -> Result<()> {
        let [buyer_key_ctx, seller_key_ctx] = [&self.buyer_output_key_ctx, &self.seller_output_key_ctx];

        self.buyers_warning_tx_buyer_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.buyers_warning_tx_builder.buyer_input_sighash()?)?;
        self.sellers_warning_tx_buyer_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.sellers_warning_tx_builder.buyer_input_sighash()?)?;
        self.buyers_redirect_tx_input_sig_ctx
            .sign_partial(buyer_key_ctx, self.buyers_redirect_tx_builder.input_sighash()?)?;
        self.sellers_claim_tx_input_sig_ctx
            .sign_partial_opt(buyer_key_ctx, self.sellers_claim_tx_builder.input_sighash().ok())
            .map_or_else(ProtocolErrorKind::skip_missing, |_| Ok(()))?;

        self.buyers_warning_tx_seller_input_sig_ctx
            .sign_partial(seller_key_ctx, self.buyers_warning_tx_builder.seller_input_sighash()?)?;
        self.sellers_warning_tx_seller_input_sig_ctx
            .sign_partial(seller_key_ctx, self.sellers_warning_tx_builder.seller_input_sighash()?)?;
        self.sellers_redirect_tx_input_sig_ctx
            .sign_partial(seller_key_ctx, self.sellers_redirect_tx_builder.input_sighash()?)?;
        self.buyers_claim_tx_input_sig_ctx
            .sign_partial_opt(seller_key_ctx, self.buyers_claim_tx_builder.input_sighash().ok())
            .map_or_else(ProtocolErrorKind::skip_missing, |_| Ok(()))?;

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
                peers_claim_tx_input_partial_signature: self.sellers_claim_tx_input_sig_ctx.my_partial_sig.as_ref(),
                swap_tx_input_partial_signature: self.swap_tx_input_sig_ctx.my_partial_sig.as_ref().filter(|_| buyer_ready_to_release),
                swap_tx_input_sighash: self.swap_tx_input_sighash.as_ref(),
            }
        } else {
            ExchangedSigs {
                peers_warning_tx_buyer_input_partial_signature: self.buyers_warning_tx_buyer_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_warning_tx_seller_input_partial_signature: self.buyers_warning_tx_seller_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_redirect_tx_input_partial_signature: self.buyers_redirect_tx_input_sig_ctx.my_partial_sig.as_ref()?,
                peers_claim_tx_input_partial_signature: self.buyers_claim_tx_input_sig_ctx.my_partial_sig.as_ref(),
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
            self.buyers_claim_tx_input_sig_ctx.peers_partial_sig = sigs.peers_claim_tx_input_partial_signature;
        } else {
            self.sellers_warning_tx_buyer_input_sig_ctx.peers_partial_sig = Some(sigs.peers_warning_tx_buyer_input_partial_signature);
            self.sellers_warning_tx_seller_input_sig_ctx.peers_partial_sig = Some(sigs.peers_warning_tx_seller_input_partial_signature);
            self.sellers_redirect_tx_input_sig_ctx.peers_partial_sig = Some(sigs.peers_redirect_tx_input_partial_signature);
            self.sellers_claim_tx_input_sig_ctx.peers_partial_sig = sigs.peers_claim_tx_input_partial_signature;
        }
        // NOTE: This passed field would normally be 'None' for the seller, as the buyer should redact the field
        // at the trade start and reveal it later, after payment is started, to prevent premature trade closure:
        self.swap_tx_input_sig_ctx.peers_partial_sig = sigs.swap_tx_input_partial_signature;
    }

    #[instrument(skip_all)]
    pub fn aggregate_partial_signatures(&mut self) -> Result<()> {
        if self.am_buyer() {
            self.buyers_warning_tx_buyer_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
            self.buyers_warning_tx_seller_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
            self.buyers_redirect_tx_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
            self.buyers_claim_tx_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)
                .map_or_else(ProtocolErrorKind::skip_missing, |_| Ok(()))?;

            // This forms a validated adaptor signature on the swap tx for the buyer, ensuring that the seller's
            // private key share is revealed if the swap tx is published. The seller doesn't get the full adaptor
            // signature (or the ordinary signature) until later on in the trade, when the buyer confirms payment:
            self.swap_tx_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
        } else {
            self.sellers_warning_tx_buyer_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)?;
            self.sellers_warning_tx_seller_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
            self.sellers_redirect_tx_input_sig_ctx.aggregate_partial_signatures(&self.seller_output_key_ctx)?;
            self.sellers_claim_tx_input_sig_ctx.aggregate_partial_signatures(&self.buyer_output_key_ctx)
                .map_or_else(ProtocolErrorKind::skip_missing, |_| Ok(()))?;
        }
        Ok(())
    }

    #[instrument(skip_all)]
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
            self.buyers_claim_tx_input_sig_ctx.compute_taproot_signature(Zero)
                .map_or_else(ProtocolErrorKind::skip_missing, |sig| {
                    self.buyers_claim_tx_builder.set_input_signature(sig).compute_signed_tx()?;
                    Ok(())
                })?;
        } else {
            self.sellers_warning_tx_builder
                .set_buyer_input_signature(self.sellers_warning_tx_buyer_input_sig_ctx.compute_taproot_signature(Zero)?)
                .set_seller_input_signature(self.sellers_warning_tx_seller_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
            self.sellers_redirect_tx_builder
                .set_input_signature(self.sellers_redirect_tx_input_sig_ctx.compute_taproot_signature(Zero)?)
                .compute_signed_tx()?;
            self.sellers_claim_tx_input_sig_ctx.compute_taproot_signature(Zero)
                .map_or_else(ProtocolErrorKind::skip_missing, |sig| {
                    self.sellers_claim_tx_builder.set_input_signature(sig).compute_signed_tx()?;
                    Ok(())
                })?;
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn sign_deposit_psbt(&mut self) -> Result<()> {
        // Check that we have all the prepared tx data we need:
        if self.am_buyer() {
            self.buyers_warning_tx_builder.signed_tx()?;
            self.buyers_redirect_tx_builder.signed_tx()?;
            self.buyers_claim_tx_builder.signed_tx()
                .map_or_else(|e| ProtocolErrorKind::from(e).skip_missing(), |_| Ok(()))?;
            self.swap_tx_input_sig_ctx.aggregated_sig.ok_or(ProtocolErrorKind::MissingAggSig)?;
        } else {
            self.sellers_warning_tx_builder.signed_tx()?;
            self.sellers_redirect_tx_builder.signed_tx()?;
            self.sellers_claim_tx_builder.signed_tx()
                .map_or_else(|e| ProtocolErrorKind::from(e).skip_missing(), |_| Ok(()))?;
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
        self.get_my_key_ctx_mut().peers_key_share.as_mut()
            .ok_or(ProtocolErrorKind::MissingKeyShare)?
            .set_prv_key(prv_key_share)?;
        Ok(())
    }

    pub fn aggregate_private_keys_for_my_output(&mut self) -> Result<&Scalar> {
        self.get_my_key_ctx_mut().aggregate_prv_key_shares()
    }

    pub fn compute_signed_swap_tx(&mut self) -> Result<()> {
        let adaptor_secret = self.buyer_output_key_ctx.get_sellers_prv_key()
            .ok_or(ProtocolErrorKind::MissingKeyShare)?.into();
        self.swap_tx_builder
            .set_input_signature(self.swap_tx_input_sig_ctx.compute_taproot_signature(adaptor_secret)?)
            .compute_signed_tx()?;
        Ok(())
    }

    pub fn get_signed_swap_tx(&self) -> Option<&Transaction> {
        self.swap_tx_builder.signed_tx().ok()
    }

    pub fn recover_seller_private_key_share_for_buyer_output(&mut self, swap_tx: &Transaction) -> Result<()> {
        let swap_tx_input = self.deposit_tx_builder.seller_payout()?;
        let final_sig = LiftedSignature::from_bytes(
            &swap_tx.find_key_spend_signature(swap_tx_input)?.serialize())?;
        let adaptor_sig = self.swap_tx_input_sig_ctx.aggregated_sig
            .ok_or(ProtocolErrorKind::MissingAggSig)?;
        let adaptor_secret: MaybeScalar = adaptor_sig.reveal_secret(&final_sig)
            .ok_or(ProtocolErrorKind::MismatchedSigs)?;
        self.buyer_output_key_ctx.set_sellers_prv_key_if_buyer(adaptor_secret.try_into()?)
    }
}

impl KeyPair {
    fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        Self::from_private(Scalar::random(rng))
    }

    fn from_private(prv_key: Scalar) -> Self {
        Self { pub_key: prv_key.base_point_mul(), prv_key }
    }
}

impl KeyPair<ByOptVal> {
    const fn from_public(pub_key: Point) -> Self {
        Self { pub_key, prv_key: None }
    }

    fn set_prv_key(&mut self, prv_key: Scalar) -> Result<&Scalar> {
        if self.pub_key != prv_key.base_point_mul() {
            return Err(ProtocolErrorKind::MismatchedKeyPair);
        }
        Ok(self.prv_key.insert(prv_key))
    }
}

impl NoncePair {
    fn new(nonce_seed: impl Into<NonceSeed>, aggregated_pub_key: Point) -> Self {
        let sec_nonce = SecNonceBuilder::new(nonce_seed)
            .with_aggregated_pubkey(aggregated_pub_key)
            .build();
        Self { pub_nonce: sec_nonce.public_nonce(), sec_nonce: Some(sec_nonce) }
    }
}

impl KeyCtx {
    fn init_my_key_share(&mut self) -> &KeyPair {
        // TODO: Make the RNG configurable, to aid unit testing. (Also, we may not necessarily want
        //  to use a nondeterministic random key share):
        self.my_key_share.insert(KeyPair::random(&mut rand::rng()))
    }

    fn get_key_shares(&self) -> Option<[Point; 2]> {
        Some(if self.am_buyer {
            [self.my_key_share.as_ref()?.pub_key, self.peers_key_share.as_ref()?.pub_key]
        } else {
            [self.peers_key_share.as_ref()?.pub_key, self.my_key_share.as_ref()?.pub_key]
        })
    }

    fn aggregate_key_shares(&mut self) -> Result<()> {
        let agg_ctx = KeyAggContext::new(self.get_key_shares()
            .ok_or(ProtocolErrorKind::MissingKeyShare)?)?;
        self.aggregated_key = Some(KeyPair::from_public(agg_ctx.aggregated_pubkey()));
        self.key_agg_ctx = Some(agg_ctx);
        Ok(())
    }

    fn get_prv_key_shares(&self) -> Option<[Scalar; 2]> {
        Some(if self.am_buyer {
            [self.my_key_share.as_ref()?.prv_key, self.peers_key_share.as_ref()?.prv_key?]
        } else {
            [self.peers_key_share.as_ref()?.prv_key?, self.my_key_share.as_ref()?.prv_key]
        })
    }

    fn aggregate_prv_key_shares(&mut self) -> Result<&Scalar> {
        let prv_key_shares = self.get_prv_key_shares()
            .ok_or(ProtocolErrorKind::MissingKeyShare)?;
        let agg_ctx = self.key_agg_ctx.as_ref()
            .ok_or(ProtocolErrorKind::MissingAggPubKey)?;
        let agg_key = self.aggregated_key.as_mut()
            .ok_or(ProtocolErrorKind::MissingAggPubKey)?;
        agg_key.set_prv_key(agg_ctx.aggregated_seckey(prv_key_shares)?)
    }

    fn get_sellers_prv_key(&self) -> Option<Scalar> {
        if self.am_buyer {
            self.peers_key_share.as_ref()?.prv_key
        } else {
            Some(self.my_key_share.as_ref()?.prv_key)
        }
    }

    fn set_sellers_prv_key_if_buyer(&mut self, prv_key: Scalar) -> Result<()> {
        if self.am_buyer {
            self.peers_key_share.as_mut().ok_or(ProtocolErrorKind::MissingKeyShare)?.set_prv_key(prv_key)?;
        }
        Ok(())
    }

    fn compute_tweaked_key_agg_ctx(&self, merkle_root: Option<&TapNodeHash>) -> Result<KeyAggContext> {
        let key_agg_ctx = self.key_agg_ctx.clone()
            .ok_or(ProtocolErrorKind::MissingAggPubKey)?;
        Ok(if let Some(merkle_root) = merkle_root {
            key_agg_ctx.with_taproot_tweak(merkle_root.as_byte_array())?
        } else {
            key_agg_ctx.with_unspendable_taproot_tweak()?
        })
    }

    fn compute_p2tr_address(&self, merkle_root: Option<&TapNodeHash>, network: Network) -> Result<Address> {
        let pub_key: Point = self.compute_tweaked_key_agg_ctx(merkle_root)?.aggregated_pubkey();
        // NOTE: We have to round-trip the public key because 'musig2' & 'bitcoin' currently use
        // different versions of the 'secp256k1' crate:
        let pub_key = PublicKey::from_slice(&pub_key.serialize_uncompressed())
            .expect("curve point should have a valid uncompressed DER encoding").into();

        // This is safe, as we just performed a Taproot tweak above (via the 'musig2::secp' crate):
        Ok(Address::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(pub_key), network))
    }
}

impl SigCtx {
    fn set_warning_output_merkle_root(&mut self, claim_pub_key: &Point, network: Network) -> &TapNodeHash {
        // NOTE: We have to round-trip the public key because 'musig2' & 'bitcoin' currently use
        // different versions of the 'secp256k1' crate:
        let claim_pub_key = PublicKey::from_slice(&claim_pub_key.serialize_uncompressed())
            .expect("curve point should have a valid uncompressed DER encoding").into();
        self.merkle_root.insert(network.warning_output_merkle_root(&claim_pub_key))
    }

    fn init_my_nonce_share(&mut self, key_ctx: &KeyCtx) -> Result<()> {
        let aggregated_pub_key = key_ctx.aggregated_key.as_ref()
            .ok_or(ProtocolErrorKind::MissingAggPubKey)?.pub_key;
        // TODO: Make the RNG configurable, to aid unit testing:
        // TODO: Are we supposed to salt with the tweaked key(s), if strictly following the standard?
        self.my_nonce_share = Some(NoncePair::new(&mut rand::rng(), aggregated_pub_key));
        Ok(())
    }

    fn get_nonce_shares(&self) -> Option<[&PubNonce; 2]> {
        Some(if self.am_buyer {
            [&self.my_nonce_share.as_ref()?.pub_nonce, self.peers_nonce_share.as_ref()?]
        } else {
            [self.peers_nonce_share.as_ref()?, &self.my_nonce_share.as_ref()?.pub_nonce]
        })
    }

    fn aggregate_nonce_shares(&mut self) -> Result<&AggNonce> {
        let agg_nonce = AggNonce::sum(self.get_nonce_shares()
            .ok_or(ProtocolErrorKind::MissingKeyShare)?);
        if matches!((&agg_nonce.R1, &agg_nonce.R2), (MaybePoint::Infinity, MaybePoint::Infinity)) {
            // Fail early if the aggregated nonce is zero, since otherwise an attacker could force
            // the final signature nonce to be equal to the base point, G. While that might not be
            // a problem (for us), there would be an attack vector if such signatures were ever
            // deemed to be nonstandard. (Note that being able to assign blame later by allowing
            // this through is unimportant for a two-party protocol.)
            return Err(ProtocolErrorKind::ZeroNonce);
        }
        Ok(self.aggregated_nonce.insert(agg_nonce))
    }

    fn sign_partial(&mut self, key_ctx: &KeyCtx, message: TapSighash) -> Result<&PartialSignature> {
        // TODO: It's wasteful not to cache the tweaked KeyAggCtx -- refactor:
        let key_agg_ctx = key_ctx.compute_tweaked_key_agg_ctx(self.merkle_root.as_ref())?;
        let seckey = key_ctx.my_key_share.as_ref()
            .ok_or(ProtocolErrorKind::MissingKeyShare)?.prv_key;
        let secnonce = self.my_nonce_share.as_mut()
            .ok_or(ProtocolErrorKind::MissingNonceShare)?.sec_nonce.take()
            .ok_or(ProtocolErrorKind::NonceReuse)?;
        let aggregated_nonce = &self.aggregated_nonce.as_ref()
            .ok_or(ProtocolErrorKind::MissingAggNonce)?;

        let sig = musig2::adaptor::sign_partial(&key_agg_ctx, seckey, secnonce, aggregated_nonce,
            self.adaptor_point, message.as_byte_array())?;
        self.message = Some(message);
        Ok(self.my_partial_sig.insert(sig))
    }

    fn sign_partial_opt(&mut self, key_ctx: &KeyCtx, opt_message: Option<TapSighash>) -> Result<&PartialSignature> {
        self.sign_partial(key_ctx, opt_message.ok_or(ProtocolErrorKind::MissingTxParams)?)
    }

    fn get_partial_signatures(&self) -> Option<[PartialSignature; 2]> {
        Some(if self.am_buyer {
            [self.my_partial_sig?, self.peers_partial_sig?]
        } else {
            [self.peers_partial_sig?, self.my_partial_sig?]
        })
    }

    fn aggregate_partial_signatures(&mut self, key_ctx: &KeyCtx) -> Result<&AdaptorSignature> {
        // TODO: It's wasteful not to cache the tweaked KeyAggCtx -- refactor:
        let key_agg_ctx = key_ctx.compute_tweaked_key_agg_ctx(self.merkle_root.as_ref())?;
        let aggregated_nonce = &self.aggregated_nonce.as_ref()
            .ok_or(ProtocolErrorKind::MissingAggNonce)?;
        let partial_signatures = self.get_partial_signatures()
            .ok_or(ProtocolErrorKind::MissingPartialSig)?;
        let message = &self.message.as_ref()
            .ok_or(ProtocolErrorKind::MissingPartialSig)?[..];

        let sig = musig2::adaptor::aggregate_partial_signatures(&key_agg_ctx, aggregated_nonce,
            self.adaptor_point, partial_signatures, message)?;
        Ok(self.aggregated_sig.insert(sig))
    }

    fn compute_taproot_signature(&self, adaptor_secret: MaybeScalar) -> Result<Signature> {
        let adaptor_sig = self.aggregated_sig
            .ok_or(ProtocolErrorKind::MissingAggSig)?;
        let sig_bytes: [u8; 64] = adaptor_sig.adapt(adaptor_secret)
            .ok_or(ProtocolErrorKind::ZeroNonce)?;
        Ok(Signature::from_slice(&sig_bytes).expect("len = 64"))
    }
}

type Result<T, E = ProtocolErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum ProtocolErrorKind {
    #[error("missing key share")]
    MissingKeyShare,
    #[error("missing nonce share")]
    MissingNonceShare,
    #[error("missing partial signature")]
    MissingPartialSig,
    #[error("missing deposit PSBT")]
    MissingDepositPsbt,
    #[error("missing tx params")]
    MissingTxParams,
    #[error("missing aggregated pubkey")]
    MissingAggPubKey,
    #[error("missing aggregated signature")]
    MissingAggSig,
    #[error("missing aggregated nonce")]
    MissingAggNonce,
    #[error("missing trade wallet")]
    MissingTradeWallet,
    #[error("nonce has already been used")]
    NonceReuse,
    #[error("nonce is zero")]
    ZeroNonce,
    #[error("public-private key mismatch")]
    MismatchedKeyPair,
    #[error("mismatched adaptor and final signature")]
    MismatchedSigs,
    KeyAgg(#[from] musig2::errors::KeyAggError),
    Signing(#[from] musig2::errors::SigningError),
    Verify(#[from] musig2::errors::VerifyError),
    Tweak(#[from] musig2::errors::TweakError),
    InvalidSecretKeys(#[from] musig2::errors::InvalidSecretKeysError),
    DecodeLiftedSignature(#[from] musig2::errors::DecodeError<LiftedSignature>),
    ZeroScalar(#[from] musig2::secp::errors::ZeroScalarError),
    AddressParse(#[from] bdk_wallet::bitcoin::address::ParseError),
    Transaction(#[from] crate::transaction::TransactionErrorKind),
}

impl ProtocolErrorKind {
    fn skip_missing(self) -> Result<()> {
        use crate::transaction::TransactionErrorKind;
        match &self {
            Self::MissingKeyShare | Self::MissingNonceShare | Self::MissingPartialSig |
            Self::MissingDepositPsbt | Self::MissingTxParams | Self::MissingAggPubKey |
            Self::MissingAggSig | Self::MissingAggNonce | Self::MissingTradeWallet |
            Self::Transaction(TransactionErrorKind::MissingTransaction) => {
                warn!("Skipping error: {self}");
                Ok(())
            }
            _ => Err(self)
        }
    }
}
