use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::amount::CheckedSum as _;
use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_wallet::bitcoin::taproot::TaprootBuilder;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    absolute, relative, script, Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf,
    TapNodeHash, TapSighash, TapSighashType, Transaction, TxIn, TxOut, Txid, Weight,
    XOnlyPublicKey,
};
use paste::paste;
use relative::LockTime;
use thiserror::Error;

pub const REGTEST_WARNING_LOCK_TIME: LockTime = LockTime::from_height(5);
pub const REGTEST_CLAIM_LOCK_TIME: LockTime = LockTime::from_height(5);
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(330);
pub const SIGNED_SWAP_TX_WEIGHT: Weight = Weight::from_wu(444);
pub const SIGNED_WARNING_TX_WEIGHT: Weight = Weight::from_wu(846);
pub const SIGNED_REDIRECT_TX_BASE_WEIGHT: Weight = SIGNED_SWAP_TX_WEIGHT;
// pub const SIGNED_CLAIM_TX_WEIGHT: Weight = SIGNED_SWAP_TX_WEIGHT;

fn claim_script(pub_key: &XOnlyPublicKey, lock_time: LockTime) -> ScriptBuf {
    script::Builder::new()
        .push_sequence(lock_time.to_sequence())
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pub_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn warning_output_merkle_root(claim_pub_key: &XOnlyPublicKey, claim_lock_time: LockTime) -> TapNodeHash {
    let claim_script = claim_script(claim_pub_key, claim_lock_time);
    TaprootBuilder::with_capacity(1)
        .add_leaf(0, claim_script)
        .expect("hardcoded TapTree build sequence should be valid")
        .try_into_taptree()
        .expect("hardcoded TapTree build sequence should be complete")
        .root_hash()
}

// TODO: Replace dummy PSBT with real one provided by a service.
//noinspection SpellCheckingInspection
pub(crate) fn empty_dummy_psbt() -> Psbt {
    "cHNidP8BAAoAAAAAAAAAAAAAAA==".parse().expect("hardcoded PSBT should be valid")
}

pub struct Receiver<V: NetworkValidation = NetworkChecked> {
    pub address: Address<V>,
    pub amount: Amount,
}

impl Receiver<NetworkUnchecked> {
    pub fn require_network(self, required: Network) -> Result<Receiver> {
        Ok(Receiver { address: self.address.require_network(required)?, amount: self.amount })
    }
}

impl Receiver {
    fn output_weight(&self) -> Weight {
        Weight::from_vb_unchecked(self.address.script_pubkey().len() as u64 + 9)
    }

    fn output_cost_msat(&self, fee_rate: FeeRate) -> Option<u64> {
        let amount_msat = self.amount.to_sat().checked_mul(1000)?;
        let fee_msat = fee_rate.to_sat_per_kwu().checked_mul(self.output_weight().to_wu())?;
        amount_msat.checked_add(fee_msat)
    }

    pub fn total_output_cost_msat<'a, I>(receivers: I, fee_rate: FeeRate, extra_output_num: u16) -> Option<u64>
        where I: IntoIterator<Item=&'a Self>
    {
        let mut cost = 0u64;
        let mut num = extra_output_num;
        for receiver in receivers {
            cost = cost.checked_add(receiver.output_cost_msat(fee_rate)?)?;
            // Fail if more than 65535 outputs, which will never happen for a standard tx:
            num = num.checked_add(1)?;
        }
        if num > 252 {
            // For more than 252 outputs, we get a 3-byte length encoding instead of 1, adding 8 wu.
            cost = cost.checked_add(fee_rate.to_sat_per_kwu().checked_mul(8)?)?;
        }
        Some(cost)
    }
}

macro_rules! make_getter {
    ($field_name:ident: $field_type:ident) => {
        paste! {
            pub fn $field_name(&self) -> Result<&$field_type> {
                self.$field_name.as_ref().ok_or(TransactionErrorKind::[<Missing $field_type>])
            }
        }
    };
}

macro_rules! make_setter {
    ($field_name:ident: $field_type:ident) => {
        paste! {
            pub fn [<set_ $field_name>](&mut self, $field_name: $field_type) -> &mut Self {
                self.$field_name.get_or_insert($field_name);
                self
            }
        }
    };
}

macro_rules! make_getter_setter {
    ($field_name:ident: $field_type:ident) => {
        make_getter!($field_name: $field_type);
        make_setter!($field_name: $field_type);
    };
}

#[derive(Clone)]
pub struct TxOutput(OutPoint, TxOut);

type ReceiverList = Vec<Receiver>;

//noinspection SpellCheckingInspection
const MOCK_DEPOSIT_TXID: &str = "ea824fbd25dfaf768d2a4d2de11090063fb79b4950b1bc4f5f47aabe9d929040";

#[derive(Default)]
pub struct DepositTxBuilder {
    // Supplied fields:
    trade_amount: Option<Amount>,
    buyers_security_deposit: Option<Amount>,
    sellers_security_deposit: Option<Amount>,
    buyer_payout_address: Option<Address>,
    seller_payout_address: Option<Address>,
    trade_fee_receivers: Option<ReceiverList>,
    fee_rate: Option<FeeRate>,
    // Externally derived fields:
    buyers_half_psbt: Option<Psbt>,
    sellers_half_psbt: Option<Psbt>,
    // Derived fields:
    txid: Option<Txid>,
}

impl DepositTxBuilder {
    make_getter_setter!(trade_amount: Amount);
    make_getter_setter!(buyers_security_deposit: Amount);
    make_getter_setter!(sellers_security_deposit: Amount);
    make_getter_setter!(buyer_payout_address: Address);
    make_getter_setter!(seller_payout_address: Address);
    make_getter_setter!(trade_fee_receivers: ReceiverList);
    make_getter_setter!(fee_rate: FeeRate);
    make_getter_setter!(buyers_half_psbt: Psbt);
    make_getter_setter!(sellers_half_psbt: Psbt);

    fn txid(&self) -> Result<Txid> {
        self.txid.ok_or(TransactionErrorKind::MissingTransaction)
    }

    pub fn compute_unsigned_tx(&mut self) -> Result<&mut Self> {
        // Check that all the params needed to compute a real unsigned tx are set...
        self.trade_amount()?;
        self.buyers_security_deposit()?;
        self.sellers_security_deposit()?;
        self.buyer_payout_address()?;
        self.seller_payout_address()?;
        self.trade_fee_receivers()?;
        self.fee_rate()?;
        self.buyers_half_psbt()?;
        self.sellers_half_psbt()?;
        // Now set a mock txid (namely, the same one used in the unit tests below).
        // TODO: Add real PSBT aggregation and unsigned-tx computation logic.
        self.txid = Some(MOCK_DEPOSIT_TXID.parse().expect("hardcoded txid should be valid"));
        Ok(self)
    }

    pub fn buyer_payout(&self) -> Result<TxOutput> {
        // TODO: Should we assume the buyer payout vout is always 3 (the case for the unit tests)?
        Ok(TxOutput(OutPoint::new(self.txid()?, 3), TxOut {
            value: self.buyers_security_deposit()?.checked_add(*self.trade_amount()?)
                .ok_or(TransactionErrorKind::Overflow)?,
            script_pubkey: self.buyer_payout_address()?.script_pubkey(),
        }))
    }

    pub fn seller_payout(&self) -> Result<TxOutput> {
        // TODO: Should we assume the seller payout vout is always 1 (the case for the unit tests)?
        Ok(TxOutput(OutPoint::new(self.txid()?, 1), TxOut {
            value: *self.sellers_security_deposit()?,
            script_pubkey: self.seller_payout_address()?.script_pubkey(),
        }))
    }
}

#[derive(Default)]
pub struct WarningTxBuilder {
    // Supplied fields:
    buyer_input: Option<TxOutput>,
    seller_input: Option<TxOutput>,
    escrow_address: Option<Address>,
    anchor_address: Option<Address>,
    warning_lock_time: Option<LockTime>,
    fee_rate: Option<FeeRate>,
    // Derived fields:
    unsigned_tx: Option<Transaction>,
}

impl WarningTxBuilder {
    make_getter_setter!(buyer_input: TxOutput);
    make_getter_setter!(seller_input: TxOutput);
    make_getter_setter!(escrow_address: Address);
    make_getter_setter!(anchor_address: Address);
    make_getter_setter!(warning_lock_time: LockTime);
    make_getter_setter!(fee_rate: FeeRate);
    make_getter!(unsigned_tx: Transaction);

    pub fn escrow_amount(input_amounts: impl IntoIterator<Item=Amount>, fee_rate: FeeRate) -> Option<Amount> {
        input_amounts.into_iter().checked_sum()?
            .checked_sub(ANCHOR_AMOUNT)?
            .checked_sub(fee_rate.checked_mul_by_weight(SIGNED_WARNING_TX_WEIGHT)?)
    }

    pub fn compute_unsigned_tx(&mut self) -> Result<&mut Self> {
        let buyer_input = TxIn {
            previous_output: self.buyer_input()?.0,
            sequence: self.warning_lock_time()?.to_sequence(),
            ..TxIn::default()
        };
        let seller_input = TxIn {
            previous_output: self.seller_input()?.0,
            sequence: self.warning_lock_time()?.to_sequence(),
            ..TxIn::default()
        };
        let escrow_output = TxOut {
            value: Self::escrow_amount(
                [self.buyer_input()?.1.value, self.seller_input()?.1.value],
                *self.fee_rate()?,
            ).ok_or(TransactionErrorKind::Overflow)?,
            script_pubkey: self.escrow_address()?.script_pubkey(),
        };
        let anchor_output = TxOut {
            value: ANCHOR_AMOUNT,
            script_pubkey: self.anchor_address()?.script_pubkey(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![buyer_input, seller_input],
            output: vec![escrow_output, anchor_output],
        };
        self.unsigned_tx.get_or_insert(tx);
        Ok(self)
    }

    fn sighash(&self, input_index: usize) -> Result<TapSighash> {
        let prevouts = [&self.buyer_input()?.1, &self.seller_input()?.1];
        let prevouts = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(self.unsigned_tx()?);
        Ok(cache.taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::All)?)
    }

    pub fn buyer_input_sighash(&self) -> Result<TapSighash> { self.sighash(0) }

    pub fn seller_input_sighash(&self) -> Result<TapSighash> { self.sighash(1) }
}

type Result<T, E = TransactionErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum TransactionErrorKind {
    #[error("missing lock time")]
    MissingLockTime,
    #[error("missing tx output")]
    MissingTxOutput,
    #[error("missing address")]
    MissingAddress,
    #[error("missing BTC amount")]
    MissingAmount,
    #[error("missing receiver list")]
    MissingReceiverList,
    #[error("missing fee rate")]
    MissingFeeRate,
    #[error("missing PSBT")]
    MissingPsbt,
    #[error("missing transaction")]
    MissingTransaction,
    #[error("overflow")]
    Overflow,
    AddressParse(#[from] bdk_wallet::bitcoin::address::ParseError),
    Taproot(#[from] bdk_wallet::bitcoin::sighash::TaprootError),
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::consensus::Decodable as _;
    use bdk_wallet::bitcoin::hex::test_hex_unwrap as hex;
    use bdk_wallet::bitcoin::Network;

    use super::*;

    // Valid signed txs pulled from a Regtest instance. We should be able to rebuild the unsigned parts exactly...

    //noinspection SpellCheckingInspection
    const SIGNED_DEPOSIT_TX: &str = "\
        02000000000103593f2490f5fe6ca34151dad53983bb4049fc389a194210377ae9efdeeec871810100000000ffffffff\
        7d43ef85d23dc54918dc017c805c181f1e3573ce30aedd8492ba4291695da9430100000000ffffffff80dc1d43c34749\
        26ac5eb7a4def9f1f604225c243f93fa1daa3b2406f4eaf8990000000000ffffffff04707693030000000022512003c4\
        c490d5b9572f4a8a9a6ba89761efe2d3fb5ab7b48fa49dcd60ab6253bdbf002d310100000000225120523abb34a5f99b\
        71e2461b119b9c60674a82a25af9aaa9a7dce7cecf79a622f6f3a7c404000000002251209a6474e216ded9220ca2de1d\
        a86398353cfd8ea00d3798105c6845d49a189b8b003b5808000000002251209c851e4bb082855c30a1441470f57edb2c\
        e53f74426f14d674e7de0bbcd1fdb301404e855da0d22221e9eeea9b45f42f968d8784bc72e501640e4ec9faa3ada13f\
        cbb9d7b0e8b42965afba8eef79b8900c0cdc6be6497b535bb1acfadce5413333ef01407c6977dac7717d66b82f0eef90\
        8a108fd8980bcdf21d08c72062b1dc44933a7b1ff7bb09933fdc9c7174064e287ee863ffcd2fa9836e006aa9323e1751\
        b5042801405ca211e8014d1df806e220a29a4751c8a362d3e52f09869df93fa43fe322e991d37d58655f8e5c2c0f277e\
        1015da25c1e533f528d4ba31bfa912c1d166dad36000000000";

    //noinspection SpellCheckingInspection
    const SIGNED_SELLERS_WARNING_TX: &str = "\
        020000000001024090929dbeaa475f4fbcb150499bb73f069010e12d4d2a8d76afdf25bd4f82ea030000000002000000\
        4090929dbeaa475f4fbcb150499bb73f069010e12d4d2a8d76afdf25bd4f82ea01000000000200000002ce6289090000\
        00002251209c851e4bb082855c30a1441470f57edb2ce53f74426f14d674e7de0bbcd1fdb34a01000000000000225120\
        fb0caf990c3315e540bef9401ea1bf5c0257a9fc1bc31d8eb4c6e3a50225532e01400a1765c41c6851258c52122f8635\
        3d4cdc67794707d5a7f79daf9a9441e484f9001eca7a01951ce62fc3eab2fd5a84f45ce3c7ad081fa263ef672cde0a43\
        7d840140d5f66951bef77e1b3a180b94042604b1e26c0c7bcdecf78b151962dc623963d53e2ac6a77f7ed7be4fc4eab2\
        3f8decd8196abafb50b7062b86b88ad697682a5c00000000";

    //noinspection SpellCheckingInspection
    const SIGNED_BUYERS_REDIRECT_TX: &str = "\
        0200000000010149634d8e127d370144fc943fd060f2af4067920ed11b10bc6e8e45102e1108ea0000000000fdffffff\
        0388d2b8050000000022512039ee586be03c9d1cddbffc83e874f4b38212fd841fdfef2dcc94fb8b5abf32df5c8cd003\
        00000000225120bdfe7695e32dfa072d8e561951925f3aff300d953cee127884b428de6b63d68c4a0100000000000022\
        5120e47961ba4f26beb5d179e98fab691d8109f894e58a8127188b1944e7541571740140bac65d0b8207957f434a80a0\
        ac02a21d9dfcd958b1ea804c44bad712e5728d9916c8bd91f386825638e750aaddacc734f9c724768aa4dbd9e8b87064\
        a9cac9bd00000000";

    #[expect(edition_2024_expr_fragment_specifier, reason = "for tests only; unlikely to break")]
    macro_rules! tx {
        ($hex:expr) => {{
            let raw_tx = hex!($hex);
            Transaction::consensus_decode(&mut raw_tx.as_slice()).unwrap()
        }};
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_warning_tx_builder() -> Result<()> {
        let deposit_tx = tx!(SIGNED_DEPOSIT_TX);
        let warning_tx = tx!(SIGNED_SELLERS_WARNING_TX);
        let redirect_tx = tx!(SIGNED_BUYERS_REDIRECT_TX);

        let [deposit_txid, warning_txid, redirect_txid] = [&deposit_tx, &warning_tx, &redirect_tx]
            .map(Transaction::compute_txid);

        assert_eq!(MOCK_DEPOSIT_TXID, deposit_txid.to_string());
        assert_eq!("ea08112e10458e6ebc101bd10e926740aff260d03f94fc4401377d128e4d6349", warning_txid.to_string());
        assert_eq!("8f0901c700f1692d56cdd0e059b822d0ee5e983fc5897f69eba3592a4728ba30", redirect_txid.to_string());

        let builder = filled_warning_tx_builder(&filled_deposit_tx_builder()?)?;
        let unsigned_tx = builder.unsigned_tx()?;
        let sighashes = [builder.buyer_input_sighash()?, builder.seller_input_sighash()?];

        assert_eq!(warning_txid, unsigned_tx.compute_txid());
        // TODO: Check that the sighashes are correct.
        dbg!(sighashes);
        Ok(())
    }

    //noinspection SpellCheckingInspection
    fn filled_deposit_tx_builder() -> Result<DepositTxBuilder> {
        let buyer_payout_address = "bcrt1pnjz3ujass2z4cv9pgs28pat7mvkw20m5gfh3f4n5ul0qh0x3lkes0qv0uf"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let seller_payout_address = "bcrt1p2gatkd99lxdhrcjxrvgeh8rqva9g9gj6lx42nf7uul8v77dxytmq0wnpk6"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;

        let mut builder = DepositTxBuilder::default();
        builder
            .set_trade_amount(Amount::from_sat(120_000_000))
            .set_buyers_security_deposit(Amount::from_sat(20_000_000))
            .set_sellers_security_deposit(Amount::from_sat(20_000_000))
            .set_buyer_payout_address(buyer_payout_address.clone())
            .set_seller_payout_address(seller_payout_address.clone())
            .set_trade_fee_receivers(vec![])
            .set_fee_rate(FeeRate::from_sat_per_kwu(5158)) // gives 7325-sat absolute fee
            .set_buyers_half_psbt(empty_dummy_psbt())
            .set_sellers_half_psbt(empty_dummy_psbt())
            .compute_unsigned_tx()?;
        Ok(builder)
    }

    //noinspection SpellCheckingInspection
    fn filled_warning_tx_builder(deposit_tx_builder: &DepositTxBuilder) -> Result<WarningTxBuilder> {
        let escrow_address = "bcrt1pnjz3ujass2z4cv9pgs28pat7mvkw20m5gfh3f4n5ul0qh0x3lkes0qv0uf"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let anchor_address = "bcrt1plvx2lxgvxv272s97l9qpagdltsp9020ur0p3mr45cm362q392vhqsq6rfa"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;

        let mut builder = WarningTxBuilder::default();
        builder
            .set_buyer_input(deposit_tx_builder.buyer_payout()?)
            .set_seller_input(deposit_tx_builder.seller_payout()?)
            .set_escrow_address(escrow_address)
            .set_anchor_address(anchor_address)
            .set_warning_lock_time(LockTime::from_height(2))
            .set_fee_rate(FeeRate::from_sat_per_kwu(1182)) // gives 1000-sat absolute fee
            .compute_unsigned_tx()?;
        Ok(builder)
    }
}
