use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bdk_wallet::bitcoin::amount::CheckedSum as _;
use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_wallet::bitcoin::taproot::TaprootBuilder;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    absolute, relative, script, Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf,
    Sequence, TapNodeHash, TapSighash, TapSighashType, Transaction, TxIn, TxOut, Txid, Weight,
    XOnlyPublicKey,
};
use paste::paste;
use relative::LockTime;
use std::sync::Arc;
use thiserror::Error;

pub const REGTEST_WARNING_LOCK_TIME: LockTime = LockTime::from_height(5);
pub const REGTEST_CLAIM_LOCK_TIME: LockTime = LockTime::from_height(5);
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(330);
pub const SIGNED_FORWARDING_TX_WEIGHT: Weight = Weight::from_wu(444);
pub const SIGNED_WARNING_TX_WEIGHT: Weight = Weight::from_wu(846);
pub const SIGNED_REDIRECT_TX_BASE_WEIGHT: Weight = SIGNED_FORWARDING_TX_WEIGHT;

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
    fn output_weight(&self) -> Weight { TxOut::from(self).weight() }

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

impl From<&Receiver> for TxOut {
    fn from(value: &Receiver) -> Self {
        Self { value: value.amount, script_pubkey: value.address.script_pubkey() }
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

pub type ReceiverList = Arc<[Receiver]>;

trait WithFixedInputs<const N: usize> {
    fn inputs(&self) -> Result<[&TxOutput; N]>;

    fn tx_ins(&self, lock_time: LockTime) -> Result<[TxIn; N]> {
        // FIXME: A bit hacky to use (an otherwise perfectly valid) zero lock time as a sentinel value.
        let sequence = if lock_time == LockTime::ZERO {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        } else {
            lock_time.to_sequence()
        };
        Ok(self.inputs()?.map(|input|
            TxIn { previous_output: input.0, sequence, ..TxIn::default() }))
    }

    fn key_spend_sighash(&self, tx: &Transaction, input_index: usize) -> Result<TapSighash> {
        let prevouts = self.inputs()?.map(|input| &input.1);
        let prevouts = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(tx);
        Ok(cache.taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::All)?)
    }
}

//noinspection SpellCheckingInspection
const MOCK_DEPOSIT_TXID: &str = "44090980ad341fb556368dbc6f32cfd5c50c61724ce7ae0a362d26c19f87a923";

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
        // FIXME: Don't assume the buyer payout vout is always 2 (the case for the unit tests).
        Ok(TxOutput(OutPoint::new(self.txid()?, 2), TxOut {
            value: self.buyers_security_deposit()?.checked_add(*self.trade_amount()?)
                .ok_or(TransactionErrorKind::Overflow)?,
            script_pubkey: self.buyer_payout_address()?.script_pubkey(),
        }))
    }

    pub fn seller_payout(&self) -> Result<TxOutput> {
        // FIXME: Don't assume the seller payout vout is always 3 (the case for the unit tests).
        Ok(TxOutput(OutPoint::new(self.txid()?, 3), TxOut {
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
    lock_time: Option<LockTime>,
    fee_rate: Option<FeeRate>,
    // Derived fields:
    unsigned_tx: Option<Transaction>,
}

impl WarningTxBuilder {
    make_getter_setter!(buyer_input: TxOutput);
    make_getter_setter!(seller_input: TxOutput);
    make_getter_setter!(escrow_address: Address);
    make_getter_setter!(anchor_address: Address);
    make_getter_setter!(lock_time: LockTime);
    make_getter_setter!(fee_rate: FeeRate);
    make_getter!(unsigned_tx: Transaction);

    pub fn escrow_amount(input_amounts: impl IntoIterator<Item=Amount>, fee_rate: FeeRate) -> Option<Amount> {
        input_amounts.into_iter().checked_sum()?
            .checked_sub(ANCHOR_AMOUNT)?
            .checked_sub(fee_rate.checked_mul_by_weight(SIGNED_WARNING_TX_WEIGHT)?)
    }

    pub fn compute_unsigned_tx(&mut self) -> Result<&mut Self> {
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
            input: self.tx_ins(*self.lock_time()?)?.to_vec(),
            output: vec![escrow_output, anchor_output],
        };
        self.unsigned_tx.get_or_insert(tx);
        Ok(self)
    }

    pub fn escrow(&self) -> Result<TxOutput> {
        let txid = self.unsigned_tx()?.compute_txid();
        let output = self.unsigned_tx()?.tx_out(0)
            .expect("warning tx output list should be nonempty");
        Ok(TxOutput(OutPoint::new(txid, 0), output.clone()))
    }

    pub fn buyer_input_sighash(&self) -> Result<TapSighash> {
        self.key_spend_sighash(self.unsigned_tx()?, 0)
    }

    pub fn seller_input_sighash(&self) -> Result<TapSighash> {
        self.key_spend_sighash(self.unsigned_tx()?, 1)
    }
}

impl WithFixedInputs<2> for WarningTxBuilder {
    fn inputs(&self) -> Result<[&TxOutput; 2]> { Ok([self.buyer_input()?, self.seller_input()?]) }
}

#[derive(Default)]
pub struct RedirectTxBuilder {
    // Supplied fields:
    input: Option<TxOutput>,
    receivers: Option<ReceiverList>,
    anchor_address: Option<Address>,
    // Derived fields:
    unsigned_tx: Option<Transaction>,
}

impl RedirectTxBuilder {
    make_getter_setter!(input: TxOutput);
    make_getter_setter!(receivers: ReceiverList);
    make_getter_setter!(anchor_address: Address);
    make_getter!(unsigned_tx: Transaction);

    pub fn compute_unsigned_tx(&mut self) -> Result<&mut Self> {
        let mut output = Vec::with_capacity(self.receivers()?.len() + 1);
        output.extend(self.receivers()?.iter().map(TxOut::from));
        output.push(TxOut {
            value: ANCHOR_AMOUNT,
            script_pubkey: self.anchor_address()?.script_pubkey(),
        });
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: self.tx_ins(LockTime::ZERO)?.to_vec(),
            output,
        };
        self.unsigned_tx.get_or_insert(tx);
        Ok(self)
    }

    pub fn input_sighash(&self) -> Result<TapSighash> {
        self.key_spend_sighash(self.unsigned_tx()?, 0)
    }
}

impl WithFixedInputs<1> for RedirectTxBuilder {
    fn inputs(&self) -> Result<[&TxOutput; 1]> { Ok([self.input()?]) }
}

#[derive(Default)]
pub struct ForwardingTxBuilder {
    // Supplied fields:
    input: Option<TxOutput>,
    payout_address: Option<Address>,
    lock_time: Option<LockTime>,
    fee_rate: Option<FeeRate>,
    // Derived fields:
    unsigned_tx: Option<Transaction>,
}

impl ForwardingTxBuilder {
    make_getter_setter!(input: TxOutput);
    make_getter_setter!(payout_address: Address);
    make_getter_setter!(lock_time: LockTime);
    make_getter_setter!(fee_rate: FeeRate);
    make_getter!(unsigned_tx: Transaction);

    pub fn disable_lock_time(&mut self) -> &mut Self { self.set_lock_time(LockTime::ZERO) }

    fn payout_amount(input_amount: Amount, fee_rate: FeeRate) -> Option<Amount> {
        input_amount.checked_sub(fee_rate.checked_mul_by_weight(SIGNED_FORWARDING_TX_WEIGHT)?)
    }

    pub fn compute_unsigned_tx(&mut self) -> Result<&mut Self> {
        let output = vec![TxOut {
            value: Self::payout_amount(self.input()?.1.value, *self.fee_rate()?)
                .ok_or(TransactionErrorKind::Overflow)?,
            script_pubkey: self.payout_address()?.script_pubkey(),
        }];
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: self.tx_ins(*self.lock_time()?)?.to_vec(),
            output,
        };
        self.unsigned_tx.get_or_insert(tx);
        Ok(self)
    }

    pub fn input_sighash(&self) -> Result<TapSighash> {
        self.key_spend_sighash(self.unsigned_tx()?, 0)
    }
}

impl WithFixedInputs<1> for ForwardingTxBuilder {
    fn inputs(&self) -> Result<[&TxOutput; 1]> { Ok([self.input()?]) }
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

    // Valid signed txs pulled from an integration test run. We should be able to rebuild the unsigned parts exactly...

    //noinspection SpellCheckingInspection
    const SIGNED_DEPOSIT_TX: &str = "\
        0200000000010300236055317618f2c54bd6a20f7e0a55bed37fb39ebd65e946ebbb5b575486650000000000fdffffff\
        23f5cc956695307d15a860d166ac2ef3f6130a565f78c6118fb78dec72cc5e4a0000000000fdffffffa3e0fd235828ce\
        bebd1f4f69b4067d59b59b65d472276749965e13b9a03c3b370100000000fdffffff0470769303000000002251203bcd\
        ca25f304ba34cf38bc37f5d4e79262b258c7c33a51673817e1cae3c6a53cf3a7c4040000000022512044245eb9ee6429\
        7d0a5e3bdb29f15af3352e8b69cd9dbaa2a0ac35d345d15bff003b58080000000022512050ae873bc1665acda868f35e\
        205cbac0d37e71ad2c1ff8930f2cf1de9b7c131b002d3101000000002251206667c68404a48b32eb80a4d117d96c8310\
        6d02ca0d8fccd6ba0348aaacf4aa260140f631ae99b4743315b237af9c48ae1f9bb87b6c5404e84d8e3907269218d1bb\
        a54c397158aa233fd3f2227f4dc46922ef62eb8cc39a06b7a339b33e2401d512c101402376111ed79dac9ff6f2d85dfe\
        57d142f6075f4df9381aeab87a9414774252247555f791ddf82354a3d73fa24955f6c5330ae44b2b238fa74be2eee9a4\
        6fcb720140637f4a624bfc46bdb52e01b923d157a97148210f1a2669716815d3249c61567317d543868698f30130e0aa\
        f693ce265c544e3db5eda568bffb6ccd03d25a31df00000000";

    //noinspection SpellCheckingInspection
    const SIGNED_SWAP_TX: &str = "\
        0200000000010123a9879fc1262d360aaee74c72610cc5d5cf326fbc8d3656b51f34ad800909440300000000fdffffff\
        0118293101000000002251204d19b6cd267c57f719f2f3f01c2ce230505e053a0d20884f4aa9115ebff3338d01400555\
        c9a53b9f233186937e090d6116dd0e5215742ed56d44bd7dce0c10b40cf4c61a573b1fd1f68ca386f7ea9e420f8bd3c2\
        552a661222e1792d63caaad3353200000000";

    //noinspection SpellCheckingInspection
    const SIGNED_SELLERS_WARNING_TX: &str = "\
        0200000000010223a9879fc1262d360aaee74c72610cc5d5cf326fbc8d3656b51f34ad80090944020000000002000000\
        23a9879fc1262d360aaee74c72610cc5d5cf326fbc8d3656b51f34ad8009094403000000000200000002ce6289090000\
        00002251206667c68404a48b32eb80a4d117d96c83106d02ca0d8fccd6ba0348aaacf4aa264a01000000000000225120\
        4d19b6cd267c57f719f2f3f01c2ce230505e053a0d20884f4aa9115ebff3338d0140623b8be648c7fb330062ae29c30e\
        9cc13c7a18b756095490c6f673f900c56a8ba0759711fe395a5b98e053dd1e3bc39dbe2d5c2c1f162d9ab5f24144f61d\
        31810140bcc2a8b0aab906ae6f32444c4e7ac163153d134f1075a4153fe735fd83ff9e172b16b14efd5cb5995f1e3553\
        c9ceed572a3419e4aab7a2dd86cdb440181c597000000000";

    //noinspection SpellCheckingInspection
    const SIGNED_BUYERS_REDIRECT_TX: &str = "\
        02000000000101f703021407bbdc217f56b8256dd620e0252cc83eb9eacba7370b96091ccc20c60000000000fdffffff\
        0388d2b8050000000022512039ee586be03c9d1cddbffc83e874f4b38212fd841fdfef2dcc94fb8b5abf32df5c8cd003\
        00000000225120bdfe7695e32dfa072d8e561951925f3aff300d953cee127884b428de6b63d68c4a0100000000000022\
        51206661819664b49934b8a84a665b6d61c1d36a4537bb0fe074843864abd21aa0dd01407881f2345129f9305e4efe84\
        5d043ba98d0538352ffc6a50db35ca661b50ba6fd3e5553bdc71e27ba274ce0b862db53dde316da92614b91e8208fe1e\
        164ae0b400000000";

    //noinspection SpellCheckingInspection
    const SIGNED_SELLERS_CLAIM_TX: &str = "\
        02000000000101f703021407bbdc217f56b8256dd620e0252cc83eb9eacba7370b96091ccc20c6000000000002000000\
        01e65e8909000000002251204d19b6cd267c57f719f2f3f01c2ce230505e053a0d20884f4aa9115ebff3338d0140b1ec\
        0464f04ced9ce0d5715f3740b24fd4226f72c2d990b2bbdad29898e15051082ffc3f3626170a992e7a5a8b48fffd58e4\
        e5520b2c45d5b09a6f07c4c2a2dc00000000";

    #[expect(edition_2024_expr_fragment_specifier, reason = "for tests only; unlikely to break")]
    macro_rules! tx {
        ($hex:expr) => {{
            let raw_tx = hex!($hex);
            Transaction::consensus_decode(&mut raw_tx.as_slice()).unwrap()
        }};
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_txids() {
        let deposit_tx = tx!(SIGNED_DEPOSIT_TX);
        let swap_tx = tx!(SIGNED_SWAP_TX);
        let warning_tx = tx!(SIGNED_SELLERS_WARNING_TX);
        let redirect_tx = tx!(SIGNED_BUYERS_REDIRECT_TX);
        let claim_tx = tx!(SIGNED_SELLERS_CLAIM_TX);

        let [deposit_txid, swap_txid, warning_txid, redirect_txid, claim_txid] =
            [&deposit_tx, &swap_tx, &warning_tx, &redirect_tx, &claim_tx].map(Transaction::compute_txid);

        assert_eq!(MOCK_DEPOSIT_TXID, deposit_txid.to_string());
        assert_eq!("41e2045e54060bfe2e094e76a7ce4fbd7185384d34afcb77353cd359b465c93d", swap_txid.to_string());
        assert_eq!("c620cc1c09960b37a7cbeab93ec82c25e020d66d25b8567f21dcbb07140203f7", warning_txid.to_string());
        assert_eq!("ecdb3995689d8e23e4c467692ab400af66eb9f5a35b99753ee3bfdaa10b0b1d6", redirect_txid.to_string());
        assert_eq!("81be3cf683c4a65979bbbe35264c8d0e4cd6fe33e80d094463f13ecf4d5eb2df", claim_txid.to_string());
    }

    #[test]
    fn test_swap_tx_builder() -> Result<()> {
        let builder = filled_swap_tx_builder(&filled_deposit_tx_builder()?)?;
        let unsigned_tx = builder.unsigned_tx()?;
        let sighash = builder.input_sighash()?;

        assert_eq!(tx!(SIGNED_SWAP_TX).compute_txid(), unsigned_tx.compute_txid());
        // TODO: Check that the sighash is correct.
        dbg!(sighash);
        Ok(())
    }

    #[test]
    fn test_warning_tx_builder() -> Result<()> {
        let builder = filled_warning_tx_builder(&filled_deposit_tx_builder()?)?;
        let unsigned_tx = builder.unsigned_tx()?;
        let sighashes = [builder.buyer_input_sighash()?, builder.seller_input_sighash()?];

        assert_eq!(tx!(SIGNED_SELLERS_WARNING_TX).compute_txid(), unsigned_tx.compute_txid());
        // TODO: Check that the sighashes are correct.
        dbg!(sighashes);
        Ok(())
    }

    #[test]
    fn test_redirect_tx_builder() -> Result<()> {
        let builder = filled_redirect_tx_builder(
            &filled_warning_tx_builder(&filled_deposit_tx_builder()?)?)?;
        let unsigned_tx = builder.unsigned_tx()?;
        let sighash = builder.input_sighash()?;

        assert_eq!(tx!(SIGNED_BUYERS_REDIRECT_TX).compute_txid(), unsigned_tx.compute_txid());
        // TODO: Check that the sighash is correct.
        dbg!(sighash);
        Ok(())
    }

    #[test]
    fn test_claim_tx_builder() -> Result<()> {
        let builder = filled_claim_tx_builder(
            &filled_warning_tx_builder(&filled_deposit_tx_builder()?)?)?;
        let unsigned_tx = builder.unsigned_tx()?;
        let sighash = builder.input_sighash()?;

        assert_eq!(tx!(SIGNED_SELLERS_CLAIM_TX).compute_txid(), unsigned_tx.compute_txid());
        // TODO: Check that the sighash is correct.
        dbg!(sighash);
        Ok(())
    }

    //noinspection SpellCheckingInspection
    fn filled_deposit_tx_builder() -> Result<DepositTxBuilder> {
        let buyer_payout_address = "bcrt1p2zhgww7pvedvm2rg7d0zqh96crfhuudd9s0l3yc09ncaaxmuzvds5zhh8t"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let seller_payout_address = "bcrt1pvenudpqy5j9n96uq5ng30ktvsvgx6qk2pk8ue446qdy24t854gnq5sp2l6"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;

        let mut builder = DepositTxBuilder::default();
        builder
            .set_trade_amount(Amount::from_sat(120_000_000))
            .set_buyers_security_deposit(Amount::from_sat(20_000_000))
            .set_sellers_security_deposit(Amount::from_sat(20_000_000))
            .set_buyer_payout_address(buyer_payout_address.clone())
            .set_seller_payout_address(seller_payout_address.clone())
            .set_trade_fee_receivers(ReceiverList::default())
            .set_fee_rate(FeeRate::from_sat_per_kwu(5158)) // gives 7325-sat absolute fee
            .set_buyers_half_psbt(empty_dummy_psbt())
            .set_sellers_half_psbt(empty_dummy_psbt())
            .compute_unsigned_tx()?;
        Ok(builder)
    }

    //noinspection SpellCheckingInspection
    fn filled_swap_tx_builder(deposit_tx_builder: &DepositTxBuilder) -> Result<ForwardingTxBuilder> {
        let payout_address = "bcrt1pf5vmdnfx03tlwx0j70cpct8zxpg9upf6p5sgsn624yg4a0lnxwxsegnwnx"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;

        let mut builder = ForwardingTxBuilder::default();
        builder
            .set_input(deposit_tx_builder.seller_payout()?)
            .set_payout_address(payout_address)
            .disable_lock_time()
            .set_fee_rate(FeeRate::from_sat_per_kwu(2252)) // gives 1000-sat absolute fee
            .compute_unsigned_tx()?;
        Ok(builder)
    }

    //noinspection SpellCheckingInspection
    fn filled_warning_tx_builder(deposit_tx_builder: &DepositTxBuilder) -> Result<WarningTxBuilder> {
        let escrow_address = "bcrt1pvenudpqy5j9n96uq5ng30ktvsvgx6qk2pk8ue446qdy24t854gnq5sp2l6"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let anchor_address = "bcrt1pf5vmdnfx03tlwx0j70cpct8zxpg9upf6p5sgsn624yg4a0lnxwxsegnwnx"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;

        let mut builder = WarningTxBuilder::default();
        builder
            .set_buyer_input(deposit_tx_builder.buyer_payout()?)
            .set_seller_input(deposit_tx_builder.seller_payout()?)
            .set_escrow_address(escrow_address)
            .set_anchor_address(anchor_address)
            .set_lock_time(LockTime::from_height(2))
            .set_fee_rate(FeeRate::from_sat_per_kwu(1182)) // gives 1000-sat absolute fee
            .compute_unsigned_tx()?;
        Ok(builder)
    }

    //noinspection SpellCheckingInspection
    fn filled_redirect_tx_builder(warning_tx_builder: &WarningTxBuilder) -> Result<RedirectTxBuilder> {
        let receiver_address1 = "bcrt1p88h9s6lq8jw3ehdlljp7sa85kwpp9lvyrl077twvjnackk4lxt0sffnlrk"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let receiver_address2 = "bcrt1phhl8d90r9haqwtvw2cv4ryjl8tlnqrv48nhpy7yyks5du6mr66xq5nlwhz"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let anchor_address = "bcrt1pvescr9nykjvnfw9gffn9kmtpc8fk53fhhv87qayy8pj2h5s65rwsjm9ja4"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;
        let receivers = [
            Receiver { address: receiver_address1, amount: Amount::from_sat(95_998_600) },
            Receiver { address: receiver_address2, amount: Amount::from_sat(63_999_068) },
        ];

        let mut builder = RedirectTxBuilder::default();
        builder
            .set_input(warning_tx_builder.escrow()?)
            .set_receivers(Arc::new(receivers))
            .set_anchor_address(anchor_address)
            .compute_unsigned_tx()?;
        Ok(builder)
    }

    //noinspection SpellCheckingInspection
    fn filled_claim_tx_builder(warning_tx_builder: &WarningTxBuilder) -> Result<ForwardingTxBuilder> {
        let payout_address = "bcrt1pf5vmdnfx03tlwx0j70cpct8zxpg9upf6p5sgsn624yg4a0lnxwxsegnwnx"
            .parse::<Address<_>>()?.require_network(Network::Regtest)?;

        let mut builder = ForwardingTxBuilder::default();
        builder
            .set_input(warning_tx_builder.escrow()?)
            .set_payout_address(payout_address)
            .set_lock_time(LockTime::from_height(2))
            .set_fee_rate(FeeRate::from_sat_per_kwu(2252)) // gives 1000-sat absolute fee
            .compute_unsigned_tx()?;
        Ok(builder)
    }
}
