use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::key::TweakedPublicKey;
use bdk_wallet::bitcoin::taproot::Signature;
use bdk_wallet::bitcoin::{Address, Network, PublicKey, TapNodeHash, TapSighash};
use musig2::adaptor::AdaptorSignature;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, LiftedSignature, NonceSeed, PartialSignature, PubNonce, SecNonce,
    SecNonceBuilder,
};
use thiserror::Error;

pub struct KeyPair {
    pub pub_key: Point,
    pub prv_key: Scalar,
}

impl KeyPair {
    fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        Self::from_private(Scalar::random(rng))
    }

    fn from_private(prv_key: Scalar) -> Self {
        Self { pub_key: prv_key.base_point_mul(), prv_key }
    }
}

pub struct OptKeyPair {
    pub pub_key: Point,
    pub prv_key: Option<Scalar>,
}

impl OptKeyPair {
    pub const fn from_public(pub_key: Point) -> Self {
        Self { pub_key, prv_key: None }
    }

    pub fn set_prv_key(&mut self, prv_key: Scalar) -> Result<&Scalar> {
        if self.pub_key != prv_key.base_point_mul() {
            return Err(MultisigErrorKind::MismatchedKeyPair);
        }
        Ok(self.prv_key.insert(prv_key))
    }
}

pub struct NoncePair {
    pub pub_nonce: PubNonce,
    pub sec_nonce: Option<SecNonce>,
}

impl NoncePair {
    fn new(nonce_seed: impl Into<NonceSeed>, aggregated_pub_key: Point) -> Self {
        let sec_nonce = SecNonceBuilder::new(nonce_seed)
            .with_aggregated_pubkey(aggregated_pub_key)
            .build();
        Self { pub_nonce: sec_nonce.public_nonce(), sec_nonce: Some(sec_nonce) }
    }
}

#[derive(Default)]
pub struct KeyCtx {
    pub my_key_share: Option<KeyPair>,
    pub peers_key_share: Option<OptKeyPair>,
    aggregated_key: Option<OptKeyPair>,
    key_agg_ctx: Option<KeyAggContext>,
}

impl KeyCtx {
    pub fn init_my_key_share(&mut self) -> &KeyPair {
        // TODO: Consider making the RNG configurable, to aid unit testing. (Also, we may not
        //  necessarily want to use a nondeterministic random key share):
        self.my_key_share.insert(KeyPair::random(&mut rand::rng()))
    }

    fn is_my_key_share_first(&self) -> Option<bool> {
        Some(self.my_key_share.as_ref()?.pub_key <= self.peers_key_share.as_ref()?.pub_key)
    }

    fn get_key_shares(&self) -> Option<[Point; 2]> {
        Some(if self.is_my_key_share_first()? {
            [self.my_key_share.as_ref()?.pub_key, self.peers_key_share.as_ref()?.pub_key]
        } else {
            [self.peers_key_share.as_ref()?.pub_key, self.my_key_share.as_ref()?.pub_key]
        })
    }

    pub fn aggregate_key_shares(&mut self) -> Result<()> {
        let agg_ctx = KeyAggContext::new(self.get_key_shares()
            .ok_or(MultisigErrorKind::MissingKeyShare)?)?;
        self.aggregated_key = Some(OptKeyPair::from_public(agg_ctx.aggregated_pubkey()));
        self.key_agg_ctx = Some(agg_ctx);
        Ok(())
    }

    fn get_prv_key_shares(&self) -> Option<[Scalar; 2]> {
        Some(if self.is_my_key_share_first()? {
            [self.my_key_share.as_ref()?.prv_key, self.peers_key_share.as_ref()?.prv_key?]
        } else {
            [self.peers_key_share.as_ref()?.prv_key?, self.my_key_share.as_ref()?.prv_key]
        })
    }

    pub fn aggregate_prv_key_shares(&mut self) -> Result<&Scalar> {
        let prv_key_shares = self.get_prv_key_shares()
            .ok_or(MultisigErrorKind::MissingKeyShare)?;
        let agg_ctx = self.key_agg_ctx.as_ref()
            .ok_or(MultisigErrorKind::MissingAggPubKey)?;
        let agg_key = self.aggregated_key.as_mut()
            .ok_or(MultisigErrorKind::MissingAggPubKey)?;
        agg_key.set_prv_key(agg_ctx.aggregated_seckey(prv_key_shares)?)
    }

    pub fn my_prv_key(&self) -> Result<Scalar> {
        Ok(self.my_key_share.as_ref().ok_or(MultisigErrorKind::MissingKeyShare)?.prv_key)
    }

    pub fn set_peers_prv_key(&mut self, prv_key: Scalar) -> Result<&Scalar> {
        self.peers_key_share.as_mut().ok_or(MultisigErrorKind::MissingKeyShare)?.set_prv_key(prv_key)
    }

    pub fn with_taproot_tweak(&self, merkle_root: Option<&TapNodeHash>) -> Result<TweakedKeyCtx> {
        let tweaked_key_agg_ctx = self.compute_tweaked_key_agg_ctx(merkle_root)?;
        Ok(TweakedKeyCtx { my_prv_key: self.my_prv_key()?, key_agg_ctx: tweaked_key_agg_ctx })
    }

    fn compute_tweaked_key_agg_ctx(&self, merkle_root: Option<&TapNodeHash>) -> Result<KeyAggContext> {
        let key_agg_ctx = self.key_agg_ctx.clone()
            .ok_or(MultisigErrorKind::MissingAggPubKey)?;
        Ok(if let Some(merkle_root) = merkle_root {
            key_agg_ctx.with_taproot_tweak(merkle_root.as_byte_array())?
        } else {
            key_agg_ctx.with_unspendable_taproot_tweak()?
        })
    }
}

#[derive(Clone)]
pub struct TweakedKeyCtx {
    my_prv_key: Scalar,
    key_agg_ctx: KeyAggContext,
}

impl TweakedKeyCtx {
    pub fn p2tr_address(&self, network: Network) -> Address {
        let pub_key: Point = self.key_agg_ctx.aggregated_pubkey();
        let pub_key = pub_key.to_public_key().into();

        // This is safe, as `self` can only be constructed with a Taproot tweak applied to its
        // inner KeyAggContext (performed via the 'musig2::secp' crate):
        Address::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(pub_key), network)
    }
}

#[derive(Default)]
pub struct SigCtx {
    pub tweaked_key_ctx: Option<TweakedKeyCtx>,
    pub adaptor_point: MaybePoint,
    pub my_nonce_share: Option<NoncePair>,
    pub peers_nonce_share: Option<PubNonce>,
    aggregated_nonce: Option<AggNonce>,
    message: Option<TapSighash>,
    pub my_partial_sig: Option<PartialSignature>,
    pub peers_partial_sig: Option<PartialSignature>,
    aggregated_sig: Option<AdaptorSignature>,
}

impl SigCtx {
    fn tweaked_key_ctx(&self) -> Result<&TweakedKeyCtx> {
        self.tweaked_key_ctx.as_ref().ok_or(MultisigErrorKind::MissingAggPubKey)
    }

    pub fn aggregated_sig(&self) -> Result<&AdaptorSignature> {
        self.aggregated_sig.as_ref().ok_or(MultisigErrorKind::MissingAggSig)
    }

    pub fn init_my_nonce_share(&mut self) -> Result<()> {
        let aggregated_pub_key = self.tweaked_key_ctx()?.key_agg_ctx.aggregated_pubkey();
        // TODO: Consider making the RNG configurable, to aid unit testing:
        self.my_nonce_share = Some(NoncePair::new(&mut rand::rng(), aggregated_pub_key));
        Ok(())
    }

    fn get_nonce_shares(&self) -> Option<[&PubNonce; 2]> {
        Some([&self.my_nonce_share.as_ref()?.pub_nonce, self.peers_nonce_share.as_ref()?])
    }

    pub fn aggregate_nonce_shares(&mut self) -> Result<&AggNonce> {
        let agg_nonce = AggNonce::sum(self.get_nonce_shares()
            .ok_or(MultisigErrorKind::MissingKeyShare)?);
        if matches!((&agg_nonce.R1, &agg_nonce.R2), (MaybePoint::Infinity, MaybePoint::Infinity)) {
            // Fail early if the aggregated nonce is zero, since otherwise an attacker could force
            // the final signature nonce to be equal to the base point, G. While that might not be
            // a problem (for us), there would be an attack vector if such signatures were ever
            // deemed to be nonstandard. (Note that being able to assign blame later by allowing
            // this through is unimportant for a two-party protocol.)
            return Err(MultisigErrorKind::ZeroNonce);
        }
        Ok(self.aggregated_nonce.insert(agg_nonce))
    }

    pub fn sign_partial(&mut self, message: TapSighash) -> Result<&PartialSignature> {
        let secnonce = self.my_nonce_share.as_mut()
            .ok_or(MultisigErrorKind::MissingNonceShare)?.sec_nonce.take()
            .ok_or(MultisigErrorKind::NonceReuse)?;
        let aggregated_nonce = &self.aggregated_nonce.as_ref()
            .ok_or(MultisigErrorKind::MissingAggNonce)?;
        let key_agg_ctx = &self.tweaked_key_ctx()?.key_agg_ctx;
        let seckey = self.tweaked_key_ctx()?.my_prv_key;

        let sig = musig2::adaptor::sign_partial(key_agg_ctx, seckey, secnonce, aggregated_nonce,
            self.adaptor_point, message.as_byte_array())?;
        self.message = Some(message);
        Ok(self.my_partial_sig.insert(sig))
    }

    fn get_partial_signatures(&self) -> Option<[PartialSignature; 2]> {
        Some([self.my_partial_sig?, self.peers_partial_sig?])
    }

    pub fn aggregate_partial_signatures(&mut self) -> Result<&AdaptorSignature> {
        let key_agg_ctx = &self.tweaked_key_ctx()?.key_agg_ctx;
        let aggregated_nonce = &self.aggregated_nonce.as_ref()
            .ok_or(MultisigErrorKind::MissingAggNonce)?;
        let partial_signatures = self.get_partial_signatures()
            .ok_or(MultisigErrorKind::MissingPartialSig)?;
        let message = self.message.as_ref()
            .ok_or(MultisigErrorKind::MissingPartialSig)?;

        let sig = musig2::adaptor::aggregate_partial_signatures(key_agg_ctx, aggregated_nonce,
            self.adaptor_point, partial_signatures, message)?;
        Ok(self.aggregated_sig.insert(sig))
    }

    pub fn compute_taproot_signature(&self, adaptor_secret: MaybeScalar) -> Result<Signature> {
        let adaptor_sig = self.aggregated_sig
            .ok_or(MultisigErrorKind::MissingAggSig)?;
        let sig_bytes: [u8; 64] = adaptor_sig.adapt(adaptor_secret)
            .ok_or(MultisigErrorKind::ZeroNonce)?;
        Ok(Signature::from_slice(&sig_bytes).expect("len = 64"))
    }

    pub fn reveal_adaptor_secret(&self, signature: Signature) -> Result<Scalar> {
        let final_sig = LiftedSignature::from_bytes(&signature.serialize())?;
        let adaptor_sig = self.aggregated_sig()?;
        let adaptor_secret: MaybeScalar = adaptor_sig.reveal_secret(&final_sig)
            .ok_or(MultisigErrorKind::MismatchedSigs)?;
        Ok(adaptor_secret.try_into()?)
    }
}

pub trait PointExt {
    fn to_public_key(&self) -> PublicKey;
}

impl PointExt for Point {
    fn to_public_key(&self) -> PublicKey {
        // NOTE: We have to round-trip the public key because 'musig2' & 'bitcoin' currently use
        // different versions of the 'secp256k1' crate:
        PublicKey::from_slice(&self.serialize_uncompressed())
            .expect("curve point should have a valid uncompressed DER encoding")
    }
}

type Result<T, E = MultisigErrorKind> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[error(transparent)]
#[non_exhaustive]
pub enum MultisigErrorKind {
    #[error("missing key share")]
    MissingKeyShare,
    #[error("missing nonce share")]
    MissingNonceShare,
    #[error("missing partial signature")]
    MissingPartialSig,
    #[error("missing aggregated pubkey")]
    MissingAggPubKey,
    #[error("missing aggregated signature")]
    MissingAggSig,
    #[error("missing aggregated nonce")]
    MissingAggNonce,
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
}
