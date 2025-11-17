use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::key::TweakedPublicKey;
use bdk_wallet::bitcoin::taproot::Signature;
use bdk_wallet::bitcoin::{Address, Network, PublicKey, TapNodeHash, TapSighash};
use musig2::adaptor::AdaptorSignature;
use musig2::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, NonceSeed, PartialSignature, PubNonce, SecNonce, SecNonceBuilder,
};
use thiserror::Error;

use crate::transaction::NetworkParams as _;

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
    pub am_buyer: bool,
    pub my_key_share: Option<KeyPair>,
    pub peers_key_share: Option<OptKeyPair>,
    aggregated_key: Option<OptKeyPair>,
    key_agg_ctx: Option<KeyAggContext>,
}

impl KeyCtx {
    pub fn init_my_key_share(&mut self) -> &KeyPair {
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

    pub fn aggregate_key_shares(&mut self) -> Result<()> {
        let agg_ctx = KeyAggContext::new(self.get_key_shares()
            .ok_or(MultisigErrorKind::MissingKeyShare)?)?;
        self.aggregated_key = Some(OptKeyPair::from_public(agg_ctx.aggregated_pubkey()));
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

    pub fn aggregate_prv_key_shares(&mut self) -> Result<&Scalar> {
        let prv_key_shares = self.get_prv_key_shares()
            .ok_or(MultisigErrorKind::MissingKeyShare)?;
        let agg_ctx = self.key_agg_ctx.as_ref()
            .ok_or(MultisigErrorKind::MissingAggPubKey)?;
        let agg_key = self.aggregated_key.as_mut()
            .ok_or(MultisigErrorKind::MissingAggPubKey)?;
        agg_key.set_prv_key(agg_ctx.aggregated_seckey(prv_key_shares)?)
    }

    pub fn get_sellers_prv_key(&self) -> Option<Scalar> {
        if self.am_buyer {
            self.peers_key_share.as_ref()?.prv_key
        } else {
            Some(self.my_key_share.as_ref()?.prv_key)
        }
    }

    pub fn set_sellers_prv_key_if_buyer(&mut self, prv_key: Scalar) -> Result<()> {
        if self.am_buyer {
            self.peers_key_share.as_mut().ok_or(MultisigErrorKind::MissingKeyShare)?.set_prv_key(prv_key)?;
        }
        Ok(())
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

    pub fn compute_p2tr_address(&self, merkle_root: Option<&TapNodeHash>, network: Network) -> Result<Address> {
        let pub_key: Point = self.compute_tweaked_key_agg_ctx(merkle_root)?.aggregated_pubkey();
        // NOTE: We have to round-trip the public key because 'musig2' & 'bitcoin' currently use
        // different versions of the 'secp256k1' crate:
        let pub_key = PublicKey::from_slice(&pub_key.serialize_uncompressed())
            .expect("curve point should have a valid uncompressed DER encoding").into();

        // This is safe, as we just performed a Taproot tweak above (via the 'musig2::secp' crate):
        Ok(Address::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(pub_key), network))
    }
}

// TODO: For safety, this should hold a reference to the KeyCtx our nonce & signature share (& final
//  aggregation) are built from, so that we don't have to pass it repeatedly as a method parameter.
#[derive(Default)]
pub struct SigCtx {
    pub am_buyer: bool,
    pub merkle_root: Option<TapNodeHash>,
    pub adaptor_point: MaybePoint,
    pub my_nonce_share: Option<NoncePair>,
    pub peers_nonce_share: Option<PubNonce>,
    aggregated_nonce: Option<AggNonce>,
    message: Option<TapSighash>,
    pub my_partial_sig: Option<PartialSignature>,
    pub peers_partial_sig: Option<PartialSignature>,
    pub aggregated_sig: Option<AdaptorSignature>,
}

impl SigCtx {
    pub fn set_warning_output_merkle_root(&mut self, claim_pub_key: &Point, network: Network) -> &TapNodeHash {
        // NOTE: We have to round-trip the public key because 'musig2' & 'bitcoin' currently use
        // different versions of the 'secp256k1' crate:
        let claim_pub_key = PublicKey::from_slice(&claim_pub_key.serialize_uncompressed())
            .expect("curve point should have a valid uncompressed DER encoding").into();
        self.merkle_root.insert(network.warning_output_merkle_root(&claim_pub_key))
    }

    pub fn init_my_nonce_share(&mut self, key_ctx: &KeyCtx) -> Result<()> {
        let aggregated_pub_key = key_ctx.aggregated_key.as_ref()
            .ok_or(MultisigErrorKind::MissingAggPubKey)?.pub_key;
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

    pub fn sign_partial(&mut self, key_ctx: &KeyCtx, message: TapSighash) -> Result<&PartialSignature> {
        // TODO: It's wasteful not to cache the tweaked KeyAggCtx -- refactor:
        let key_agg_ctx = key_ctx.compute_tweaked_key_agg_ctx(self.merkle_root.as_ref())?;
        let seckey = key_ctx.my_key_share.as_ref()
            .ok_or(MultisigErrorKind::MissingKeyShare)?.prv_key;
        let secnonce = self.my_nonce_share.as_mut()
            .ok_or(MultisigErrorKind::MissingNonceShare)?.sec_nonce.take()
            .ok_or(MultisigErrorKind::NonceReuse)?;
        let aggregated_nonce = &self.aggregated_nonce.as_ref()
            .ok_or(MultisigErrorKind::MissingAggNonce)?;

        let sig = musig2::adaptor::sign_partial(&key_agg_ctx, seckey, secnonce, aggregated_nonce,
            self.adaptor_point, message.as_byte_array())?;
        self.message = Some(message);
        Ok(self.my_partial_sig.insert(sig))
    }

    fn get_partial_signatures(&self) -> Option<[PartialSignature; 2]> {
        Some(if self.am_buyer {
            [self.my_partial_sig?, self.peers_partial_sig?]
        } else {
            [self.peers_partial_sig?, self.my_partial_sig?]
        })
    }

    pub fn aggregate_partial_signatures(&mut self, key_ctx: &KeyCtx) -> Result<&AdaptorSignature> {
        // TODO: It's wasteful not to cache the tweaked KeyAggCtx -- refactor:
        let key_agg_ctx = key_ctx.compute_tweaked_key_agg_ctx(self.merkle_root.as_ref())?;
        let aggregated_nonce = &self.aggregated_nonce.as_ref()
            .ok_or(MultisigErrorKind::MissingAggNonce)?;
        let partial_signatures = self.get_partial_signatures()
            .ok_or(MultisigErrorKind::MissingPartialSig)?;
        let message = &self.message.as_ref()
            .ok_or(MultisigErrorKind::MissingPartialSig)?[..];

        let sig = musig2::adaptor::aggregate_partial_signatures(&key_agg_ctx, aggregated_nonce,
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
    KeyAgg(#[from] musig2::errors::KeyAggError),
    Signing(#[from] musig2::errors::SigningError),
    Verify(#[from] musig2::errors::VerifyError),
    Tweak(#[from] musig2::errors::TweakError),
    InvalidSecretKeys(#[from] musig2::errors::InvalidSecretKeysError),
}
