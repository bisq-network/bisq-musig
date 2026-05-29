//! `(XOnlyPublicKey -> BIP32 child index)` map kept by the protocol layer.
//!
//! Every internal key the protocol mints via `TradeWallet::new_internal_key` carries an
//! associated BIP32 child index. Recording the pair as it's produced lets us populate
//! `bip32_derivation` on the deposit-payout PSBT at signing time without having to
//! reverse-look-up the index from the key (i.e. without `Wallet::derivation_of_spk`).
//!
//! The map lives on the protocol side (typically inside `BMPContext`) so that the wallet
//! layer can stay key-management-only and doesn't need to expose any
//! `update_psbt_with_derivation_paths`-like method.

use std::collections::HashMap;

use bdk_wallet::bitcoin::{Psbt, XOnlyPublicKey};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor};
use bdk_wallet::miniscript::ToPublicKey as _;

use crate::transaction::{Result, TransactionErrorKind};

/// Records `(internal_key, derivation_index)` pairs for keys minted via
/// `TradeWallet::new_internal_key`, and applies them to a PSBT's `bip32_derivation`
/// when signing.
///
/// Intended use:
/// 1. Whenever the protocol calls `wallet.new_internal_key()`, immediately [`record`](Self::record)
///    the returned `(key, index)` pair.
/// 2. Just before passing a PSBT to the wallet for signing, call
///    [`populate_bip32_derivation`](Self::populate_bip32_derivation) on a clone of the PSBT, then
///    have the wallet sign the clone, then merge signatures back into the original PSBT. (See
///    `protocol::psbt::populate_then_sign` for the wrapper.)
#[derive(Debug, Default, Clone)]
pub struct InternalKeyIndexMap {
    inner: HashMap<XOnlyPublicKey, u32>,
}

impl InternalKeyIndexMap {
    /// Construct an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a `(key, index)` pair. Overwrites any existing entry for `key` -- the
    /// underlying keychain only ever derives one key per index, so re-recording is a
    /// no-op in practice.
    pub fn record(&mut self, key: XOnlyPublicKey, index: u32) {
        self.inner.insert(key, index);
    }

    /// Look up the BIP32 child index that was recorded for `key`, if any.
    #[must_use]
    pub fn get(&self, key: &XOnlyPublicKey) -> Option<u32> {
        self.inner.get(key).copied()
    }

    /// True if no `(key, index)` pairs have been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// For every key in every input's `tap_key_origins`, look up the recorded index in
    /// this map and populate `bip32_derivation` with the corresponding
    /// `(pub_key, key_source)` derived from the wallet's external Taproot descriptor.
    ///
    /// Keys not present in the map are silently skipped: the trade-deposit PSBT also
    /// carries keys we *don't* own (the peer's contributed `pk(...)`, the descriptor's
    /// literal placeholder), and erroring on those would make every signing fail.
    /// As an end-to-end consistency check, this method does fail outright if the map
    /// is entirely empty -- that case can only mean the protocol layer forgot to record
    /// freshly minted keys, which would silently break signing further down the line.
    pub fn populate_bip32_derivation(
        &self,
        psbt: &mut Psbt,
        external_descriptor: &ExtendedDescriptor,
    ) -> Result<()> {
        if self.is_empty() {
            // Defensive: callers should always have at least one (own) internal key
            // recorded by the time they hand the PSBT to the wallet for signing.
            // An empty map here means either the caller wired this up wrong or the
            // protocol forgot to call `record(...)` after `new_internal_key()`.
            return Err(TransactionErrorKind::EmptyKeyIndexMap);
        }
        for input in &mut psbt.inputs {
            for key in input.tap_key_origins.keys() {
                let Some(index) = self.get(key) else { continue };
                let desc = external_descriptor
                    .at_derivation_index(index)
                    .expect("child can't be hardened");
                if let Descriptor::Tr(tr) = desc {
                    let ik = tr.internal_key();
                    let pub_key = ik.to_public_key().inner;
                    let key_source = (
                        ik.master_fingerprint(),
                        ik.full_derivation_path().expect("descriptor is definite"),
                    );
                    input.bip32_derivation.insert(pub_key, key_source);
                }
            }
        }
        Ok(())
    }
}
