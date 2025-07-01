use musig2::{
    AdaptorSignature, AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce,
    SecNonce,
};
use rand::Rng;
use musig2::secp::{MaybeScalar, Point, Scalar};
/*
Let's assume Alice and Bob have a 2of2 Multisig, where they hold one key each already.
This module we try to simulate a peer to peer communication for 2of2 Multisig with adaptor

Now Alice says, if you give me your signature for this transaction of the multisig, then you can
retrieve the private key for this public key.

Here this is all done scriptless.
 */
pub(crate) fn key4sig() {
    // create the Alice and Bob
    let mut alice = M2a::new();
    let mut bob = M2a::new();

    // alice holds the adaptor secrekt
    alice.sec_adaptor = Some(Scalar::random(&mut rand::thread_rng())); // adaptor should be in real scenario something meaningful
    let pub_adaptor = alice.sec_adaptor.unwrap().base_point_mul();
    alice.pub_adaptor = Some(pub_adaptor); // like a signature to other TX or private Key to another multisig
    bob.pub_adaptor = Some(pub_adaptor);

    // now Alice and Bob are initialized
    // Alice runs the p3 to receive the signature from Bob and reveals to him the adaptor_secret
    let bob_adaptor_secret = alice.ms_adaptor(bob);

    // now the secret_adapt must have transported from alice to bob
    assert_eq!(bob_adaptor_secret, alice.sec_adaptor.unwrap());
    println!("Done.");
}
/**
struct to hold all data for this p3. Most data will be added successively.
that's my fields are Options.
*/
struct M2a {
    ctx: Option<KeyAggContext>,
    sec_adaptor: Option<Scalar>, // private / secure adaptor
    pub_adaptor: Option<Point>,  // public / encrypted adaptor
    sec_key: Scalar,
    pub_key: Point,
    other_pubkey: Option<Point>,
    message: Option<String>,
    aggregated_pubkey: Option<Point>,
    sec_nonce: Option<SecNonce>,
    agg_nonce: Option<AggNonce>,
    adaptor_signature: Option<AdaptorSignature>,
}

impl M2a {
    pub(crate) fn ms_adaptor(&mut self, mut other: M2a) -> Scalar {
        // first exchange the pubkeys.
        self.exchange_pubkey(other.exchange_pubkey(self.pub_key));
        let message = String::from("Serialisation of Transaction in question.");
        self.agree_on_message(&message);
        other.agree_on_message(&message);
        self.exchange_nonce(other.exchange_nonce(self.sec_nonce.clone().unwrap().public_nonce()));
        // Alice must sign first and send it to Bob
        let mysig = self.adapted_part_sign();
        self.exchange_part_sig(other.exchange_part_sig(mysig));

        let valid_sig = self.sign_and_publish();
        // in real cases, the valid_signature will get to the other side through mempool or blockchain.
        other.reveal(valid_sig)
    }

    fn new() -> M2a {
        let k = Scalar::random(&mut rand::thread_rng());
        M2a {
            ctx: None,
            sec_adaptor: None,
            pub_adaptor: None,
            sec_key: k,
            pub_key: k.base_point_mul(),
            other_pubkey: None,
            message: None,
            aggregated_pubkey: None,
            sec_nonce: None,
            agg_nonce: None,
            adaptor_signature: None,
        }
    }

    fn exchange_pubkey(&mut self, opub: Point) -> Point {
        self.other_pubkey = Some(opub);
        // now we can compute the aggregated key
        // the public keys need to be ordered, otherwise alice and Bob will compute different
        // aggregated key from same public keys.
        let pubkeys = if opub < self.pub_key {
            [self.pub_key, opub]
        } else {
            [opub, self.pub_key]
        };

        println!("Exchange pubkeys: {:?}", pubkeys);
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        self.ctx = Some(key_agg_ctx.clone());
        self.aggregated_pubkey = key_agg_ctx.aggregated_pubkey();
        println!("aggregrated_key {:?}", self.aggregated_pubkey);
        self.pub_key
    }

    pub(crate) fn agree_on_message(&mut self, msg: &str) {
        self.message = Some(msg.to_string());
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);

        let nonce = SecNonce::generate(
            // &mut rand::rngs::OsRng,
            seed,
            self.sec_key,
            self.aggregated_pubkey.unwrap(),
            &self.message.clone().unwrap(),
            "12345",
        );
        self.sec_nonce = Option::from(nonce);
    }

    fn exchange_nonce(&mut self, othernonce: PubNonce) -> PubNonce {
        let mynonce = self.sec_nonce.clone().unwrap().public_nonce();
        self.agg_nonce = Some(AggNonce::sum([mynonce.clone(), othernonce]));
        mynonce
    }

    fn adapted_part_sign(&self) -> PartialSignature {
        musig2::adaptor::sign_partial(
            &self.ctx.clone().unwrap(),
            self.sec_key,
            self.sec_nonce.clone().unwrap(),
            &self.agg_nonce.clone().unwrap(),
            self.pub_adaptor.unwrap(),
            &self.message.clone().unwrap(),
        )
            .expect("Signing partial signature failed.")
    }

    fn exchange_part_sig(&mut self, othersig: PartialSignature) -> PartialSignature {
        let mysig = self.adapted_part_sign();

        let adaptor_signature = musig2::adaptor::aggregate_partial_signatures(
            &self.ctx.clone().unwrap(),
            &self.agg_nonce.clone().unwrap(),
            self.pub_adaptor.unwrap(),
            [othersig, mysig],
            &self.message.clone().unwrap(),
        )
            .expect("failed to aggregate partial adaptor signatures");
        self.adaptor_signature = Some(adaptor_signature);

        // Verify the adaptor signature is valid for the given adaptor point and pubkey.
        musig2::adaptor::verify_single(
            self.aggregated_pubkey.clone().unwrap(),
            &adaptor_signature,
            &self.message.clone().unwrap(),
            self.pub_adaptor.clone().unwrap(),
        )
            .expect("invalid aggregated adaptor signature");
        mysig // return mysig only if all is ok, otherwise Alice may have scamed me.
    }

    pub(crate) fn sign_and_publish(&mut self) -> LiftedSignature {
        // Decrypt the signature with the adaptor secret.
        let valid_signature: LiftedSignature = self
            .adaptor_signature
            .unwrap()
            .adapt(self.sec_adaptor.unwrap())
            .unwrap();

        musig2::verify_single(
            self.aggregated_pubkey.unwrap(),
            valid_signature,
            &self.message.clone().unwrap(),
        )
            .expect("invalid decrypted adaptor signature");
        valid_signature
    }

    fn reveal(&mut self, valid_sig: LiftedSignature) -> Scalar {
        // The decrypted signature and the adaptor signature allow an
        // observer to deduce the adaptor secret.
        let revealed: MaybeScalar = self
            .adaptor_signature
            .unwrap()
            .reveal_secret(&valid_sig)
            .expect("should compute adaptor secret from decrypted signature");

        self.sec_adaptor = Some(revealed.unwrap());
        self.sec_adaptor.unwrap()
    }
}
