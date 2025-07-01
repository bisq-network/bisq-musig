use musig2::{secp::{MaybeScalar, Point, Scalar}, AdaptorSignature, KeyAggContext, PartialSignature};
// Using the functional API.

pub(crate) fn _m2() {
    let seckeys = [
        Scalar::from_slice(&[0x11; 32]).unwrap(),
        Scalar::from_slice(&[0x22; 32]).unwrap(),
    ];

    let pubkeys = [seckeys[0].base_point_mul(), seckeys[1].base_point_mul()];

    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let message = "danger, will robinson!";
    // let mut csprng = rand::thread_rng();

    let adaptor_secret = Scalar::random(&mut rand::thread_rng());
    // let adaptor_secret = Scalar::random(&mut csprng);
    let adaptor_point = adaptor_secret.base_point_mul();

    use musig2::{AggNonce, SecNonce};

    let secnonces = [
        SecNonce::build([0x11; 32]).build(),
        SecNonce::build([0x22; 32]).build(),
    ];

    let pubnonces = [secnonces[0].public_nonce(), secnonces[1].public_nonce()];

    let aggnonce = AggNonce::sum(&pubnonces);

    let partial_signatures: Vec<PartialSignature> = seckeys
        .into_iter()
        .zip(secnonces)
        .map(|(seckey, secnonce)| {
            musig2::adaptor::sign_partial(
                &key_agg_ctx,
                seckey,
                secnonce,
                &aggnonce,
                adaptor_point,
                &message,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to create partial adaptor signatures");

    let adaptor_signature: AdaptorSignature = musig2::adaptor::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggnonce,
        adaptor_point,
        partial_signatures.iter().copied(),
        &message,
    )
    .expect("failed to aggregate partial adaptor signatures");

    // Verify the adaptor signature is valid for the given adaptor point and pubkey.
    musig2::adaptor::verify_single(
        aggregated_pubkey,
        &adaptor_signature,
        &message,
        adaptor_point,
    )
    .expect("invalid aggregated adaptor signature");

    // Decrypt the signature with the adaptor secret.
    let valid_signature = adaptor_signature.adapt(adaptor_secret).unwrap();

    musig2::verify_single(aggregated_pubkey, valid_signature, &message)
        .expect("invalid decrypted adaptor signature");

    // The decrypted signature and the adaptor signature allow an
    // observer to deduce the adaptor secret.
    let revealed: MaybeScalar = adaptor_signature
        .reveal_secret(&valid_signature)
        .expect("should compute adaptor secret from decrypted signature");

    assert_eq!(revealed, MaybeScalar::Valid(adaptor_secret));
    println!("Done.");
}
