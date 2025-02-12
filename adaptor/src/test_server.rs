#[cfg(test)]
mod test_server {
    use bdk::bitcoin::secp256k1::Secp256k1;
    use bdk::bitcoin::Network::Bitcoin;
    use bdk::bitcoin::Txid;
    use bdk::descriptor::{Descriptor, DescriptorPublicKey};
    use bdk::electrum_client;
    use bdk::electrum_client::ElectrumApi;
    use dotenv::dotenv;
    use musig2::KeyAggContext;
    use secp::{Point, Scalar};
    use std::env;
    use std::str::FromStr;

    /// Tests that the order of secret keys matters in MuSig2 key aggregation.
    /// This verifies that:
    /// 1. Aggregation succeeds when secret keys are provided in the same order as their public keys
    /// 2. Aggregation fails when secret keys are provided in a different order
    /// 3. The aggregated public key matches the public key derived from correctly ordered secret keys
    #[test]
    fn test_order_seckeys() {
        let seckeys = [
            Scalar::from_slice(&[0x11; 32]).unwrap(),
            Scalar::from_slice(&[0x22; 32]).unwrap(),
        ];

        let pubkeys: [Point; 2] = [
            seckeys[0].base_point_mul(),
            seckeys[1].base_point_mul()
        ];

        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

        let agg_sec1: Scalar = key_agg_ctx
            .aggregated_seckey([seckeys[0], seckeys[1]])
            .expect("Aggregation with correct order should succeed");
        
        let agg_sec2: Result<Scalar, _> = key_agg_ctx.aggregated_seckey([seckeys[1], seckeys[0]]);
        assert!(agg_sec2.is_err(), "Aggregation with wrong order should fail");

        assert_eq!(
            aggregated_pubkey,
            agg_sec1.base_point_mul(),
            "Aggregated public key should match public key derived from correctly ordered secret keys"
        );

        println!("Done.");
    }
    /**
    This test just checks if there is an electrum server (like electrs) running.
    It does get a transaction from that server, which is on main net

    this test only works on mainnet for now...
    ELECTRUM_SERVER=192.168.178.31:50001
    */
    #[test]
    fn test_electrum_server() {
        generate_ms_descriptor_from_tx().unwrap();
    }
    fn generate_ms_descriptor_from_tx() -> anyhow::Result<()> {
        dotenv().ok(); // Load environment variables
        let electrum_server =
            env::var("ELECTRUM_SERVER").expect("ELECTRUM_SERVER environment variable must be set");

        let client = electrum_client::Client::new(&electrum_server).expect(&format!(
            "electrum server running on {}?",
            &*electrum_server
        ));
        let txid: Txid =
            Txid::from_str("37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517")?;

        let tx = client.transaction_get(&txid)?;

        let mut descriptor = "sh(multi(1".to_string();
        descriptor += tx
            .input
            .iter()
            .map(|vin| &vin.witness[1])
            .map(|pubkey| {
                format!(
                    ",{}",
                    pubkey
                        .into_iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                )
            })
            .collect::<String>()
            .as_str();

        descriptor += "))";
        dbg!(&descriptor);
        let secp = Secp256k1::default();
        let (descr_pub_key, _keymap) =
            Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, descriptor.as_str())?;

        let address = descr_pub_key
            .derived_descriptor(&secp, 0)?
            .address(Bitcoin)?;

        print!("{}", address);
        Ok(())
    }
}
