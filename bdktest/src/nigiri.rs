// Bitcoin and BDK-related imports

// External crates
use std::process::Output;
use std::{collections::HashMap, env, process::Command, str::FromStr, thread, time};
use std::error::Error;
use crate::{build_and_merge_tx, generate_part_tx, transfer_sig_and_broadcast, ConnectedWallet, DepositTx, ProtocolRole, TestWallet, DESCRIPTOR_PRIVATE_EXTERNAL, DESCRIPTOR_PRIVATE_INTERNAL, STOP_GAP};
use bdk_core::bitcoin::{Address, Txid};
use bdk_core::{
    bitcoin::{
        secp256k1::XOnlyPublicKey,
        Amount, Network,
    },
    spk_client::{FullScanRequestBuilder, SyncRequestBuilder},
};
use bdk_core::bitcoin::key::{Keypair, Secp256k1};
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_esplora::esplora_client::Builder;
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_wallet::miniscript::{translate_hash_fail, Descriptor, DescriptorPublicKey, Miniscript, Tap, ToPublicKey, TranslatePk, Translator};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{bitcoin, serde_json, KeychainKind, PersistedWallet, Wallet};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::Network::Bitcoin;
use bdk_wallet::bitcoin::{KnownHrp, WitnessVersion};
use bdk_wallet::bitcoin::key::TapTweak;
use bdk_wallet::miniscript::descriptor::DescriptorType;
use bdk_wallet::miniscript::policy::Concrete;
use bdk_wallet::template::{Bip86, DescriptorTemplate};
use dotenv::dotenv;
use rand::RngCore;

/** run p3 as library
using security by identical generation
*/
#[test]
fn test_protocol() -> anyhow::Result<()> {
    println!("running...");
    check_start();
    let mut alice = funded_wallet();
    let mut bob = funded_wallet();
    fund_wallet(&mut bob);

    // Round 1
    let alice_psbt = generate_part_tx(&mut alice, ProtocolRole::Seller)?;
    let bob_psbt = generate_part_tx(&mut bob, ProtocolRole::Buyer)?;
    // Round2
    let alice_signed = build_and_merge_tx(&mut alice, alice_psbt.clone(), bob_psbt.clone(), ProtocolRole::Seller)?;
    let bob_signed = build_and_merge_tx(&mut bob, bob_psbt, alice_psbt, ProtocolRole::Buyer)?;
    // Round 3
    let alice_txid = transfer_sig_and_broadcast(&alice, alice_signed.clone(), bob_signed.clone(), ProtocolRole::Seller)?;
    println!("Alice txid = {}", alice_txid);
    let bob_txid = transfer_sig_and_broadcast(&bob, bob_signed, alice_signed, ProtocolRole::Seller)?;
    println!("Bob txid = {}", bob_txid);
    tiktok();
    Ok(())
}

/*
-  create_load wallet
- what balance
- if too low, load some btc
- same for bob
- create deposit tx1
-- deposit tx1 has 2 input and needs be signed from both.
-- send the coin to imaginary address.

-- create new wallets for bob and alice
--
 */
#[test]
fn test_2input_tx() {
    println!("running...");
    check_start();
    let alice = funded_wallet();
    let mut bob = funded_wallet();
    fund_wallet(&mut bob);

    let dep = DepositTx::new(alice, bob).unwrap();
    tiktok();
    println!("Txid = {:?}", dep.psbt.extract_tx());
}
#[test]
fn test_wallet() {
    println!("running...");
    check_start();
    let mut alice = funded_wallet();

    // transfer to myself
    let destination = alice.next_unused_address();
    let txid = alice
        .transfer_to_address(destination, Amount::from_btc(0.1).unwrap())
        .unwrap();
    tiktok();
    println!("Txid = {}", txid);
    // try to have a transaction with 2 inputs, from 2 parties
}

pub(crate) fn funded_wallet() -> TestWallet {
    println!("loading wallet...");
    let mut wallet = TestWallet::new().unwrap();
    fund_wallet(&mut wallet);
    wallet
}
pub(crate) fn fund_wallet(wallet: &mut TestWallet) {
    let initial_balance = wallet.balance();
    // load some more coin to wallet
    let adr = wallet.next_unused_address().to_string();
    println!("address = {}", adr);
    fund_address(&*adr);
    loop {
        thread::sleep(time::Duration::from_secs(1));
        wallet.sync().unwrap();
        let balance = wallet.balance();
        println!("\nCurrent wallet amount: {}", balance);

        if balance > initial_balance {
            break;
        }
    }
    assert!(wallet.balance() >= Amount::from_btc(1.0).unwrap());
}

#[test]
fn test_wallet_persist() {
    println!("running...");
    check_start();
    println!("loading wallet...");
    let mut wallet = ConnectedWallet::load_or_create_wallet("bdk-electrum-example.db").unwrap();
    if wallet.balance() < Amount::from_btc(1.0).unwrap() {
        // load some more coin to wallet
        fund_address(&*wallet.next_unused_address().to_string());
    }
    println!("Current wallet amount: {}", wallet.balance());
    assert!(wallet.balance() >= Amount::from_btc(1.0).unwrap());

    // transfer to myself
    let destination = wallet.next_unused_address();
    let txid = wallet
        .transfer_to_address(destination, Amount::from_btc(0.1).unwrap())
        .unwrap();
    tiktok();
    println!("Txid = {}", txid);
    // try to have a transaction with 2 inputs, from 2 parties
}

const FUND_ADDRESS: &str = "bcrt1plrmcqc9pwf4zjcej5n7ynre5k8lkn0xcz0c7y3dw37e8nqew2utq5l06jv";
#[test]
fn test_tx() -> anyhow::Result<()> {
    println!("Starting..");
    check_start();
    // create or load wallet
    // and sync
    let mut con = ConnectedWallet::load_or_create_wallet("bdk-electrum-example.db")?;

    // check balance

    let balance = con.wallet.balance().trusted_spendable();
    println!("Wallet spendable after syncing: {}", balance);

    // load extra monex if to low.
    if balance < Amount::from_btc(1f64)? {
        fund_address(
            con.wallet
                .next_unused_address(KeychainKind::External)
                .to_string()
                .as_str(),
        );
    }
    // start first tx.
    Ok(())
}

#[test]
fn test_fund() {
    check_start();
    fund_address(FUND_ADDRESS);
}
fn fund_address(address: &str) {
    let faucet_response = Command::new("nigiri")
        .args(["faucet", address])
        .output()
        .expect("Failed to fund Alice's wallet");
    eprintln!("{}", String::from_utf8_lossy(&faucet_response.stdout));
    // thread::sleep(time::Duration::from_secs(2)); // Add delays between steps

    eprintln!("Mining mining to {}", address);
    let resp = mine(address, 1);
    eprintln!("reponse {}", String::from_utf8_lossy(&resp.stdout));
}
pub(crate) fn tiktok() -> Output {
    mine(FUND_ADDRESS, 1)
}
fn mine(address: &str, num_blocks: u16) -> Output {
    Command::new("nigiri")
        .args(["rpc", "generatetoaddress", &num_blocks.to_string(), address])
        .output()
        .expect("Failed to mine block")
}

#[test]
pub(crate) fn check_start() {
    // Step 2: Run 'nigiri start' to start Nigiri
    let nigiri_output = Command::new("nigiri").arg("start").output().unwrap();

    if nigiri_output.status.success() {
        eprintln!("Nigiri starting...");
        thread::sleep(time::Duration::from_secs(3));
        eprintln!("Nigiri started successfully.");
    } else {
        let msg = String::from_utf8_lossy(&nigiri_output.stderr);
        if !msg.contains("already running") {
            panic!(
                "Failed to start Nigiri. Please install Docker and Nigiri manually. Error: {}",
                String::from_utf8_lossy(&nigiri_output.stderr)
            );
        }
    }
}

#[test]
fn generate_ms_descriptor_from_tx() -> anyhow::Result<()> {
    dotenv().ok(); // Load environment variables
    let electrum_server =
        env::var("ELECTRUM_SERVER").expect("ELECTRUM_SERVER environment variable must be set");

    let client2 = BdkElectrumClient::new(
        electrum_client::Client::new(&electrum_server) //
            .expect(&format!(
                "electrum server running on {}?",
                &*electrum_server
            )),
    ); //
    let txid: Txid =
        Txid::from_str("8b1488df532c831c69eee8e4fae6b23e2d60c6d68f04c3cb51b3506aa93b8457")?;

    let tx = client2.fetch_tx(txid)?;
    dbg!(&tx);
    // let mut descriptor = "sh(multi(1".to_string();
    // let descriptor = "tr(musig(".to_owned()
    let descriptor = "sh(multi(1,".to_owned()
        + &*tx.input[0].witness[1]
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        + ","
        + &*tx.input[1].witness[1]
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        + "))";

    dbg!(&descriptor);
    let secp = Secp256k1::default();
    let (descr_pub_key, _keymap) =
        Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, descriptor.as_str())?;
    dbg!(&descr_pub_key);

    let address = descr_pub_key.at_derivation_index(0)?.address(Bitcoin)?;
    print!("scritless 2of2 aggregated pubkey {}", address);

    Ok(())
}

/*
spending policy -> miniscript -> bitcoin script
 */
#[test]
fn policy_test() -> Result<(), Box<dyn Error>> {
    // We start with a miniscript policy string
    let policy_str = "or(
        10@thresh(4,
            pk(029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0),
            pk(025f05815e3a1a8a83bfbb03ce016c9a2ee31066b98f567f6227df1d76ec4bd143),
            pk(025625f41e4a065efc06d5019cbbd56fe8c07595af1231e7cbc03fafb87ebb71ec),
            pk(02a27c8b850a00f67da3499b60562673dcf5fdfb82b7e17652a7ac54416812aefd),
            pk(03e618ec5f384d6e19ca9ebdb8e2119e5bef978285076828ce054e55c4daf473e2)
        ),1@and(
            older(4209713),
            thresh(2,
                pk(03deae92101c790b12653231439f27b8897264125ecb2f46f48278603102573165),
                pk(033841045a531e1adf9910a6ec279589a90b3b8a904ee64ffd692bd08a8996c1aa),
                pk(02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068)
            )
        )
    )"
        .replace(&[' ', '\n', '\t'][..], "");

    println!("Compiling policy: \n{}", policy_str);

    // Parse the string as a [`Concrete`] type miniscript policy.
    let policy = Concrete::<String>::from_str(&policy_str)?;

    // Create a `wsh` type descriptor from the policy.
    // `policy.compile()` returns the resulting miniscript from the policy.
    let descriptor = Descriptor::new_wsh(policy.compile()?)?.to_string();

    println!("Compiled into Descriptor: \n{}", descriptor);

    // Create a new wallet from descriptors
    let mut wallet = Wallet::create_single(descriptor)
        .network(Network::Regtest)
        .create_wallet_no_persist()?;

    println!(
        "First derived address from the descriptor: \n{}",
        wallet.next_unused_address(KeychainKind::External),
    );

    // BDK also has it's own `Policy` structure to represent the spending condition in a more
    // human readable json format.
    let spending_policy = wallet.policies(KeychainKind::External)?.unwrap();
    println!(
        "The BDK spending policy: \n{}",
        serde_json::to_string_pretty(&spending_policy)?
    );

    Ok(())
}

// Refer to https://github.com/sanket1729/adv_btc_workshop/blob/master/workshop.md#creating-a-taproot-descriptor
// for a detailed explanation of the policy and it's compilation

// copied from rust-miniscript/examples/taproot.rs

struct StrPkTranslator {
    pk_map: HashMap<String, XOnlyPublicKey>,
}

impl Translator<String, XOnlyPublicKey, ()> for StrPkTranslator {
    fn pk(&mut self, pk: &String) -> Result<XOnlyPublicKey, ()> {
        self.pk_map.get(pk).copied().ok_or(())
    }

    // We don't need to implement these methods as we are not using them in the policy.
    // Fail if we encounter any hash fragments. See also translate_hash_clone! macro.
    translate_hash_fail!(String, XOnlyPublicKey, ());
}

/*
taproot policy, compile tr to minscript, replace placeholders and convert to bitcoin spcript
 */
#[test]
fn testtap() {
    println!("running...");
    let pol_str = "or(
        99@thresh(2,
            pk(hA), pk(S)
        ),1@or(
            99@pk(Ca),
            1@and(pk(In), older(9))
            )
        )"
        .replace(&[' ', '\n', '\t'][..], "");

    // let _ms = Miniscript::<String, Tap>::from_str("and_v(v:ripemd160(H),pk(A))").unwrap();
    let pol = Concrete::<String>::from_str(&pol_str).unwrap();
    // In case we can't find an internal key for the given policy, we set the internal key to
    // a random pubkey as specified by BIP341 (which are *unspendable* by any party :p)
    let desc = pol.compile_tr(Some("UNSPENDABLE_KEY".to_string())).unwrap();

    let expected_desc =
        Descriptor::<String>::from_str("tr(Ca,{and_v(v:pk(In),older(9)),and_v(v:pk(hA),pk(S))})")
            .unwrap();
    assert_eq!(desc, expected_desc);

    // Check whether the descriptors are safe.
    assert!(desc.sanity_check().is_ok());

    // Descriptor type and version should match respectively for taproot
    let desc_type = desc.desc_type();
    assert_eq!(desc_type, DescriptorType::Tr);
    assert_eq!(desc_type.segwit_version().unwrap(), WitnessVersion::V1);

    if let Descriptor::Tr(ref p) = desc {
        // Check if internal key is correctly inferred as Ca
        // assert_eq!(p.internal_key(), &pubkeys[2]);
        assert_eq!(p.internal_key(), "Ca");

        // Iterate through scripts
        let mut iter = p.iter_scripts();
        assert_eq!(
            iter.next().unwrap(),
            (
                1u8,
                &Miniscript::<String, Tap>::from_str("and_v(vc:pk_k(In),older(9))").unwrap()
            )
        );
        assert_eq!(
            iter.next().unwrap(),
            (
                1u8,
                &Miniscript::<String, Tap>::from_str("and_v(v:pk(hA),pk(S))").unwrap()
            )
        );
        assert_eq!(iter.next(), None);
    }

    let mut pk_map = HashMap::new();

    // We require secp for generating a random XOnlyPublicKey
    let secp = Secp256k1::new();
    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    // Random unspendable XOnlyPublicKey provided for compilation to Taproot Descriptor
    let (unspendable_pubkey, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    pk_map.insert("UNSPENDABLE_KEY".to_string(), unspendable_pubkey);
    let pubkeys = hardcoded_xonlypubkeys();
    pk_map.insert("hA".to_string(), pubkeys[0]);
    pk_map.insert("S".to_string(), pubkeys[1]);
    pk_map.insert("Ca".to_string(), pubkeys[2]);
    pk_map.insert("In".to_string(), pubkeys[3]);
    let mut t = StrPkTranslator { pk_map };

    let real_desc = desc.translate_pk(&mut t).unwrap();

    // Max satisfaction weight for compilation, corresponding to the script-path spend
    // `and_v(PUBKEY_1,PUBKEY_2) at tap tree depth 1, having:
    //
    //     max_witness_size = varint(control_block_size) + control_block size +
    //                        varint(script_size) + script_size + max_satisfaction_size
    //                      = 1 + 65 + 1 + 68 + 132 = 269
    let max_sat_wt = real_desc.max_weight_to_satisfy().unwrap().to_wu();
    assert_eq!(max_sat_wt, 267);

    // Compute the bitcoin address and check if it matches
    let network = Network::Bitcoin;
    let addr = real_desc.address(network).unwrap();
    let expected_addr = bitcoin::Address::from_str(
        "bc1p4l2xzq7js40965s5w0fknd287kdlmt2dljte37zsc5a34u0h9c4q85snyd",
    )
        .unwrap()
        .assume_checked();
    assert_eq!(addr, expected_addr);
}

fn hardcoded_xonlypubkeys() -> Vec<XOnlyPublicKey> {
    let serialized_keys: [[u8; 32]; 4] = [
        [
            22, 37, 41, 4, 57, 254, 191, 38, 14, 184, 200, 133, 111, 226, 145, 183, 245, 112, 100,
            42, 69, 210, 146, 60, 179, 170, 174, 247, 231, 224, 221, 52,
        ],
        [
            194, 16, 47, 19, 231, 1, 0, 143, 203, 11, 35, 148, 101, 75, 200, 15, 14, 54, 222, 208,
            31, 205, 191, 215, 80, 69, 214, 126, 10, 124, 107, 154,
        ],
        [
            202, 56, 167, 245, 51, 10, 193, 145, 213, 151, 66, 122, 208, 43, 10, 17, 17, 153, 170,
            29, 89, 133, 223, 134, 220, 212, 166, 138, 2, 152, 122, 16,
        ],
        [
            50, 23, 194, 4, 213, 55, 42, 210, 67, 101, 23, 3, 195, 228, 31, 70, 127, 79, 21, 188,
            168, 39, 134, 58, 19, 181, 3, 63, 235, 103, 155, 213,
        ],
    ];
    let mut keys: Vec<XOnlyPublicKey> = vec![];
    for key in serialized_keys {
        keys.push(XOnlyPublicKey::from_slice(&key).unwrap());
    }
    keys
}
/*
convert taproot policy to taproot miniscript descriptors
 */
#[test]
fn test_policy2descriptor() {
    // convert taprrot policy into taproot descriptor
    println!("running...");
    let pol_str = "or(
        99@thresh(2,
            pk(hA), pk(S)
        ),1@or(
            99@pk(Ca),
            1@and(pk(In), older(9))
            )
        )"
        .replace(&[' ', '\n', '\t'][..], "");
    let pol = Concrete::<String>::from_str(&pol_str).unwrap();
    // In case we can't find an internal key for the given policy, we set the internal key to
    // a random pubkey as specified by BIP341 (which are *unspendable* by any party :p)
    let descriptor = pol.compile_tr(Some("UNSPENDABLE_KEY".to_string())).unwrap();

    descriptor.sanity_check().unwrap();
    println!("Descriptor:\n{}", &descriptor.to_string());
    //
    // let secp = Secp256k1::new();
    //
    // // Parse the descriptor
    // let (descriptor, key_map) = Descriptor::<bdk_wallet::bitcoin::PublicKey>::parse_descriptor(&secp, descriptor_str)?;

    // Convert the descriptor into a script
    let mut pk_map = HashMap::new();

    // We require secp for generating a random XOnlyPublicKey
    let secp = Secp256k1::new();
    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    // Random unspendable XOnlyPublicKey provided for compilation to Taproot Descriptor
    let (unspendable_pubkey, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    pk_map.insert("UNSPENDABLE_KEY".to_string(), unspendable_pubkey);
    let pubkeys = hardcoded_xonlypubkeys();
    pk_map.insert("hA".to_string(), pubkeys[0]);
    pk_map.insert("S".to_string(), pubkeys[1]);
    pk_map.insert("Ca".to_string(), pubkeys[2]);
    pk_map.insert("In".to_string(), pubkeys[3]);
    let mut t = StrPkTranslator { pk_map };

    let real_descriptor = descriptor.translate_pk(&mut t).unwrap();
    println!("Bitcoin script: {}", real_descriptor.script_pubkey());
}
/*
generate new private keys for regtest. BIP-86 taproot single keys.
 */
#[test]
fn create_new_keys() {
    println!("running...");
    let mut seed: [u8; 32] = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    let network: Network = Network::Regtest;
    let xprv: Xpriv = Xpriv::new_master(network, &seed).unwrap();
    println!("Generated Master Private Key:\n{}\nWarning: be very careful with private keys when using MainNet! We are logging these values for convenience only because this is an example on SigNet.\n", xprv);

    let (descriptor, key_map, _) = Bip86(xprv, KeychainKind::External)
        .build(Network::Regtest)
        .expect("Failed to build external descriptor");

    let (change_descriptor, change_key_map, _) = Bip86(xprv, KeychainKind::Internal)
        .build(Network::Regtest)
        .expect("Failed to build internal descriptor");

    let descriptor_string_priv = descriptor.to_string_with_secret(&key_map);
    let change_descriptor_string_priv = change_descriptor.to_string_with_secret(&change_key_map);
    dbg!(&descriptor_string_priv);
    dbg!(&change_descriptor_string_priv);

    let secp = Secp256k1::new();

    let address = Address::p2tr_tweaked(
        xprv.to_priv().public_key(&secp).to_x_only_pubkey().dangerous_assume_tweaked(),
        KnownHrp::Regtest,
    );

    println!("Generated Bitcoin Address: {}", address);
}

const DB_PATH: &str = "bdk-example-esplora-blocking.db";
const PARALLEL_REQUESTS: usize = 1;

// do we still need this, it uses esplora and testnet and mutinynet test coins
fn _wallet_create() -> anyhow::Result<()> {
    // const DESCRIPTOR_PRIVATE_INTERNAL: &str = "tr([d7ed2b9e/86'/1'/0']tpubDC4qsHnap67BkghxNKBEYJg3nkgpoR9B44myunV1UgN2fX8Ff5PRApNVoc9iyTVhsjs6i1masdiaAETr3iUvYYkfkxR35PEtnLFWAE4MYdj/0/*)#ss3vgv5h";
    let mut conn = Connection::open(DB_PATH)?;
    // let mut db = Store::<bdk_wallet::ChangeSet>::open_or_create_new(
    //     "bdk_wallet_esplora_example".as_bytes(),
    //     "bdk-example-esplora-blocking.db",
    // )?;
    let mut wallet = Wallet::create(DESCRIPTOR_PRIVATE_EXTERNAL, DESCRIPTOR_PRIVATE_INTERNAL)
        .network(Network::Signet)
        .create_wallet(&mut conn)?;
    println!("Performing full scan...");
    let client: esplora_client::BlockingClient =
        esplora_client::Builder::new("https://mutinynet.com/api").build_blocking();

    let full_scan_request: FullScanRequestBuilder<KeychainKind> = wallet.start_full_scan();
    let update = client.full_scan(full_scan_request, STOP_GAP, PARALLEL_REQUESTS)?;
    wallet.apply_update(update)?;
    wallet.persist(&mut conn)?;
    println!("Wallet balance: {} sat", wallet.balance().total().to_sat());
    let funding_address = wallet.next_unused_address(KeychainKind::External);
    println!(
        "Next unused address: ({}) {}",
        funding_address.index, funding_address.address
    );
    Ok(())
}
// funding address: tb1pg5hcjpec288zlwmn4drvq497r33evnpmx3fm8038pzdp7ffl94ds8ysha6

#[test]
fn test_deposit() {
    let adr = "tb1pez0yfvf9gqpnn4nwpjh6n7fza96nzgf88pgdgmkms0stzcrj7wqsxdkv32";
    deposit_tx(adr).unwrap();
}
fn deposit_tx(address_string: &str) -> anyhow::Result<()> {
    // create a fake dscriptor
    // We require secp for generating a random XOnlyPublicKey
    // let secp = secp256k1::Secp256k1::new();
    // let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    // // Random unspendable XOnlyPublicKey provided for compilation to Taproot Descriptor
    // let (tr_interal_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
    // let descriptor = Descriptor::new_tr(tr_interal_key, None)?.to_string();
    //
    // // assume wallet being funded
    // let mut wallet = Wallet::create_single(descriptor)
    //     .network(Network::Regtest)
    //     .create_wallet_no_persist()?;

    // construct deposit tx for both of us
    // let p = Concrete::from_str("pk(123)")?.compile_tr(None)?;
    let mut wallet = update_balance()?;

    let pa = Address::from_str(address_string)?.require_network(Network::Signet)?;

    let mut builder = wallet.build_tx();
    builder.add_recipient(pa.script_pubkey(), Amount::from_sat(5000));
    // .add_utxo(outpoint_from_bob)

    let psbt = builder.finish().expect("valid psbt");

    // sign my input
    // let _b = wallet.sign(&mut psbt, Default::default())?;
    // return pbst for Bob to sign
    // print transaction
    dbg!(&psbt);
    let tx = psbt.extract_tx()?;
    dbg!(tx);
    Ok(())
}

/**
using esplora and mutinynet as backend
*/
fn update_balance() -> Result<PersistedWallet<Connection>, anyhow::Error> {
    let mut conn = Connection::open(DB_PATH)?;

    let Some(mut wallet) = Wallet::load()
        .descriptor(KeychainKind::External, Some(DESCRIPTOR_PRIVATE_EXTERNAL))
        .descriptor(KeychainKind::Internal, Some(DESCRIPTOR_PRIVATE_INTERNAL))
        .extract_keys()
        .check_network(Network::Regtest)
        .load_wallet(&mut conn)?
    else {
        panic!("Wallet not found")
    };
    // Perform a regular sync
    println!("Performing regular sync...");
    let sync_request: SyncRequestBuilder<(KeychainKind, u32)> =
        wallet.start_sync_with_revealed_spks();
    let client: esplora_client::BlockingClient =
        Builder::new("https://mutinynet.com/api").build_blocking();
    let update = client.sync(sync_request, PARALLEL_REQUESTS)?;
    wallet.apply_update(update).unwrap();
    wallet.persist(&mut conn)?;
    println!("Wallet balance: {} sat", &wallet.balance().total().to_sat());
    Ok(wallet)
}
/*
tr(UNSPENDABLE, {
  pk(SOME_THIRD_PARTY_PK),
  and_v(v:pk(MY_XONLY_KEY),older(1008))
}
// Add the foreign UTXO
wallet.insert_txout(utxo, txout);


// Spend the recovery path
let mut psbt = wallet
    .build_tx()
    .manually_selected_only()
    .add_utxo(utxo)
    .expect("valid outpoint")
    .add_recipient(change_address.script_pubkey(), amount)
    .fee_rate(fee_rate)
    .clone()
    .finish()
    .expect("valid psbt");
wallet.sign(&mut psbt, Default::default()).unwrap();
 */
