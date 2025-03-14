use bdk_wallet::{AddressInfo, Balance, KeychainKind, LocalOutput, Wallet};
use bdk_wallet::bitcoin::{Network, Transaction, Txid};
use bdk_wallet::chain::{CheckPoint, ChainPosition, ConfirmationBlockTime};
use bdk_bitcoind_rpc::Emitter;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi as _};
use std::prelude::rust_2021::*;
use std::sync::{Arc, RwLock};

const COOKIE_FILE_PATH: &str = ".localnet/bitcoind/regtest/.cookie";
const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAj\
    WytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAj\
    WytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";

pub trait WalletService {
    fn connect(&self);
    fn balance(&self) -> Balance;
    fn reveal_next_address(&self) -> AddressInfo;
    fn list_unspent(&self) -> Vec<LocalOutput>;
    fn get_tx_confidence(&self, txid: Txid) -> Option<TxConfidence>;
}

pub struct WalletServiceImpl {
    wallet: RwLock<Wallet>,
}

impl WalletServiceImpl {
    pub fn new() -> WalletServiceImpl {
        let wallet: Wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();

        WalletServiceImpl { wallet: RwLock::new(wallet) }
    }
}

impl WalletService for WalletServiceImpl {
    // FIXME: This currently panics in case of failure to sync. Make error handling more robust.
    fn connect(&self) {
        let rpc_client: Client = Client::new(
            "https://127.0.0.1:18443",
            Auth::CookieFile(COOKIE_FILE_PATH.into()),
        ).unwrap();

        let blockchain_info = rpc_client.get_blockchain_info().unwrap();
        println!("Connected to Bitcoin Core RPC.\n  Chain: {}\n  Latest block: {} at height {}",
            blockchain_info.chain, blockchain_info.best_block_hash, blockchain_info.blocks);

        let wallet_tip: CheckPoint = self.wallet.read().unwrap().latest_checkpoint();
        let start_height = wallet_tip.height();
        println!("Current wallet tip is: {} at height {}", wallet_tip.hash(), start_height);

        let mut emitter = Emitter::new(&rpc_client, wallet_tip, start_height);
        while let Some(block) = emitter.next_block().unwrap() {
            print!(" {}", block.block_height());
            self.wallet.write().unwrap()
                .apply_block_connected_to(&block.block, block.block_height(), block.connected_to())
                .unwrap();
        }
        println!();

        println!("Syncing mempool...");
        let mempool_emissions = emitter.mempool().unwrap();
        self.wallet.write().unwrap().apply_unconfirmed_txs(mempool_emissions);

        println!("Wallet balance after syncing: {}", self.balance().total());
    }

    fn balance(&self) -> Balance {
        self.wallet.read().unwrap().balance()
    }

    fn reveal_next_address(&self) -> AddressInfo {
        self.wallet.write().unwrap().reveal_next_address(KeychainKind::External)
    }

    fn list_unspent(&self) -> Vec<LocalOutput> {
        self.wallet.read().unwrap().list_unspent().collect()
    }

    fn get_tx_confidence(&self, txid: Txid) -> Option<TxConfidence> {
        let wallet = self.wallet.read().unwrap();
        let wallet_tx: WalletTx = wallet.get_tx(txid)?.into();
        let next_height = wallet.latest_checkpoint().height() + 1;
        drop(wallet);
        let conf_height = wallet_tx.chain_position.confirmation_height_upper_bound().unwrap_or(next_height);
        let num_confirmations = next_height - conf_height;
        Some(TxConfidence { wallet_tx, num_confirmations })
    }
}

pub struct TxConfidence {
    pub wallet_tx: WalletTx,
    pub num_confirmations: u32,
}

pub struct WalletTx {
    pub tx: Arc<Transaction>,
    pub chain_position: ChainPosition<ConfirmationBlockTime>,
}

impl From<bdk_wallet::WalletTx<'_>> for WalletTx {
    fn from(value: bdk_wallet::WalletTx) -> Self {
        WalletTx { tx: value.tx_node.tx, chain_position: value.chain_position }
    }
}
