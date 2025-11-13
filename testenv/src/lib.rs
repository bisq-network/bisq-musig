//! Bitcoin regtest environment using electrsd with automatic executable downloads
use anyhow::{Context, Result};
use bdk_wallet::bitcoin::{
    address::{NetworkChecked, NetworkUnchecked},
    Address, Amount, BlockHash, Network, Txid,
};
use electrsd::{corepc_node::Node, electrum_client::ElectrumApi, ElectrsD};
use std::time::Duration;

/// Bitcoin regtest environment manager
pub struct TestEnv {
    bitcoind: Node,
    electrsd: ElectrsD,
}

impl TestEnv {
    /// Create a new test environment with automatic executable downloads
    pub fn new() -> Result<Self> {
        Self::create_with_downloads()
    }

    /// create environment with automatic downloads
    fn create_with_downloads() -> Result<Self> {
        // Try to start bitcoind (from environment or downloads)
        eprintln!("Starting bitcoind...");
        let bitcoind = match std::env::var("BITCOIND_EXEC") {
            Ok(path) => {
                eprintln!("Using custom bitcoind executable: {}", path);
                Node::new(&path)
                    .with_context(|| format!("Failed to start bitcoind from: {}", path))?
            }
            Err(_) => {
                // For now, require manual installation or use defaults
                eprintln!("BITCOIND_EXEC not set! Falling back to downloaded version");
                Node::from_downloaded().expect("Failed to download bitcoind")
            }
        };

        // Try to get electrs executable (from environment or downloads)
        let electrs_exe = match std::env::var("ELECTRS_EXEC") {
            Ok(path) => {
                eprintln!("Using custom electrs executable: {}", path);
                path
            }
            Err(_) => {
                // Try to use downloaded electrs
                let path = electrsd::downloaded_exe_path()
                    .expect("No downloaded electrs found, trying electrs in PATH...");
                eprintln!("Using downloaded electrs: {}", path);
                path
            }
        };

        eprintln!("Starting electrsd...");
        let electrsd = ElectrsD::new(&electrs_exe, &bitcoind)
            .with_context(|| format!("Failed to start electrsd from: {}", electrs_exe))?;

        eprintln!("Bitcoin regtest environment ready!");
        eprintln!("Electrum URL: {}", electrsd.electrum_url);

        Ok(Self { bitcoind, electrsd })
    }

    /// Get the electrum client for blockchain operations
    pub fn electrum_client(&self) -> &impl ElectrumApi {
        &self.electrsd.client
    }

    /// Get the electrum URL
    pub fn electrum_url(&self) -> &str {
        &self.electrsd.electrum_url
    }

    /// Mine blocks using bitcoind RPC
    pub fn mine_blocks(&self, count: usize) -> Result<Vec<BlockHash>> {
        // Generate blocks to the node's mining address
        let mining_address_str = self.bitcoind.client.get_new_address(None, None)?.0;
        let mining_address: Address<NetworkUnchecked> = mining_address_str.parse()?;
        let mining_address_checked = mining_address.require_network(Network::Regtest)?;
        let block_hashes = self
            .bitcoind
            .client
            .generate_to_address(count, &mining_address_checked)?;

        // Convert to BlockHash format
        let hashes: Result<Vec<BlockHash>> = block_hashes
            .0
            .into_iter()
            .map(|hash_str| hash_str.parse::<BlockHash>().map_err(anyhow::Error::msg))
            .collect();

        Ok(hashes?)
    }

    /// Mine a single block
    pub fn mine_block(&self) -> Result<BlockHash> {
        let hashes = self.mine_blocks(1)?;
        Ok(hashes[0])
    }

    /// Fund an address using bitcoind RPC
    pub fn fund_address(&self, address: &Address<NetworkChecked>, amount: Amount) -> Result<Txid> {
        // First ensure we have some coins by mining blocks if needed
        let balance = self.bitcoind.client.get_balance()?;
        let balance_sats = (balance.0 * 100_000_000.0) as u64; // Convert BTC to satoshis

        if balance_sats < amount.to_sat() {
            // Mine some blocks to get coins
            let mining_address = self
                .bitcoind
                .client
                .get_new_address(None, None)?
                .0
                .parse::<Address<NetworkUnchecked>>()?
                .require_network(Network::Regtest)?;

            // Mine 101 blocks (standard for regtest to make coins spendable)
            self.bitcoind
                .client
                .generate_to_address(101, &mining_address)?;

            // Wait a moment for blocks to be processed
            std::thread::sleep(Duration::from_secs(1));
        }

        // Send money to the address
        let txid_str = self.bitcoind.client.send_to_address(address, amount)?;
        let txid = txid_str.0.parse::<Txid>().map_err(anyhow::Error::msg)?;
        Ok(txid)
    }

    /// Create a new address for testing using bitcoind RPC
    pub fn new_address(&self) -> Result<Address<NetworkChecked>> {
        let addr_str = self.bitcoind.client.get_new_address(None, None)?.0;
        let addr = addr_str
            .parse::<Address<_>>()?
            .require_network(Network::Regtest)?;
        Ok(addr)
    }

    /// Wait for electrum to see a new block
    pub fn wait_for_block(&self, timeout: Duration) -> Result<()> {
        self.electrsd.client.block_headers_subscribe()?;
        let delay = Duration::from_millis(200);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            self.electrsd.trigger()?;
            self.electrsd.client.ping()?;

            if let Some(_header) = self.electrsd.client.block_headers_pop()? {
                return Ok(());
            }

            std::thread::sleep(delay);
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for electrum to see block after {:?}",
            timeout
        ))
    }

    /// Wait for electrum to see a specific transaction
    pub fn wait_for_tx(&self, txid: Txid, timeout: Duration) -> Result<()> {
        let delay = Duration::from_millis(200);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if self.electrsd.client.transaction_get(&txid).is_ok() {
                return Ok(());
            }
            std::thread::sleep(delay);
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for electrum to see transaction {} after {:?}",
            txid,
            timeout
        ))
    }

    /// Get the current block count from bitcoind
    pub fn block_count(&self) -> Result<u64> {
        let count = self.bitcoind.client.get_block_count()?.0;
        Ok(count)
    }

    /// Get the best block hash from bitcoind
    pub fn best_block_hash(&self) -> Result<BlockHash> {
        let hash_str = self.bitcoind.client.get_best_block_hash()?.0;
        let hash = hash_str.parse::<BlockHash>().map_err(anyhow::Error::msg)?;
        Ok(hash)
    }

    /// Get the genesis block hash from bitcoind
    pub fn genesis_hash(&self) -> Result<BlockHash> {
        let hash_str = self.bitcoind.client.get_block_hash(0)?.0;
        let hash = hash_str.parse::<BlockHash>().map_err(anyhow::Error::msg)?;
        Ok(hash)
    }

    /// Trigger electrs sync
    pub fn trigger_sync(&self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            self.electrsd.trigger()
        }
    }

    /// Get the working directory path
    pub fn workdir(&self) -> std::path::PathBuf {
        self.electrsd.workdir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_creation() -> Result<()> {
        let env = TestEnv::new()?;

        // Basic checks
        assert!(env.block_count().is_ok());
        assert!(env.genesis_hash().is_ok());
        assert!(!env.electrum_url().is_empty());

        Ok(())
    }

    #[test]
    fn test_mining() -> Result<()> {
        let env = TestEnv::new()?;
        let initial_count = env.block_count()?;

        env.mine_block()?;

        let new_count = env.block_count()?;
        assert_eq!(new_count, initial_count + 1);

        Ok(())
    }

    #[test]
    fn test_address_operations() -> Result<()> {
        let env = TestEnv::new()?;

        // Create new address
        let address = env.new_address()?;
        eprintln!("Created address: {}", address);

        // Address is already verified to be on regtest network when created via new_address()

        // Get initial balance
        let initial_balance = env.bitcoind.client.get_balance()?;
        eprintln!("Initial balance: {} BTC", initial_balance.0);

        // Fund address with 1000 satoshis
        let amount = Amount::from_sat(1000);
        let txid = env.fund_address(&address, amount)?;
        eprintln!("Funded address with txid: {}", txid);

        // Verify the transaction was created
        assert_ne!(
            txid.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // Mine a block to confirm the transaction
        env.mine_block()?;

        // Wait for electrum to sync
        env.trigger_sync()?;

        // Wait for the transaction to appear in electrum
        env.wait_for_tx(txid, Duration::from_secs(10))?;
        eprintln!("Transaction confirmed in electrum");

        // Verify we can get the transaction from bitcoind
        let tx = env.bitcoind.client.get_transaction(txid)?;

        // Extract the receive amount from transaction details
        use electrsd::corepc_node::vtype::TransactionCategory;
        let receive_amount = tx
            .details
            .iter()
            .find(|detail| matches!(detail.category, TransactionCategory::Receive))
            .map(|detail| Amount::from_sat((detail.amount * 100_000_000.0) as u64))
            .unwrap_or_default();

        assert_eq!(receive_amount, amount);
        eprintln!("Transaction amount verified: {} BTC", tx.amount);

        Ok(())
    }
}
