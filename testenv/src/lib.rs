/// Bitcoin regtest environment using electrsd with automatic executable downloads
use anyhow::{Context, Result};
use axum::Router;
use axum_reverse_proxy::ReverseProxy;
use bdk_wallet::bitcoin::{address::NetworkChecked, Address, Amount, BlockHash, Network, Txid};
use electrsd::corepc_node;
use electrsd::{corepc_node::Node, electrum_client::ElectrumApi, ElectrsD};
use std::time::Duration;

/// Bitcoin regtest environment manager
pub struct TestEnv {
    bitcoind: Node,
    electrsd: ElectrsD,
    timeout: Duration,
    delay: Duration,
}

/// Configuration parameters.
#[derive(Debug)]
pub struct Config<'a> {
    /// [`bitcoind::Conf`]
    pub bitcoind: corepc_node::Conf<'a>,
    /// [`electrsd::Conf`]
    pub electrsd: electrsd::Conf<'a>,
    pub timeout: Duration,
    pub delay: Duration,
}

impl Default for Config<'_> {
    fn default() -> Self {
        Self {
            bitcoind: {
                let mut conf = corepc_node::Conf::default();
                conf.args.push("-blockfilterindex=1");
                conf.args.push("-peerblockfilters=1");
                conf.args.push("-txindex=1");
                conf
            },
            electrsd: {
                let mut conf = electrsd::Conf::default();
                conf.http_enabled = true;
                conf.args.push("--cors");
                conf.args.push("*");
                // conf.view_stderr = true;
                conf
            },
            timeout: Duration::from_secs(5),
            delay: Duration::from_millis(200),
        }
    }
}

const NETWORK: Network = Network::Regtest;

impl TestEnv {
    /// Create a new test environment with automatic executable downloads
    pub fn new() -> Result<Self> {
        Self::new_with_conf(Config::default())
    }

    /// create environment with automatic downloads
    pub fn new_with_conf(config: Config) -> Result<Self> {
        // Try to start bitcoind (from environment or downloads)
        eprintln!("Starting bitcoind...");
        let bitcoind = match std::env::var("BITCOIND_EXEC") {
            Ok(path) => {
                eprintln!("Using custom bitcoind executable: {}", path);
                Node::with_conf(&path, &config.bitcoind)?
            }
            Err(_) => {
                eprintln!(
                    "BITCOIND_EXEC not set! Falling back to downloaded version at {}",
                    corepc_node::downloaded_exe_path()?
                );

                Node::from_downloaded_with_conf(&config.bitcoind)?
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

        let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &config.electrsd)
            .with_context(|| "Starting electrsd failed...")?;

        eprintln!("Electrum URL: {}", electrsd.electrum_url);
           let test_env = Self { bitcoind, electrsd, timeout: Duration::from_secs(5), delay: Duration::from_millis(200) };
        if let Some(url) = test_env.esplora_url() {
            eprintln!("Esplora REST address: http://{url}/mempool",);
        };
        eprintln!("Bitcoin regtest environment ready!");

        Ok(test_env)
    }

    pub async fn start_esplora_ui(&self, port: u16) -> Result<()> {
        let Some(api_url) = self.esplora_url() else {
            eprintln!("Failed to start Esplora UI! Please set electrsd.http_enabled = true");
            return Err(anyhow::anyhow!("Esplora URL not available"));
        };

        eprintln!("Starting Esplora UI...");

        // Create a reverse proxy that forwards requests from /api/*
        let api = ReverseProxy::new("/api", &format!("http://{api_url}"));

        //The actual frontend should be running in a container on the port 8888(look at the README for more details)
        let frontend = ReverseProxy::new("/", "http://localhost:8888");
        let app: Router = api.into();

        // Forward all other requests to actual frontend
        let app: Router = app.fallback_service(frontend);

        let listener = tokio::net::TcpListener::bind(&format!("127.0.0.1:{port}"))
            .await
            .context("Failed to bind to port 8989 for Esplora UI")?;

        let local_addr = listener
            .local_addr()
            .context("Failed to get local address for Esplora UI")?;

        eprintln!("Esplora UI served at: http://{:?}", local_addr);

        axum::serve(listener, app)
            .await
            .context("Esplora UI server failed")?;

        eprintln!("!!! Esplora UI terminated!!");
        Ok(())
    }

    /// Get the electrum client for blockchain operations
    pub fn electrum_client(&self) -> &impl ElectrumApi {
        &self.electrsd.client
    }

    /// Get the electrum URL
    pub fn electrum_url(&self) -> String {
        self.electrsd.electrum_url.replace("0.0.0.0", "127.0.0.1")
    }

    /// Get the Esplora REST URL
    pub fn esplora_url(&self) -> Option<String> {
        self.electrsd
            .esplora_url
            .as_ref()
            .map(|url| url.replace("0.0.0.0", "127.0.0.1"))
    }

    /// Mine blocks using bitcoind RPC
    pub fn mine_blocks(&self, count: usize) -> Result<Vec<BlockHash>> {
        let block_hashes = self
            .bitcoind
            .client
            .generate_to_address(count, &self.new_address()?)?;

        // Convert to BlockHash format
        block_hashes
            .0
            .into_iter()
            .map(|hash_str| hash_str.parse::<BlockHash>().map_err(anyhow::Error::msg))
            .collect()
    }

    /// Mine a single block
    pub fn mine_block(&self) -> Result<BlockHash> {
        let hashes = self.mine_blocks(1)?;
        Ok(hashes[0])
    }

    /// Fund an address using bitcoind RPC
    pub fn fund_address(&self, address: &Address<NetworkChecked>, amount: Amount) -> Result<Txid> {
        // First ensure we have some coins by mining blocks if needed
        let balance = self.bitcoind.client.get_balance()?.balance()?;

        if balance < amount {
            // Mine 101 blocks (standard for regtest to make coins spendable)
            self.bitcoind
                .client
                .generate_to_address(101, &self.new_address()?)?;

            // Wait a moment for blocks to be processed
            std::thread::sleep(Duration::from_secs(1));
        }

        // Send money to the address
        let txid = self
            .bitcoind
            .client
            .send_to_address(address, amount)?
            .txid()?;
        Ok(txid)
    }

    /// Create a new address for testing using bitcoind RPC
    pub fn new_address(&self) -> Result<Address<NetworkChecked>> {
        Ok(self
            .bitcoind
            .client
            .get_new_address(None, None)?
            .address()?
            .require_network(NETWORK)?)
    }

    /// Wait for electrum to see a new block
    pub fn wait_for_block(&self) -> Result<()> {
        self.electrsd.client.block_headers_subscribe()?;
        let start = std::time::Instant::now();

        while start.elapsed() < self.timeout {
            self.electrsd.trigger()?;
            self.electrsd.client.ping()?;

            if let Some(_header) = self.electrsd.client.block_headers_pop()? {
                return Ok(());
            }

            std::thread::sleep(self.delay);
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for electrum to see block after {:?}",
            self.timeout
        ))
    }

    /// Wait for electrum to see a specific transaction
    pub fn wait_for_tx(&self, txid: Txid) -> Result<()> {
        let start = std::time::Instant::now();

        while start.elapsed() < self.timeout {
            if self.electrsd.client.transaction_get(&txid).is_ok() {
                return Ok(());
            }
            std::thread::sleep(self.delay);
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for electrum to see transaction {} after {:?}",
            txid,
            self.timeout
        ))
    }

    /// Get the current block count from bitcoind
    pub fn block_count(&self) -> Result<u64> {
        let count = self.bitcoind.client.get_block_count()?.0;
        Ok(count)
    }

    /// Get the best block hash from bitcoind
    pub fn best_block_hash(&self) -> Result<BlockHash> {
        let hash = self.bitcoind.client.get_best_block_hash()?.block_hash()?;
        Ok(hash)
    }

    /// Get the genesis block hash from bitcoind
    pub fn genesis_hash(&self) -> Result<BlockHash> {
        let hash = self.bitcoind.client.get_block_hash(0)?.block_hash()?;
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
        eprintln!("Initial balance: {:?} BTC", initial_balance);

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
        env.wait_for_tx(txid)?;
        eprintln!("Transaction confirmed in electrum");

        // Verify we can get the transaction from bitcoind
        let tx = env.bitcoind.client.get_transaction(txid)?;

        // Extract the received amount from transaction details
        use electrsd::corepc_node::vtype::TransactionCategory;
        let receive_amount = tx
            .details
            .iter()
            .find(|detail| detail.category == TransactionCategory::Receive)
            .map(|detail| Amount::from_sat((detail.amount * 100_000_000.0) as u64))
            .unwrap_or_default();

        assert_eq!(receive_amount, amount);
        eprintln!("Transaction amount verified: {} ", receive_amount);

        Ok(())
    }

    #[test]
    fn test_esplora_ui_without_electrsonfig() -> Result<()> {
        // Test that error handling works when http_enabled is false
        let mut config = Config::default();
        // Disable HTTP to make Esplora URL unavailable
        config.electrsd.http_enabled = false;

        let env = TestEnv::new_with_conf(config)?;

        // Esplora URL should be None when HTTP is disabled
        assert!(
            env.esplora_url().is_none(),
            "Esplora URL should be None when HTTP is disabled"
        );

        Ok(())
    }
}
