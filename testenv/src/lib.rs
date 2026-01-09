/// Bitcoin regtest environment using electrsd with automatic executable downloads
use anyhow::{Context, Result};
use bdk_electrum::bdk_core::bitcoin::{KnownHrp, XOnlyPublicKey};
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::All;
use bdk_wallet::bitcoin::{address::NetworkChecked, Address, Amount, BlockHash, Network, Transaction, Txid};
use corepc_node::get_available_port;
use electrsd::corepc_node;
use electrsd::electrum_client::Client;
use electrsd::{corepc_node::Node, electrum_client::ElectrumApi, ElectrsD};
use secp::Scalar;
use simple_semaphore::{Permit, Semaphore};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};


/// Bitcoin regtest environment manager
pub struct TestEnv {
    bitcoind: Node,
    electrsd: ElectrsD,
    timeout: Duration,
    delay: Duration,
    bdk_electrum_client: bdk_electrum::BdkElectrumClient<Client>,
    ctx: Secp256k1<All>,
    _permit: Permit,
    _tmp_dir: TempDir,
    explorer_process: Option<std::process::Child>,
    container_name: Option<String>,
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
                // bitcoin / bitcoin
                conf.args.push("-rpcauth=bitcoin:81ad5d600eb1df69d27323dd1ef31162$7c4315f44d8eea5cb6764295c0233a5e0d51d5ea461e122f337bc6e8502f0d93");
                // Listen on all interfaces (0.0.0.0) instead of just localhost
                conf.args.push("-rpcbind=0.0.0.0");

                // Allow connections from any IP (use 0.0.0.0/0 for "everywhere")
                conf.args.push("-rpcallowip=0.0.0.0/0");

                conf.args.push("-blockfilterindex=1");
                conf.args.push("-peerblockfilters=1");
                conf.args.push("-txindex=1");
                conf
            },
            electrsd: {
                let mut conf = electrsd::Conf::default();
                conf.http_enabled = true;
                // conf.args.push("--http-addr");
                // conf.args.push("0.0.0.0:3003");
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
static SEMAPHORE: once_cell::sync::Lazy<Arc<Semaphore>> =
    once_cell::sync::Lazy::new(|| Semaphore::new(1));

impl TestEnv {
    /// Create a new test environment with automatic executable downloads
    pub fn new() -> Result<Self> {
        Self::new_with_conf(Config::default())
    }

    /// create environment with automatic downloads
    pub fn new_with_conf(config: Config) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let permit = SEMAPHORE.acquire(); // have testenvs single threaded because of bitcoind and electrs references.
        let tmp_dir = tempdir().expect("failed to create temporary directory");
        std::env::set_current_dir(tmp_dir.path()).expect("failed to set current directory");

        // Try to start bitcoind (from environment or downloads)
        println!("Starting bitcoind...");
        let bitcoind = match std::env::var("BITCOIND_EXEC") {
            Ok(path) => {
                println!("Using custom bitcoind executable: {}", path);
                Node::with_conf(&path, &config.bitcoind)?
            }
            Err(_) => {
                println!(
                    "BITCOIND_EXEC not set! Falling back to downloaded version at {}",
                    corepc_node::downloaded_exe_path()?
                );

                Node::from_downloaded_with_conf(&config.bitcoind)?
            }
        };

        // Try to get electrs executable (from environment or downloads)
        let electrs_exe = match std::env::var("ELECTRS_EXEC") {
            Ok(path) => {
                println!("Using custom electrs executable: {}", path);
                path
            }
            Err(_) => {
                // Try to use downloaded electrs
                let path = electrsd::downloaded_exe_path()
                    .expect("No downloaded electrs found, trying electrs in PATH...");
                println!("Using downloaded electrs: {}", path);
                path
            }
        };

        println!("Starting electrsd...");

        let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &config.electrsd)
            .with_context(|| "Starting electrsd failed...")?;

        let client = Client::from_config(&electrsd.electrum_url, bdk_electrum::electrum_client::Config::default())?;
        let bdk_electrum_client = BdkElectrumClient::new(client);


        // permit will be dropped when TestEnv is dropped
        let test_env = Self {
            bitcoind,
            electrsd,
            timeout: config.timeout,
            delay: config.delay,
            bdk_electrum_client,
            ctx: Secp256k1::new(),
            _permit: permit,
            _tmp_dir: tmp_dir,
            explorer_process: None,
            container_name: None,
        };
        println!("Bitcoin regtest environment ready!");
        Ok(test_env)
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let txid = self.bdk_electrum_client.transaction_broadcast(tx)?;
        let _ = self.wait_for_tx(txid);
        Ok(txid)
    }

    pub fn start_explorer_in_container(&mut self) -> Result<()> {
        // this start a container for debugging
        let bitcoind_rpc_port = self.bitcoind.params.rpc_socket.port();
        let browserport = get_available_port()?;

        let electrum_port = self.electrsd.electrum_url.split(':').last()
                .context("Failed to parse electrum port")?;

        let container_name = format!("btc-explorer-{}", browserport);

        let mut container = std::process::Command::new("podman");
        container.args(["run", "-it", "--rm",
            "--name", &container_name,
            "-p",
            format!("{}:3002", browserport).as_str(),
            "--add-host=host.containers.internal:host-gateway",
            "-e",
            "BTCEXP_BITCOIND_HOST=host.containers.internal",
            "-e",
            "BTCEXP_HOST=0.0.0.0",
            "-e",
            format!("BTCEXP_BITCOIND_PORT={}", bitcoind_rpc_port).as_str(),
            "-e", "BTCEXP_BITCOIND_USER=bitcoin",
            "-e", "BTCEXP_BITCOIND_PASS=bitcoin",
            "-e", "BTCEXP_ADDRESS_API=electrum",
            "-e", format!("BTCEXP_ELECTRUM_SERVERS=tcp://host.containers.internal:{}", electrum_port).as_str(),
            "docker.io/getumbrel/btc-rpc-explorer:v3.5.1",
        ]);

        // println!("Spawning container: {:?}", container);
        let child = container
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .context("Failed to spawn rpc_proxy")?;

        // let id = child.id();
        // let output = child.wait_with_output()?;
        // eprintln!("id: {} out:{}", id, std::str::from_utf8(&output.stdout)?);

        self.explorer_process = Some(child);
        self.container_name = Some(container_name);

        eprintln!("Starting explorer in container, access it at http://127.0.0.1:{}/blocks", browserport);
        eprintln!("you can check the container logs with: ");
        eprintln!("podman logs -f --timestamps {}", self.container_name.as_ref().unwrap());
        Ok(())
    }

    /// Get the electrum client for blockchain operations
    pub fn electrum_client(&self) -> &impl ElectrumApi {
        // &self.electrsd.client
        &self.bdk_electrum_client.inner
    }

    /// Get the electrum URL
    pub fn electrum_url(&self) -> String {
        self.electrsd.electrum_url.replace("0.0.0.0", "127.0.0.1")
    }

    pub fn bdk_electrum_client(&self) -> &BdkElectrumClient<Client> {
        &self.bdk_electrum_client
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
        self.wait_for_block()?;
        Ok(hashes[0])
    }

    pub fn fund_from_prv_key(&self, key: &Scalar, amount: Amount) -> Result<Txid> {
        let xonly_pubkey = key.base_point_mul().serialize_xonly();
        let pbk = XOnlyPublicKey::from_slice(&xonly_pubkey)?;
        let addrress = Address::p2tr(&self.ctx, pbk, None, KnownHrp::Regtest);
        self.fund_address(&addrress, amount)
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
            if self.bdk_electrum_client.fetch_tx(txid).is_ok() {
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

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(name) = self.container_name.take() {
            eprintln!("Stopping explorer container {}...", name);
            let output = std::process::Command::new("podman")
                    .args(["stop", &name])
                    .output();
            eprintln!("explorer container returned {:?}...", output);
        }

        // Try graceful shutdown first (SIGTERM)
        if let Some(mut child) = self.explorer_process.take() {
            eprintln!("Shutting down explorer process...");

            // Send SIGTERM (graceful)
            let _ = child.kill();
            let _ = child.wait();
        }
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
        let mut env = TestEnv::new()?;

        // Create new address
        let address = env.new_address()?;
        println!("Created address: {}", address);

        // Address is already verified to be on regtest network when created via new_address()

        // Get initial balance
        let initial_balance = env.bitcoind.client.get_balance()?;
        println!("Initial balance: {:?} BTC", initial_balance);

        // Fund address with 1000 satoshis
        let amount = Amount::from_sat(1000);
        let txid = env.fund_address(&address, amount)?;
        println!("Funded address with txid: {}", txid);

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
        println!("Transaction confirmed in electrum");

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
        println!("Transaction amount verified: {} ", receive_amount);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_container_ui_manual() -> Result<()> {
        let mut env = TestEnv::new()?;
        env.start_explorer_in_container()?;
        env.mine_block()?;
        // put a breakpoint on the Ok statement so you inspect the blockchain before it is dropped
        Ok(())
    }

}
