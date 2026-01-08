/// Bitcoin regtest environment using electrsd with automatic executable downloads
use anyhow::{Context, Result};
use bdk_electrum::bdk_core::bitcoin::{KnownHrp, XOnlyPublicKey};
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::All;
use bdk_wallet::bitcoin::{address::NetworkChecked, Address, Amount, BlockHash, Network, Transaction, Txid};
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
    esplora_proxy_process: Option<std::process::Child>,
    rpc_proxy_process: Option<std::process::Child>,
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

                // conf.args.push("-rpcport=18443"); // seems at startup a random port is already used.
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
        eprintln!("rpc: {}", bitcoind.rpc_url());

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

        println!("Electrum URL: {}", electrsd.electrum_url);
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
            esplora_proxy_process: None,
            rpc_proxy_process: None,
        };
        if let Some(url) = test_env.esplora_url() {
            println!("Esplora REST address: http://{url}/mempool", );
        };
        println!("Bitcoin regtest environment ready!");
        // test_env.start_esplora_ui(8989)?;
        Ok(test_env)
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let txid = self.bdk_electrum_client.transaction_broadcast(tx)?;
        let _ = self.wait_for_tx(txid);
        Ok(txid)
    }

    pub fn start_esplora_ui(&mut self, port: u16) -> Result<()> {
        let Some(api_url) = self.esplora_url() else {
            eprintln!("Failed to start Esplora UI! Please set electrsd.http_enabled = true");
            return Ok(()); // could be intended
        };
        // Check if Esplora UI is available at http://localhost:8888/
        let check_url = "http://localhost:8888/";
        let keyword = "Esplora Block Explorer";
        let mut success = false;

        match ureq::get(check_url).call() {
            Ok(response) => {
                match response.into_string() {
                    Ok(body) => {
                        if body.contains(keyword) {
                            success = true;
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }

        if !success {
            eprintln!("Esplora UI at {} did not contain the keyword '{}'. Did you start the Esplora container? See testenv/readme.md!",
                check_url,
                keyword,
            );
            return Ok(()); // could be intended
        }

        println!("Starting Esplora UI child process...");

        // Use compile-time manifest dir if the environment variable is missing at runtime
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
        let manifest_path = std::path::Path::new(&manifest_dir);

        // Try to find the compiled binary first
        // If we are in the workspace, the binary should be in ../target/debug/esplora_proxy
        // or ../target/release/esplora_proxy (assuming this crate is in a subdirectory)
        let workspace_root = if manifest_path.ends_with("testenv") {
            manifest_path.parent().unwrap_or(manifest_path)
        } else {
            manifest_path
        };

        let release_bin = workspace_root.join("target/release/esplora_proxy");
        let debug_bin = workspace_root.join("target/debug/esplora_proxy");

        let mut command = if release_bin.exists() {
            println!("Using compiled release binary: {:?}", release_bin);
            let mut cmd = std::process::Command::new(release_bin);
            cmd.args([&api_url, &port.to_string()]);
            cmd
        } else if debug_bin.exists() {
            println!("Using compiled debug binary: {:?}", debug_bin);
            let mut cmd = std::process::Command::new(debug_bin);
            cmd.args([&api_url, &port.to_string()]);
            cmd
        } else {
            println!("Compiled binary not found, falling back to 'cargo run'");
            let mut cmd = std::process::Command::new("cargo");
            cmd.current_dir(manifest_dir);
            cmd.args([
                "run",
                "--bin",
                "esplora_proxy",
                "--",
                &api_url,
                &port.to_string(),
            ]);
            cmd
        };

        let child = command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .context("Failed to spawn esplora_proxy")?;

        self.esplora_proxy_process = Some(child);

        println!("Esplora UI should be available at: http://127.0.0.1:{port}");
        Ok(())
    }

    pub fn start_rpc_proxy(&mut self) -> Result<()> {
        let bitcoind_rpc_port = self.bitcoind.params.rpc_socket.port();

        // check at port 3002 if something is listening, if not dont start the proxy.
        if std::net::TcpStream::connect("127.0.0.1:3002").is_err() {
            println!("Nothing listening on port 3002, skipping RPC proxy start.");
            return Ok(());
        }

        println!("Starting RPC proxy child process...");

        // Use compile-time manifest dir if the environment variable is missing at runtime
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
                .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
        let manifest_path = std::path::Path::new(&manifest_dir);

        let workspace_root = if manifest_path.ends_with("testenv") {
            manifest_path.parent().unwrap_or(manifest_path)
        } else {
            manifest_path
        };

        let release_bin = workspace_root.join("target/release/rpc_proxy");
        let debug_bin = workspace_root.join("target/debug/rpc_proxy");

        let mut command = if release_bin.exists() {
            println!("Using compiled release binary: {:?}", release_bin);
            let mut cmd = std::process::Command::new(release_bin);
            cmd.args([&bitcoind_rpc_port.to_string(), "18443"]);
            cmd
        } else if debug_bin.exists() {
            println!("Using compiled debug binary: {:?}", debug_bin);
            let mut cmd = std::process::Command::new(debug_bin);
            cmd.args([&bitcoind_rpc_port.to_string(), "18443"]);
            cmd
        } else {
            println!("Compiled binary not found, falling back to 'cargo run'");
            let mut cmd = std::process::Command::new("cargo");
            cmd.current_dir(manifest_dir);
            cmd.args([
                "run",
                "--bin",
                "rpc_proxy",
                "--",
                &bitcoind_rpc_port.to_string(),
                "18443",
            ]);
            cmd
        };

        let child = command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .context("Failed to spawn rpc_proxy")?;

        self.rpc_proxy_process = Some(child);

        println!("RPC proxy mapping bitcoind port {bitcoind_rpc_port} to 18443");
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
        if let Some(mut child) = self.esplora_proxy_process.take() {
            let _ = child.kill();
        }
        if let Some(mut child) = self.rpc_proxy_process.take() {
            let _ = child.kill();
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
        let env = TestEnv::new()?;

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
    fn test_esplora_ui_without_electrsonfig() -> Result<()> {
        // Test that error handling works when http_enabled is false
        let mut config = Config::default();
        // Disable HTTP to make Esplora URL unavailable
        config.electrsd.http_enabled = false;

        let mut env = TestEnv::new_with_conf(config)?;

        // Esplora URL should be None when HTTP is disabled
        assert!(
            env.esplora_url().is_none(),
            "Esplora URL should be None when HTTP is disabled"
        );

        assert!(env.start_esplora_ui(8989).is_err());

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_esplora_ui_manual() -> Result<()> {
        let env = TestEnv::new()?;
        env.mine_block()?;
        //println!("Esplora UI started. You can now set a breakpoint and inspect the blockchain.");
        // println!("Press Ctrl+C to stop or wait for 10 minutes...");
        // std::thread::sleep(Duration::from_secs(600));
        Ok(())
    }
}
