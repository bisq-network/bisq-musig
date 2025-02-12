pub fn setup() {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;
        
    println!("Starting the setup...");

    // Check if Docker is running
    let docker_check = Command::new("docker")
        .arg("info")
        .output();

    match docker_check {
        Ok(output) => {
            if !output.status.success() {
                eprintln!("Docker is not running. Please start Docker first.");
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("Docker is not installed or not in PATH. Please install Docker first.");
            std::process::exit(1);
        }
    }

    // Stop Nigiri first
    println!("Stopping Nigiri...");
    let _ = Command::new("nigiri")
        .arg("stop")
        .output();

    // Force remove any existing Bitcoin container
    println!("Removing existing Bitcoin container...");
    let _ = Command::new("docker")
        .args(["rm", "-f", "nigiri-bitcoin"])
        .output();

    // Remove Bitcoin data volume
    println!("Removing Bitcoin data volume...");
    let _ = Command::new("docker")
        .args(["volume", "rm", "-f", "nigiri-bitcoin-data"])
        .output();

    // Create a temporary container to clean up wallet data
    println!("Cleaning up wallet data...");
    let _ = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            "nigiri-bitcoin-data:/data",
            "alpine",
            "sh",
            "-c",
            "rm -rf /data/.bitcoin/regtest/wallets/*"
        ])
        .output();

    thread::sleep(Duration::from_secs(2));

    // Start fresh Nigiri instance
    println!("Starting fresh Nigiri instance...");
    let nigiri_output = Command::new("nigiri")
        .arg("start")
        .output();

    match nigiri_output {
        Ok(output) => {
            if output.status.success() {
                println!("Nigiri started successfully.");
            } else {
                eprintln!(
                    "Failed to start Nigiri. Error: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error while starting Nigiri: {}", e);
            std::process::exit(1);
        }
    }

    // Wait for Nigiri's Bitcoin node to be fully ready
    println!("Waiting for Nigiri services to be ready...");
    thread::sleep(Duration::from_secs(10));

    println!("Setup completed successfully.");
}

