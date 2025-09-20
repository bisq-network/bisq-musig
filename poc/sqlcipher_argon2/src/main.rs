//! This POC demonstrates:
//! - Password-based key derivation using Argon2
//! - Encrypted SQLite database using SQLCipher
//! - Wallet data storage and retrieval

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, Result as SqlResult};
use std::fs;

fn main() -> anyhow::Result<()> {
    println!("SQLCipher + Argon2 POC");
    println!("================================================");

    let db_path = "wallet.db";
    let password = "super_secure_password_123";

    // Demo 1: Create table
    println!("Creating new encrypted wallet...");
    let wallet = EncryptedWallet::create_wallet(db_path, password)?;

    // Demo 2: Insert data
    println!("Adding wallet data...");
    let wallet_id = wallet.add_wallet(
        "My Bitcoin Wallet",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    )?;
    println!("Added wallet with ID: {wallet_id}");

    let wallet_id2 = wallet.add_wallet(
        "My Ethereum Wallet",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    )?;
    println!("Added wallet with ID: {wallet_id2}");

    // Demo 3: List data
    println!("Listing wallets:");
    let wallets = wallet.list_wallet()?;
    for (id, name, seed, created_at) in wallets {
        println!(" ID: {id}, Name: {name}, SeedPhrase: {seed}, Created: {created_at}");
    }

    // Demo 4: query
    println!("Getting wallet details:");
    if let Some(wallet_data) = wallet.get_wallet(wallet_id as i32)? {
        println!("  Wallet: {}", wallet_data.name);
        println!("  Seed: {}", wallet_data.seed_phrase);
        println!("  Created: {}", wallet_data.created_at);
    }

    // Demo 5: Reopen the encrypted database
    println!("Reopening encrypted database...");
    let reopened_wallet = EncryptedWallet::open_wallet(db_path, password)?;

    println!("Wallets in reopened database:");
    let wallets = reopened_wallet.list_wallet()?;
    for (id, name, seed, created_at) in wallets {
        println!(" ID: {id}, Name: {name}, SeedPhrase: {seed}, Created: {created_at}");
    }

    // Demo 6: Try wrong password (this should fail)
    println!("Testing wrong password...");
    // drop(reopened_wallet);

    match EncryptedWallet::open_wallet(db_path, "wrong_password") {
        Ok(_) => println!("ERROR: Should have failed with wrong password!"),
        Err(e) => println!("Correctly rejected wrong password: {e}"),
    }

    println!("POC completed successfully!");
    println!(
        "Database file '{}' contains encrypted wallet data.",
        wallet.db_path
    );

    Ok(())
}

/// Represents a wallet with encrypted storage
pub struct EncryptedWallet {
    conn: Connection,
    db_path: String,
}

#[derive(Debug)]
pub struct WalletData {
    pub id: i32,
    pub name: String,
    pub seed_phrase: String,
    pub created_at: String,
}

impl EncryptedWallet {
    /// Create a new encrypted wallet database
    pub fn create_wallet(db_path: &str, password: &str) -> anyhow::Result<Self> {
        let salt_path = format!("{db_path}.salt");
        // Remove existing database and salt for clean start
        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path)?;
        }
        if fs::metadata(&salt_path).is_ok() {
            fs::remove_file(&salt_path)?;
        }

        // Derive encryption key from password using Argon2
        let salt = SaltString::generate(&mut OsRng);
        fs::write(&salt_path, salt.as_str())?;

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // Extract the hash portion for SQLCipher key (64 hex chars)
        let output = password_hash.hash.unwrap();
        let key_bytes = output.as_bytes();
        let key_hex = hex::encode(&key_bytes[..32]); // Use first 32 bytes (256 bits)

        // Create encrypted database connection
        let conn = Connection::open(db_path)?;

        // Set SQLCipher encryption key
        conn.pragma_update(None, "key", format!("x'{key_hex}'"))?;

        // Create wallet data table
        conn.execute(
            "CREATE TABLE wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                seed_phrase TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        println!("Created encrypted wallet database at: {db_path}");
        println!("Salt stored at: {salt_path}");

        Ok(EncryptedWallet {
            conn,
            db_path: db_path.to_string(),
        })
    }

    /// Open an existing encrypted database
    pub fn open_wallet(db_path: &str, password: &str) -> anyhow::Result<Self> {
        let salt_path = format!("{db_path}.salt");
        let salt_str = fs::read_to_string(&salt_path)?;

        // Derive the correct key using stored salt
        let salt =
            SaltString::from_b64(salt_str.as_str()).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let output = password_hash.hash.unwrap();
        let key_bytes = output.as_bytes();
        let key_hex = hex::encode(&key_bytes[..32]);

        // Open the encrypted database
        let conn = Connection::open(db_path)?;

        // Set the encryption key
        conn.pragma_update(None, "key", format!("x'{key_hex}'"))?;

        // Verify we can read the database by checking table count
        let table_count: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='wallets'",
            [],
            |row| row.get(0),
        )?;

        if table_count != 1 {
            return Err(anyhow::anyhow!("Invalid password or corrupted database"));
        }

        println!("Opened encrypted wallet database: {db_path}");

        Ok(EncryptedWallet {
            conn,
            db_path: db_path.to_string(),
        })
    }

    /// Add wallet data to the encrypted database
    pub fn add_wallet(&self, name: &str, seed_phrase: &str) -> SqlResult<i64> {
        let mut stmt = self
            .conn
            .prepare("INSERT INTO wallets (name, seed_phrase) VALUES (?1, ?2)")?;

        stmt.execute(params![name, seed_phrase])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get wallet data by ID
    pub fn get_wallet(&self, id: i32) -> SqlResult<Option<WalletData>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, seed_phrase, created_at FROM wallets WHERE id = ?1")?;

        let mut wallet_iter = stmt.query_map([id], |row| {
            Ok(WalletData {
                id: row.get(0)?,
                name: row.get(1)?,
                seed_phrase: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        if let Some(wallet) = wallet_iter.next() {
            return Ok(Some(wallet?));
        }

        Ok(None)
    }

    pub fn list_wallet(&self) -> SqlResult<Vec<(i32, String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name,seed_phrase, created_at FROM wallets ORDER BY created_at DESC",
        )?;

        let wallet_iter = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut wallets = Vec::new();
        for wallet in wallet_iter {
            wallets.push(wallet?);
        }

        Ok(wallets)
    }
}
