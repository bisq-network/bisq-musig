//! This POC demonstrates:
//! - Password-based key derivation using Argon2
//! - Encrypted SQLite database using SQLCipher
//! - Wallet data storage and retrieval

use argon2::{Argon2, Block, Params};
use base64::{engine::general_purpose, Engine as _};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, Result as SqlResult};
use std::fs;
use zeroize::Zeroize;

fn main() -> anyhow::Result<()> {
    println!("SQLCipher + Argon2 POC");
    println!("================================================");

    run_demo("wallet.db", "super_secure_password_123")?;

    println!("POC completed successfully!");
    Ok(())
}

fn run_demo(db_path: &str, password: &str) -> anyhow::Result<()> {
    // Demo 1: Create table
    println!("Creating new encrypted wallet...");
    let wallet = EncryptedWallet::create_wallet(db_path, password)?;

    // Demo 2: Insert data
    println!("Adding wallet data...");
    let wallet_id = wallet.add_wallet(
        "My Bitcoin Wallet",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )?;
    println!("Added wallet with ID: {wallet_id}");

    let wallet_id2 = wallet.add_wallet(
        "My Ethereum Wallet",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
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
    match EncryptedWallet::open_wallet(db_path, "wrong_password") {
        Ok(_) => println!("ERROR: Should have failed with wrong password!"),
        Err(e) => println!("Correctly rejected wrong password: {e}"),
    }

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
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        fs::write(&salt_path, general_purpose::STANDARD.encode(salt))?;

        let key_hex = derive_key_from_password(password, &salt)?;

        // Create encrypted database connection
        let conn = setup_database_connection(db_path, &key_hex)?;

        // Create wallet data table
        create_wallet_table(&conn)?;

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
        let salt = general_purpose::STANDARD.decode(salt_str.as_bytes())?;

        // Derive the correct key using stored salt
        let key_hex = derive_key_from_password(password, &salt)?;

        // Open the encrypted database
        let conn = setup_database_connection(db_path, &key_hex)?;

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

/// Derives a 256-bit key from a password and salt using Argon2.
fn derive_key_from_password(password: &str, salt: &[u8]) -> anyhow::Result<String> {
    let argon2 = Argon2::default();
    let mut memory: Vec<Block> = vec![Block::default(); Params::DEFAULT_M_COST as usize];
    let mut key_bytes = [0u8; 32]; // 256-bit key
    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut key_bytes, &mut memory)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let key_hex = hex::encode(key_bytes);
    key_bytes.zeroize();
    Ok(key_hex)
}

/// Sets up the database connection and applies the encryption key.
fn setup_database_connection(db_path: &str, key_hex: &str) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "key", format!("x'{key_hex}'"))?;
    Ok(conn)
}

/// Creates the `wallets` table in the database.
fn create_wallet_table(conn: &Connection) -> SqlResult<()> {
    conn.execute(
        "CREATE TABLE wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            seed_phrase TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    Ok(())
}
