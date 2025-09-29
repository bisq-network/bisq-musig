# SQLCipher + Argon2 Proof of Concept

This POC demonstrates how to use Argon2 to derive a key from a password and use it to encrypt a SQLite database with SQLCipher.

## How to run

1. Make sure you are in `bisq-musig/poc/sqlcipher_argon2`
2. Run the POC with:
   ```bash
   cargo run
   ```

## What it does

The POC will:

1.  Create a new wallet with a password .
2.  Attempt to open the wallet with the correct password.
3.  Write and read some data to prove the database is encrypted and accessible.
4.  Attempt to open the wallet with an incorrect password, which will fail.
