use tonic::{Request, Response, Result};
use tracing::info;

use crate::pb::bmp_wallet;
use crate::pb::bmp_wallet::wallet_server::Wallet;

#[derive(Debug, Default)]
pub struct BmpWalletServiceImpl {}

#[tonic::async_trait]
impl Wallet for BmpWalletServiceImpl {
    async fn is_wallet_ready(
        &self,
        _request: Request<bmp_wallet::IsWalletReadyRequest>,
    ) -> Result<Response<bmp_wallet::IsWalletReadyResponse>> {
        info!("is_wallet_ready called");
        Ok(Response::new(bmp_wallet::IsWalletReadyResponse {
            ready: true,
        }))
    }

    async fn get_unused_address(
        &self,
        _request: Request<bmp_wallet::GetUnusedAddressRequest>,
    ) -> Result<Response<bmp_wallet::GetUnusedAddressResponse>> {
        info!("get_unused_address called");
        Ok(Response::new(bmp_wallet::GetUnusedAddressResponse {
            address: "bc1qvyw2m3f2y2p2l42jm2q5j2j2q2j2q2j2q2j2q2".to_owned(),
        }))
    }

    async fn get_wallet_addresses(
        &self,
        _request: Request<bmp_wallet::GetWalletAddressesRequest>,
    ) -> Result<Response<bmp_wallet::GetWalletAddressesResponse>> {
        info!("get_wallet_addresses called");
        Ok(Response::new(bmp_wallet::GetWalletAddressesResponse {
            addresses: vec![
                "bc1qvyw2m3f2y2p2l42jm2q5j2j2q2j2q2j2q2j2q2".to_owned(),
                "bc1qvyw2m3f2y2p2l42jm2q5j2j2q2j2q2j2q2j2q3".to_owned(),
            ],
        }))
    }

    async fn list_transactions(
        &self,
        _request: Request<bmp_wallet::ListTransactionsRequest>,
    ) -> Result<Response<bmp_wallet::ListTransactionsResponse>> {
        info!("list_transactions called");
        let transactions = vec![bmp_wallet::Transaction {
            tx_id: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".to_owned(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            block_height: 123_456,
            date: 1_678_886_400,
            num_confirmations: 10,
            amount: 100_000,
            incoming: true,
        }];
        Ok(Response::new(bmp_wallet::ListTransactionsResponse {
            transactions,
        }))
    }

    async fn list_utxos(
        &self,
        _request: Request<bmp_wallet::ListUtxosRequest>,
    ) -> Result<Response<bmp_wallet::ListUtxosResponse>> {
        info!("list_utxos called");
        let utxos = vec![bmp_wallet::Utxo {
            tx_id: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".to_owned(),
            vout: 0,
            amount: 100_000,
            address: "bc1qvyw2m3f2y2p2l42jm2q5j2j2q2j2q2j2q2j2q2".to_owned(),
            num_confirmations: 10,
        }];
        Ok(Response::new(bmp_wallet::ListUtxosResponse { utxos }))
    }

    async fn send_to_address(
        &self,
        _request: Request<bmp_wallet::SendToAddressRequest>,
    ) -> Result<Response<bmp_wallet::SendToAddressResponse>> {
        info!("send_to_address called");
        Ok(Response::new(bmp_wallet::SendToAddressResponse {
            tx_id: "e40a1b5b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b1a1b".to_owned(),
        }))
    }

    async fn is_wallet_encrypted(
        &self,
        _request: Request<bmp_wallet::IsWalletEncryptedRequest>,
    ) -> Result<Response<bmp_wallet::IsWalletEncryptedResponse>> {
        info!("is_wallet_encrypted called");
        Ok(Response::new(bmp_wallet::IsWalletEncryptedResponse {
            encrypted: true,
        }))
    }

    async fn get_balance(
        &self,
        _request: Request<bmp_wallet::GetBalanceRequest>,
    ) -> Result<Response<bmp_wallet::GetBalanceResponse>> {
        info!("get_balance called");
        Ok(Response::new(bmp_wallet::GetBalanceResponse {
            balance: 123_456_789,
        }))
    }

    async fn get_seed_words(
        &self,
        _request: Request<bmp_wallet::GetSeedWordsRequest>,
    ) -> Result<Response<bmp_wallet::GetSeedWordsResponse>> {
        info!("get_seed_words called");
        let seed_words =
            "abandon ability able about above absent absorb abstract absurd abuse access accident"
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<String>>();
        Ok(Response::new(bmp_wallet::GetSeedWordsResponse {
            seed_words,
        }))
    }

    async fn encrypt_wallet(
        &self,
        _request: Request<bmp_wallet::EncryptWalletRequest>,
    ) -> Result<Response<bmp_wallet::EncryptWalletResponse>> {
        info!("encrypt_wallet called");
        Ok(Response::new(bmp_wallet::EncryptWalletResponse {
            success: true,
        }))
    }

    async fn decrypt_wallet(
        &self,
        _request: Request<bmp_wallet::DecryptWalletRequest>,
    ) -> Result<Response<bmp_wallet::DecryptWalletResponse>> {
        info!("decrypt_wallet called");
        Ok(Response::new(bmp_wallet::DecryptWalletResponse {
            success: true,
        }))
    }
}
