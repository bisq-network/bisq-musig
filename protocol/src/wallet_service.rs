/*
This represents a service to get access to the wallet
as of now its a fake implementation, you need to pass in the wallet which you
want to retrieve later. In the real version this should discover and actually load the user's wallet.
 */
use crate::protocol_musig_adaptor::MemWallet;

#[derive(Default)]
pub struct WalletService {
    wallet_opt: Option<MemWallet>,
}

impl WalletService {
    pub fn retrieve_wallet(self) -> MemWallet {
        self.wallet_opt.unwrap()
    }

    pub const fn new() -> Self {
        Self { wallet_opt: None }
    }

    #[must_use]
    pub fn load(mut self, wallet: MemWallet) -> Self {
        self.wallet_opt = Some(wallet);
        self
    }
}
