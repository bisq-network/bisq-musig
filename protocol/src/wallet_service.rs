/*
This represents a service to get access to the wallet
as of now its a fake implementation, you need to pass in the wallet which you
want to retrieve later. In the real version this should discover and actually load the user's wallet.
*/
use crate::psbt::TradeWallet;

/// Type-erased wallet handle used by the trade protocol. The concrete wallet may be a
/// `MemWallet`, a `BMPWallet<Connection>`, or any other type that implements [`TradeWallet`].
pub type BoxedTradeWallet = Box<dyn TradeWallet + Send>;

#[derive(Default)]
pub struct WalletService {
    wallet_opt: Option<BoxedTradeWallet>,
}

impl WalletService {
    pub fn retrieve_wallet(self) -> BoxedTradeWallet {
        self.wallet_opt.unwrap()
    }

    pub const fn new() -> Self {
        Self { wallet_opt: None }
    }

    #[must_use]
    pub fn load<W: TradeWallet + Send + 'static>(mut self, wallet: W) -> Self {
        self.wallet_opt = Some(Box::new(wallet));
        self
    }

    /// Load an already-boxed wallet. Useful when a helper produces the boxed trait object
    /// directly (e.g. a switch that returns either `MemWallet` or `BMPWallet`).
    #[must_use]
    pub fn load_boxed(mut self, wallet: BoxedTradeWallet) -> Self {
        self.wallet_opt = Some(wallet);
        self
    }
}
