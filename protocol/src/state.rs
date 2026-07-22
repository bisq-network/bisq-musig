use std::cmp::Ordering;
use std::fmt::{Display, Formatter};

#[expect(clippy::exhaustive_enums)]
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug)]
pub enum TradeState {
    /// Initial data exchange phase at the start of the trade. No real commitments have been made
    /// yet and it is safe to abandon the trade without persisting any of its state.
    #[default]
    Init,
    /// We have signed the Deposit PSBT and are ready to share it. The peer may or may not already
    /// have our signatures on it. The Deposit Tx may or may not have been broadcast or confirmed.
    Deposit,
    /// - (If buyer) we are ready to release our lock on the escrow by sharing our partial signature
    ///   on the Swap Tx, which the seller may or may not have already received.
    /// - (If seller) we have already received the buyer's partial signature on the Swap Tx and
    ///   persisted it, releasing their lock on the escrow.
    BuyerReadyToRelease,
    /// (For seller only.) We are ready to release our lock on the escrow by revealing our key share
    /// for the buyer's payout. The buyer may or may not already have it.
    SellerReadyToRelease,
    /// We have signed a Custom Payout PSBT and are ready to share it. The peer may or may not
    /// already have our signatures on it. The fully signed Custom Payout Tx has not yet been seen
    /// on the network.
    CustomPayoutSigned,
    /// - (If buyer) we have persisted our decision not to close the trade normally and broadcast
    ///   our Warning Tx instead. It may or may not have successfully broadcast or confirmed yet.
    /// - (If seller) we have seen the buyer's Warning Tx and persisted its full signature.
    BuyersWarning,
    /// - (If buyer) we have seen the seller's Warning Tx and persisted its full signature.
    /// - (If seller) we have persisted our decision not to close the trade normally and broadcast
    ///   our Warning Tx instead. It may or may not have successfully broadcast or confirmed yet.
    SellersWarning,
    /// The trade closed with the given [`ClosureType`], which may subsequently change, such as from
    /// [`ClosureType::Cooperative`] to [`ClosureType::BuyersPenaltyTx`]. The trade will not reopen.
    TradeClosed(ClosureType),
}

#[expect(clippy::exhaustive_enums)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ClosureType {
    Cooperative,
    Forced,
    Custom,
    BuyersRedirect,
    SellersRedirect,
    BuyersClaim,
    SellersClaim,
    BuyersPenaltyTx,
    SellersPenaltyTx,
}

impl TradeState {
    pub const VALUES: [Self; 16] = [
        Self::Init,
        Self::Deposit,
        Self::BuyerReadyToRelease,
        Self::SellerReadyToRelease,
        Self::CustomPayoutSigned,
        Self::BuyersWarning,
        Self::SellersWarning,
        Self::TradeClosed(ClosureType::Cooperative),
        Self::TradeClosed(ClosureType::Forced),
        Self::TradeClosed(ClosureType::Custom),
        Self::TradeClosed(ClosureType::BuyersRedirect),
        Self::TradeClosed(ClosureType::SellersRedirect),
        Self::TradeClosed(ClosureType::BuyersClaim),
        Self::TradeClosed(ClosureType::SellersClaim),
        Self::TradeClosed(ClosureType::BuyersPenaltyTx),
        Self::TradeClosed(ClosureType::SellersPenaltyTx),
    ];

    pub fn precedes(self, new_state: Self) -> bool {
        self < new_state && new_state.minimal_predecessors().iter().any(|s| *s <= self)
    }

    const fn minimal_predecessors(self) -> &'static [Self] {
        use ClosureType::Cooperative;
        use TradeState::{BuyersWarning, CustomPayoutSigned, SellersWarning, TradeClosed};
        const COOP: TradeState = TradeClosed(Cooperative);

        match self {
            Self::Init => &[],
            Self::Deposit => &[Self::Init],
            Self::BuyerReadyToRelease | CustomPayoutSigned | BuyersWarning | SellersWarning => {
                &[Self::Deposit]
            }
            Self::SellerReadyToRelease | TradeClosed(Cooperative | ClosureType::Forced) => {
                &[Self::BuyerReadyToRelease]
            }
            TradeClosed(ClosureType::Custom) => &[CustomPayoutSigned],
            TradeClosed(ClosureType::BuyersRedirect) => &[SellersWarning],
            TradeClosed(ClosureType::SellersRedirect) => &[BuyersWarning],
            TradeClosed(ClosureType::BuyersClaim) => &[BuyersWarning, COOP],
            TradeClosed(ClosureType::SellersClaim) => &[SellersWarning, COOP],
            TradeClosed(ClosureType::BuyersPenaltyTx | ClosureType::SellersPenaltyTx) => &[COOP],
        }
    }

    const fn bits(self) -> u16 {
        match self {
            Self::Init /*                                      -*/ => 0x000, // . .... ....
            Self::Deposit /*                                   -*/ => 0x001, // . .... ...1
            Self::BuyerReadyToRelease /*                       -*/ => 0x003, // . .... ..11
            Self::SellerReadyToRelease /*                      -*/ => 0x007, // . .... .111
            Self::CustomPayoutSigned /*                        -*/ => 0x013, // . ...1 ..11
            Self::BuyersWarning /*                             -*/ => 0x033, // . ..11 ..11
            Self::SellersWarning /*                            -*/ => 0x053, // . .1.1 ..11
            Self::TradeClosed(ClosureType::Cooperative) /*     -*/ => 0x00f, // . .... 1111
            Self::TradeClosed(ClosureType::Forced) /*          -*/ => 0x067, // . .11. .111
            Self::TradeClosed(ClosureType::Custom) /*          -*/ => 0x093, // . 1..1 ..11
            Self::TradeClosed(ClosureType::BuyersRedirect) /*  -*/ => 0x153, // 1 .1.1 ..11
            Self::TradeClosed(ClosureType::SellersRedirect) /* -*/ => 0x133, // 1 ..11 ..11
            Self::TradeClosed(ClosureType::BuyersClaim) /*     -*/ => 0x03f, // . ..11 1111
            Self::TradeClosed(ClosureType::SellersClaim) /*    -*/ => 0x05f, // . .1.1 1111
            Self::TradeClosed(ClosureType::BuyersPenaltyTx) /* -*/ => 0x08f, // . 1... 1111
            Self::TradeClosed(ClosureType::SellersPenaltyTx) /*-*/ => 0x10f, // 1 .... 1111
        }
    }
}

impl PartialOrd for TradeState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let [x, y] = [self.bits(), other.bits()];
        if x == y {
            Some(Ordering::Equal)
        } else if x & y == x {
            Some(Ordering::Less)
        } else if x & y == y {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

// We shouldn't really define a `Display` impl via the derived `Debug` impl, since the latter makes
// no stability promise. However, it is extremely unlikely to change in this simple case (and any
// such change would break the unit tests below).
impl Display for TradeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
const TRADE_STATE_TRANSITION_GRAPH: &str = r#"digraph transitions {
    "Init" -> "Deposit"
    "Deposit" -> "BuyerReadyToRelease"
    "Deposit" -> "CustomPayoutSigned" [style=dashed]
    "Deposit" -> "BuyersWarning" [style=dashed]
    "Deposit" -> "SellersWarning" [style=dashed]
    "BuyerReadyToRelease" -> "SellerReadyToRelease"
    "BuyerReadyToRelease" -> "CustomPayoutSigned"
    "BuyerReadyToRelease" -> "BuyersWarning" [style=dashed]
    "BuyerReadyToRelease" -> "SellersWarning" [style=dashed]
    "BuyerReadyToRelease" -> "TradeClosed\n(Cooperative)" [style=dashed]
    "BuyerReadyToRelease" -> "TradeClosed\n(Forced)" [style=dashed]
    "SellerReadyToRelease" -> "TradeClosed\n(Cooperative)"
    "SellerReadyToRelease" -> "TradeClosed\n(Forced)"
    "CustomPayoutSigned" -> "BuyersWarning"
    "CustomPayoutSigned" -> "SellersWarning"
    "CustomPayoutSigned" -> "TradeClosed\n(Custom)"
    "BuyersWarning" -> "TradeClosed\n(SellersRedirect)"
    "BuyersWarning" -> "TradeClosed\n(BuyersClaim)"
    "SellersWarning" -> "TradeClosed\n(BuyersRedirect)"
    "SellersWarning" -> "TradeClosed\n(SellersClaim)"
    "TradeClosed\n(Cooperative)" -> "TradeClosed\n(BuyersClaim)"
    "TradeClosed\n(Cooperative)" -> "TradeClosed\n(SellersClaim)"
    "TradeClosed\n(Cooperative)" -> "TradeClosed\n(BuyersPenaltyTx)"
    "TradeClosed\n(Cooperative)" -> "TradeClosed\n(SellersPenaltyTx)"
}
"#;

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use const_format::str_replace;

    use super::*;

    const EXPECTED_MINIMAL_DAG: &str = str_replace!(
        str_replace!(
            str_replace!(TRADE_STATE_TRANSITION_GRAPH, "\\n", ""),
            "    \"Deposit\" -> \"CustomPayoutSigned\" [style=dashed]\n    \
                 \"Deposit\" -> \"BuyersWarning\" [style=dashed]\n    \
                 \"Deposit\" -> \"SellersWarning\" [style=dashed]\n",
            ""
        ),
        "    \"BuyerReadyToRelease\" -> \"BuyersWarning\" [style=dashed]\n    \
             \"BuyerReadyToRelease\" -> \"SellersWarning\" [style=dashed]\n    \
             \"BuyerReadyToRelease\" -> \"TradeClosed(Cooperative)\" [style=dashed]\n    \
             \"BuyerReadyToRelease\" -> \"TradeClosed(Forced)\" [style=dashed]\n",
        ""
    );
    const EXPECTED_FULL_DAG: &str = str_replace!(
        str_replace!(TRADE_STATE_TRANSITION_GRAPH, "\\n", ""),
        " [style=dashed]",
        ""
    );

    #[test]
    fn trade_state_partial_order_has_expected_minimal_dag() {
        let mut dag = "digraph transitions {\n".to_owned();
        for s in TradeState::VALUES {
            for t in TradeState::VALUES {
                if s < t && TradeState::VALUES.into_iter().all(|u| !(s < u && u < t)) {
                    writeln!(&mut dag, r#"    "{s}" -> "{t}""#).unwrap();
                }
            }
        }
        writeln!(&mut dag, "}}").unwrap();
        assert_eq!(dag, EXPECTED_MINIMAL_DAG);
    }

    #[test]
    fn trade_state_has_expected_full_dag() {
        let mut dag = "digraph transitions {\n".to_owned();
        for s in TradeState::VALUES {
            for t in TradeState::VALUES {
                if s.precedes(t) {
                    writeln!(&mut dag, r#"    "{s}" -> "{t}""#).unwrap();
                }
            }
        }
        writeln!(&mut dag, "}}").unwrap();
        assert_eq!(dag, EXPECTED_FULL_DAG);
    }
}
