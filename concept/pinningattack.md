# pinning attack on SingleTransaction protocol

Our protocol relies heavily on presigned transactions, which come with the difficulty of not knowing
the correct mining fee at the time the signature is made. This introduces the problem of pinning.
Pinning attacks are about preventing the opponent's fee-bump transactions from entering the mempool.

## mempool policy rules

There are currently three different sets of mempool rules which are relevant for pinning:

1. the legacy policy for non-TRUC (version 2) transactions, which is what we use right now: BIP-125
   RBF, ancestor/descendant limits of 25 transactions / 101 kvB, and the CPFP carve-out rule,
2. TRUC / BIP-431 (version 3 transactions): at most one unconfirmed child, a child size limit of
   1000 vB, and sibling eviction,
3. cluster mempool, live since Bitcoin Core 31: ancestor/descendant limits and the carve-out are
   replaced by cluster limits of 64 transactions / 101 kvB.

They affect us since we have presigned transactions which may need fee bumping. Since cluster mempool
is the newest set of rules, any attack vector needs to be tested against it.

## attack scenario

Assuming cluster mempool (Bitcoin Core 31+).

Relevant properties of the current implementation (`protocol/src/transaction.rs`):

- `WarningTx` has a relative timelock on its inputs (`MAINNET_WARNING_LOCK_TIME`, 1440 blocks) and
  an anchor output which only the broadcasting party can spend.
- `RedirectTx` has **no relative timelock** (`MAINNET_REDIRECT_LOCK_TIME = LockTime::ZERO`, i.e.
  nSequence = `0xFFFFFFFD`), so it can be broadcast while the `WarningTx` is still unconfirmed. 
- `ClaimTx` spends the `WarningTx` escrow output via a script path with `OP_CSV`
  (`MAINNET_CLAIM_LOCK_TIME`, 720 blocks), so it can never be in the mempool together with its
  `WarningTx`.

In this scenario the seller is the victim:

1. The seller broadcasts the `SellersWarningTx` at its presigned fee rate, intending to bump it
   afterwards via CPFP on its anchor output.
2. The buyer (attacker) immediately broadcasts the `BuyersRedirectTx`, which spends the unconfirmed
   `SellersWarningTx`.
3. The buyer attaches a chain of junk transactions below the anchor output of the `RedirectTx`. With
   62 junk transactions the cluster reaches the limit of 64 transactions (`WarningTx` + `RedirectTx`
   \+ 62). Alternatively, fewer but larger junk transactions can hit the 101 kvB cluster size limit.
4. The seller wants to broadcast a CPFP for the `SellersWarningTx`, but it is rejected because the
   cluster would exceed its limits. The `SellersWarningTx` is now pinned at a possibly insufficient
   fee rate.
5. The buyer broadcasts the `BuyersWarningTx` (together with a CPFP child as a package), which
   conflicts with the `SellersWarningTx`, since both spend the same `DepositTx` outputs. This is an
   RBF of the whole cluster: the buyer must pay a higher absolute fee than all evicted transactions
   combined (including his own junk chain), plus the incremental relay fee. This is the cost of the
   attack, but it can be small if the junk chain was kept at a low fee rate.
6. If the seller's software does not react to its `WarningTx` being replaced by the peer's
   `WarningTx` (e.g. its internal state is still `SellersWarning`, which cannot send
   `SellersRedirectTx`), the seller will not broadcast the `SellersRedirectTx`.
7. After the CSV delay of the `ClaimTx` has passed, the buyer broadcasts the `BuyersClaimTx` and
   captures the funds.

Note that steps 6 and 7 are not a pinning issue in themselves: once the `BuyersWarningTx` confirms,
the seller has the whole CSV window of the `ClaimTx` to broadcast the `SellersRedirectTx`. The funds
are only lost if the seller's state machine fails to handle a replaced or conflicting `WarningTx`.
Conversely, without that handling the buyer does not even need the pinning of steps 2–4 — any RBF of
a low-fee `SellersWarningTx` leads to the same result.

## countermeasures

Different countermeasures work under different mempool rules:

- **CPFP carve-out** is not available under cluster mempool. Its preconditions are not met anyway,
  since the `RedirectTx` can spend the `WarningTx` escrow output while unconfirmed.
- **Broadcasting the fee bump together with the transaction** (package relay of `WarningTx` + CPFP)
  can always be done and gets the `WarningTx` into the mempool at a sufficient fee rate. It is only a
  partial defence: the attacker can still attach `RedirectTx` + junk below it up to the cluster
  limit. Replacing the seller's CPFP with a higher-fee one (1-for-1 RBF) keeps the cluster count
  unchanged and therefore still works, unless the larger replacement pushes the cluster over the
  101 kvB size limit. Sudden spikes in the mining fee may therefore still leave the seller unable to
  bump further.
- **`nSequence=1` (relative timelock of 1 block) for the `RedirectTx`**. Since all our transactions
  are version 2, BIP-68 applies, and the `RedirectTx` can then only enter the mempool after the
  `WarningTx` is confirmed. The only unconfirmed child a `WarningTx` can then have is the CPFP
  spending its own anchor, which only the broadcasting party can sign. The cluster cannot be
  inflated by the peer, and the pinning attack described above is not possible under any of the
  three sets of rules. The cost is a delay of one block for the legitimate use of the `RedirectTx`,
  which is negligible compared to the `ClaimTx` delay.
- **State machine handling of a replaced `WarningTx`**, independently of pinning: the trade protocol
  must detect when the peer's `WarningTx` is confirmed (or replaces its own `WarningTx` in the
  mempool) and respond with its own `RedirectTx` before the `ClaimTx` delay expires.
