## Proposed update to the bisq-musig protocol
Based on suddenwhipvapor comments about privacy of the protocol in case of alternative paths, I took a fresh look at the protocol and figured out 3 optimizations. In total increasing the privacy, but also making the protocol easier to implement. (see new transaction graph at the end of the post)

### abandon CSV scripts in WarningTx
(see the old transaction graph for the CSV scripts)
To enforce that a transaction cannot be used before a certain waiting time, the transaction needs to have the nSequence property of the input (Vin) to be set to a certain value. This can be enforced by using the OP_CSV op code, but when we enforce that all transactions are created pre-signed by both parties, then we can enforce the nSequence of the input by the fact that at least one party will only sign a transaction if it has nSequence set.

For example if the WarningTx is mined, the RedirectTx shall not be broadcasted before a certain timedelay $t_1$. Since Alice and Bob both need to sign the RedirectTx, one of them will simply not sign any RedirectTx which has no nSequence.

To make this work, we need to make the ClaimTx a pre-signed Transaction as well (which is was not before). This is a little disadvantage for the person wanting to use the ClaimTx, because now he has to supply a Address where to send the funds to at the time when the trade starts (at which point the ClaimTx would need to get constructed and signed now). But I think this is a minor issue. abandoning the CSV scripts has the advantage of making the alternative paths much simpler and more private.

### SwapTx can only be used by the Seller
If the seller is the one which can use the SwapTx, we can sign he SwapTx right in the beginning when the trade starts (together with all other transactions). The SwapTx is the only transaction that needs adaptive MuSig signature. When Alice (as Seller) uses the SwapTx prematurely, then the adaptive signature reveals the secret key to Bob which enables him to retrieve the deposit and the trade amount (Output 0 from DepositTx). So effectively Alice would give away the trade amount. She will not do that and keep the SwapTx transaction to herself until she has the fiat payment.
This works only if the seller has the SwapTx not the buyer.

This seems like a minor change, but does have an important impact. Since the SwapTx can be constructed and signed at the time of construction of the trade, there is no need for the traders to be online at any other time. The adaptive signature for SwapTx was previously constructed at the time when the UTXO swap happens. But this is not needed any more. Now, the swap can be handled with 1 message from Alice (sending Bob the missing key for the 2of2 MS) and 1 message from Bob to Alice (sending the missing key). And that would be fine for asynchronous communication.
With this the bisq-musig protocol is on par with the Bisq1 protocol in terms of needing to have the traders being online at the same time only once (at the construction time).

### Anchor outputs

The WarningTx and RedirectTx need anchor outputs, because they dont have any output which could be used by Alice or Bob to just speed up mining through CPFP. For the RedirectTx it is important to be able to get it mined
in a certain timeframe, otherwise the ClaimTx could be used.
