# Protocol Update 2

Stejbac suggested the following updates.

## reverting ClaimTx to former Script solution

ClaimTx shall now be created when needed\
pro: no anchor output needed, anything else?\
con: less private, introduces scripts

## removing time delay of RedirectTx

The time delay is actually not needed.

## PunishTx shall be created by protocol not by wallet

This is mainly only a change in the responsibilities of the different modules.\
pro: This keeps the wallet more standard, it doesn't need to observe a txid,
which is unusual for wallets.\
con: protocol needs to keep the secret key even after sending it to the wallet.
(not really an issue)

# Observing the blockchain for the protocol

This is actually not part of the Update, but wanted to mention it here.
The protocol needs to observe the blockchain. This can be done in all cases through observing Txid being broadcasted.
In detail this is:

- Observe SwapTx to read the adaptor signature
- WarningTx if the key exchange has not being done, then publish the RedirectTx
- WarningTx if the key exchange has been done, then publish the PunishTx