# blinded signature and taproot signing

## motivation

The `SwapTx` will in most trades not be broadcasted to the blockchain. Therefore
Alice (the Seller, which creates the `SwapTx`) may not want the buyer to learn
the address used in the `SwapTx`. Since Bob (the buyer) needs to sign
the `SwapTx` this can only be done by letting him
blindly sign the transaction.

## basics of signing with key spends

When signing with the internal key in taproot transaction where there are
taproot script,
but we want to spend with the single internal key. For that we need to compute
the signing key $q$
which actually does the signature taking into account the merkle
root of the scripts.

$$q = p + H_{TapTweak}( P ~||~ m)$$

$$\begin{aligned}
\text{where}~~~~~~~~~~& \\
p &~~~~\text{is the internal key} \hspace{1000pt}\\
P = p \cdot G &~~~\text{ is the internal public key} \\
q &~~~~\text{is the tweaked private key, the key for the signature.}\\
m &~~~~\text{is the merkle root of all scripts (if there are any)}\\
\end{aligned}
$$

This effectively means that the signing key is dependent on the internal key and
the output scripts.

The $sighash$ is actually calculated from the transaction data (and other stuff) and is used
as input for the schnorr signature.

## blinded signature

Bob needs to make the signature for the `SwapTx`. Alice could send the
receiver address for the `SwapTx` and Bob could construct the `SwapTx`, then the
$sighash$ and then sign with the signing key $q$. But Alice doesn't want him to
learn the address, so she will only send the $sighash$ to Bob.

## possible attack

Since Bob is not knowing what he signs, Alice could let him sign any transaction.
The transaction is signed with the signing key $q$ by Bob and therefore
is limited only by 2 conditions:

- the internal Key (which $q'$)
- the outputs scripts

The `DepositTx` and The `WarningTx` both have an output with $Q'$ as internal pubkey.
So Alice could use the blinded signature for the `WarningTx` instead of the ``DepositTx``.
The only thing preventing her to do so is if the scripts of `DepositTx Output 1`
and `WarningTx Output 0` and actually different.

