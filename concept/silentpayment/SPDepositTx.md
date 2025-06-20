# trade fee payment in the DepositTx

In this section I am going a little further into details on how to use [silent payment](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
for trade fee payment when using
an extra utxo of the `DepositTx` for trade fee payment to the BM. The intention is to lay out the
theoretical foundations to understand silent payments in our use case. Keep in mind that this is an abstraction
and still has some simplifications.
In this section, Alice and Carol are the
traders and Bob is the BM that receives the trade fee payment. Prerequisite to this section would be the chapter
of `working principle of silent payments` from [the silent payment article](SilentPayment.md), but we are going much more into details as its
needed for the cooperative payment with SP.
The trade fee payment is modeled as another UTXO of `DepositTx`,
this was suggested by Hendrik lately as this is a simple solution for now.

![DepostTx.drawio.svg](../renderedForWeb/DepostTx.drawio.svg)

Bob needs to make his SP address known to the traders, which is done through the DAO as it is done
today in Bisq1. From the SP address there is a way to calculate the shared secret and from that the
effective taproot address which will be used in the transaction.

### [Inputs For Shared Secret Derivation](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#inputs-for-shared-secret-derivation)

For deriving the shared secret (to produce the target address), we need at
least one Public key (and private key)
which is known to the sender.
So the utxos which fund the DepositTx both need to have a public/private key in one of the following
forms:

- P2TR (only if the witness (keypath or scriptpath) has exactly one key)
- P2WPKH
- P2SH-P2WPKH
- P2PKH

All funding UTXOs for the DepositTx need to be used for the Shared Secret Key and need to have exactly one
private/public key which can be extracted by silent payment.

### calculation for the senders

First we calculate a `hash_input`
$$h:=hash(o ~||~ A+C)$$
where \
$o$ is the smallest outpoint of `DepositTx` lexicographically \
$a = a_1+...+a_n~$ is the sum of all private keys from Alice's contributed Pubkeys.\
$c = c_1+...+c_m~$ is the sum of all private keys from Carol's contributed Pubkeys.\
$A = a \cdot G~$ is the sum of pubkeys from Alice\
$C = c \cdot G~$ is the sum of pubkeys from Carol

The hash $h$ commits to all involved public keys and to a part of one input transaction, so
the resulting payment address can only be used with this transaction and reuse is impossible.

Alice and Carol construct the target pubkey in the following manner:
$$(1) \hspace{10px}P = B_{SPEND} + hash(h \cdot (a \cdot B_{SCAN} + c \cdot B_{SCAN}) ~||~ 0) \cdot G$$

Bob detects this payment by calculating
$$(2) \hspace{10px}P = B_{SPEND} + hash(h \cdot b_{SCAN} \cdot (A+C) ~||~ 0) \cdot G$$
where \
$~~B_{SPEND} = b_{SPEND} \cdot G ~$ is the key needed for spending P, it is only in possession of Bob. \
$~~B_{SCAN} = b_{SCAN} \cdot G ~$ is the key needed for scanning the blockchain, it may be in possession of a scanning server

The formula in (1) contains '$|| 0$', which is a concatenation with zero. The BIP-352 standard states
to have index numbers to differentiate several SP Addresses within the same transaction to prevent reuse of addresses.
Since we have only one SP output, we can hardcode index $0$.

By using Deffie-Hellman we can prove that (1) and (2)
actually calculate to the same address:
$$\begin{eqnarray}
a \cdot B_{SCAN} + c \cdot B_{SCAN} &=& (a+c) \cdot B_{SCAN} \\
&=& (a+c) \cdot b_{SCAN} \cdot G \\
&=& b_{SCAN} \cdot (a+c) \cdot G \\
&=& b_{SCAN} \cdot (a \cdot G + c \cdot G) \\
&=& b_{SCAN} \cdot (A+C) \\
\end{eqnarray}$$

### exchange of data

To do this calculation, Alice and Carol actually need some information from each other.
Looking at the formula (1) Alice would need from Carol

- $h$
- $c \cdot B_{SCAN}$

Alice and Carol are constructing the transaction `DepositTx` in a collaborative manner anyway, so the
inputs are shared already. The `hash_input` $h:=hash(o ~||~ A+C)$ can be calculated without further information exchange.
Alice needs to get $c \cdot B_{SCAN}$ from Carol. This product is new information that needs to be shared.
Since $c$ is encrypted by multiplication with curve point $B_{SCAN}$ Alice will not learn
anything from Carol.
Carol could send any bogus data and effecting the sum inside the $hash$ function of (1).
Whatever effect Carol may have with the bogus data, after hashing it, she cannot predict the
effect on the outer sum ($B_{SPEND}+hash(...)$). Therefore, she may have the effect of constructing an
address that is not redeemable for Bob, but the resulting address will not be redeemable for Carol.
So Carol has no incentive to send manipulated data.

For our use case in Bisq, it's enough to know that Carol cannot take advantage of sending manipulated data,
worst case is that Bob cannot claim the fees.

###