# Mempool in privacy preserving way

## use case

When the user wants to fund the bisq wallet, he may send from an external wallet
to the bisq wallet. For the bisq wallet to start the trade it needs to make sure that enough funds are available.
Also when a trade is starting it needs to fund the DepositTx. For the funding the wallet needs at least to see the incoming transaction in the
mempool. It doesn't need to be on-chain yet. Because, to construct the DepositTx, it's enough to have the outputs which will fund the DepositTx.
There are no other use case, while the protocol is interested in knowing new transaction its sufficient to see the transaction when they are on the chain.

## requirements

- The user should not be required to run a server with large disk requirements.
- If the user's computer is off, and then comes up again, the load time should be reasonable. (whatever that means)
- Ideally no extra infrastructure should by operated by the bisq team.
- Any server needed shall be able to be self hosted. Custom versions of bitcoin core or electrum are not considered at the moment)
- Last but not least, privacy should be preserved in both cases, self-hosted and not self-hosted.

## ideas so far

- electrum has no privacy, and it is too heavy to get a required local installation
- install locally a stripped down bitcoin core to receive the mempool locally.
- Download the mempool using RPCs then get update through ZMQ from bitcoin core.
- intercept the `inv` messages from bitcoins P2P-Network.

### bitcoin core locally

bitcoin core can be run in a pruned way, so it doesnt need to store the whole blockchain.
It needs some researrch to see how we exactly can configure it.
But iff bitcoin core is installed locally, but the computer is down, and then started again, how will it receive the missed messages?

### intercept the `inv` messages

BDK and BDK floresta libs are currently not able to intercept the `inv` messages.
rust-bitcoin has also limited support for it.
It would neeed a complex implementation. Also, all Messages that are being published will
need to be received by the client.

### RPCs and ZMQ -- whole mempool

This solution would need the provided bitcoin server to open these both technologies to the public. Also self hosted
bitcoin core server would need to be configured correctly (which they need to in bisq1 as well).

When the client starts, there might be transactions for it, which need to be downloaded from the mempool initially.

#### Initial Download

The RPC `getrawmemppol` will download all txids in the mempool.
The RPC `getrawtransaction` can get for all txids the transaction details.
The RPC interface is capable of batching several calls into one, this makes it more suitable
than the rest-interface of bitcoin core.

#### updates

bitcoin core has the interface of ZMQ (Zero Message Queue). This message service can inform about the messages in the mempool.
To preserve the privacy, we probably need to subscribe to all transaction being relayed, which is quite some traffic.
RPC Interface and ZMQ interface need to be enabled on the bitcoin core server, which is not done by default.
But this can be done easily on the bisq provided servers as well as on the self-hosted servers.
Potentially, this means that we exposed these APIs to the public.
We would need to research how scalable this solution is as a large number for client will download the mempool info
from the provided bisq servers.

### RPCs and ZMQ -- specific scritpubkeys

When we accept a privacy hit, things can get much easier.
wiith the RPC `scantxoutset`, we can query all utxos that belong to a set of scriptpubkeys.
And with RPC `gettxspendingprevout`, we can make sure these transactions are not yet spent
within the mempool.

Using these RPCs it could probably be possible to just poll the bitcoin core server in
a short timeframe.

Technically better would be to use ZMQ to get any update to this information. ZMQ can
filter the events to those we are interested in.

This approach lacks privacy, partially it can be mitigated by diluting the set of queried scriptpubkeys
with fake scriptpubkeys. But since the fake scriptpubkeys always return negative responses, the privacy gains are limited.
The bitcoin core operator will learn the pubkeys an onion address is asking for iff there are incoming transactions
for that pubkey.

## conclusion of the solutions

The bisq client is not always online. If it comes online after a while again, it needs to catch up with the mempool
and get all transactions that are relevant for it. Most of the ideas mentioned above lack of a way to catchup with the mempool.
A local bitcoin core instance will not pick up all unconfirmed transactions sent while it was offline.
The only way I see this as viable is to query running bitcoin core servers through RPCs. Since I think this is a mandatory
feature, I don't see a way around using RPCs for initial mempool loading.
Comparing the other solutions for just updating the mempool information, I think the ZMQ solution clearly wins without
detailed analysis necessary.

