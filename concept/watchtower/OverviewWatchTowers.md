# Watchtowers problematic

This document tries to capture the main results of various discussions about the watchtower problematic in the Bisq
Musig protocol.
For a lack of a better name I call it the 'watchtower problematic'.

## What are we trying to solve?

In the happy path of the Bisq MuSig protocol (see protocol description), it ends with the key exchange
between Alice and Bob. In that state it is possible for Bob (and Alice) to broadcast the WarningTx, which would be
a breach to the protocol. Alice would need to react to this by broadcasting the PunishTx.
The problem is that Alice may not be online to realize that Bob has broadcasted the WarningTx.
This is where the watchtower comes in.

For Bob to conduct a successful attack, he would somehow know that Alice is offline,
because in case she is not, he will suffer a loss of his Deposit. Since the Bisq software will automatically
broadcast the PunishTx when online, the likelihood of a successful attack depends on Alice being offline.
He Bob hasn't any way to know that Alice is offline, the likelihood of conducting a successful attack is low.

## Watchtower functionality

The logic to detect the wrongly broadcasted WarningTx and broadcast the PunishTx is called Watchtower functionality.
This could be inside the normal Bisq application or an extra application.

## Watchtower functionality in Bisq

If the watchtower functionality is inside the Bisq application itself, it has most privacy, but the effectiveness
depends on the Bisq application running. If we could ensure that the Bisq application is running at least once
within the watchtower period, we would be safe. Since the Bisq application is a desktop app, we cannot ensure
that it's running always.

### Desktop app as Watchtower

If we had some functionality being autostart with the Operating system, we could
increase the probability of being online at the right time. (This is intended to only watch for one's own
transactions (see external Watchtowers))

### Mobile app as Watchtower

Mobile devices are almost always online, an app only would need to check the status every week or so. Which is not
much of a battery drain.

## mitigation by user awareness

### spend the UTXO from key exchange immediately be default

This, of course, is a little drawback from the Single transaction protocol. But if made optional, the user could be
informed of the small risk.

### shows a prominent warning to users

make sure to prominently warn traders that "Bisq2 has security checks in place to prevent risks, yet you
should withdraw funds to an external wallet within (claim TX timelock) to put them in a safer storage"

## external Watchtowers

The warning txid and the encrypted PunishTx would need to be passed to the service. It would detect the
WarningTx on the blockchain and decrypt the PunishTx by some key passed in the WarningTx. That way
privacy could be preserved mostly.

### specialized watchtowers

Bisq could run special nodes to act as watchtowers.

### other Bisq nodes as watchtowers

The watchtower functionality could be implemented for other in the Bisq application.
This, of course, needs some thoughts on how to limit the amount of work for each Bisq node and still ensuring that
all transactions to watch for have a high enough probability to get executed.

## likelihood of an attack

Without any information of the likelihood of the other person being unobservant, the attack would not be economically
feasible.
The attacker could observe that a UTXO is very old and therefore think that the other party is not paying attention
properly.
However, it also could be the other way around, that the UTXO is actually very old, but the owner is observing it
to wait for an attacker to try to steal it and then get the Deposit of the attack by sending the PunishTx.

This attack would be more profitable for the seller to get back the trade funds from the other party. However,
Since the trade had been successful already, the seller's bank account information is known to the buyer.
And even if the attack is successful, afterward the buyer can prove that he was scammed and has the bank account
info from that person.

If the Bisq application is never started again after such a successful attack happened, it could detect that situation
and give the user advice on what to do and send off a report to the DAO.

# Conclusion

Given the arguments in 'likelihood of an attack', I think the attack is very risky. At this point it seems we are
putting too much effort into preventing a case that might never be an issue. To start the Bisq MuSig, I think it would
be sufficient to install a service on the operating system, which does a check once a week. And also have a reporting
functionality in Bisq. 