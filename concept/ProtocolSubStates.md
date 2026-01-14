# The bisq-musig protocol state maschine
The bisq-musig protocol describes the communication between the 2 traders conducting the trade.
Each communication between the 2 parties will result in different state of the state maschine, and the traders have
some predefined options of what they (or the bisq software) will so, also based on events resulting from the blockchain
and time expiration.
The graphics below shows the Overview of states. below it we will describe the states and 
substates of it. It is intended that this state maschine will be implemented in the Java part of 
Bisq2 using the FSM.

![StateMachine.drawio.png](StateMachine.drawio.png)

1. signing of Txs
   this is already implemented in rust, basically the running test link serves as a rust 
   implementation of what needs to be implemented in Java with FSM. Please see the [test-case here](https://github.com/bisq-network/bisq-musig/blob/main/protocol/src/lib.rs#L23).
   It basically consists of 5 Rounds of communication where each rounds has a class 
   Round1Request and Round1Response. The data in these classes need to be exchanged between the 
   peers.

2. DepositTx broadcast
   -no substates-

3. Seller broadcasts SwapTx
    1. Seller broadcasts SwapTx has no additional state for the seller
    2. Buyer gets informed of chain-services that SwapTx is being detected, then continue with 6.

4. Traders exchange secret keys for P'\
    1. Seller sends hie partial key to Buyer\
    1. Buyer receives a partial key from Seller
    1. continue with 7.

5. Seller or Buyer broadcast WarningTx.
   Note that there are two (slightly) different WarningTxs for seller and buyer
    1. S or B presses the button to broadcast WarningTx
    2. B or S sees that WarningTx is confirmed on blockchain (seeing in mempool is not enough)
    3. continue with 8.

6. No additional substates (will be one call to the rust code)

7. Traders exchange secret keys for Q'
    1. Buyer send private key for Q' to seller
    2. Users (Buyer and seller) get informed that the trade is over and funds can be spend.

8. +9. can be made into one state API-call for the java code.
Something like checkWarningKeysExchanged(...) could be called and returns true iff keys were present and funds have been transafered to wallet.
    1. Users need to be informed about funds being transferred.

10. t1 expired
    time trigger should go off if other trader broadcasted the WarningTx and t1 expired. no substates
11. If the other trader broadcasted the WarningTx , we need to send the RedirectTx to get into Arbitration.
    The trade ends in arbitration, some substate need to be added here, basically the same procedure as in bisq1.
12. time trigger if we posted the WarningTx and RedirectTx did not appear on chain yet.
13. Seller or Buyer broadcast ClaimTx. Workflow ends with ClaimTx.
