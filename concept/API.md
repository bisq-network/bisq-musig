# Java Protocol & Rust API

Rust protocol intention is to keep all cryptogrphy and blockchain access inside rust, but not more. All other logic shall be implemented in Java Protocol.

1. User accepts Offer -> api call init(), signing of Transactions and DepositTx broadcast (1+2)
2. On the UI a Button for sending the WarningTx appears.
1. automatic timeout on broadcasting DepositTx, if DepositTx not broadcasted, but has been signed already,
   then Alice must broadcast a transaction to spend the input of the DepositTx to herself. Status changes to FAILED. Java protocol needs to get a message.
2. automatic timeout, init() take too long (but signing of DepsoitTx has not been done),
3. Bob pays amount -> state of Java protocol changes, Rust protocol : no changes.
4. Alice receives Fiat -> state of Java protocol changes (Button for SwapTx appears on UI), Rust: Seller sends secret key for P'  (and S').
4. P2P event Bob receives seckey for P' (and R'):  Bob responds with secret key for Q' (and S') -> TradeState changes to 'success'.
7. Automatic event: Timeout on Alice side -> Alice broadcasts SwatTx
8. Alice may also press the Button for immediate release (swap-Button); SwapTx is broadcasts
6. blockchain event: Bob discovers SwapTx on blockchain: Bob reveals the adaptor from the SwatTx signature and constructs P'. (diagramm 3+6)
10. Warning Button pressed -> Java protocol changes, Rust: broadcast WarningTx and set a timer for t2 to expire. (diagram 5)
11. blockchain event: WarningTx is detected: Rust: if we have the keys R' or S' then automatically create a transaction to myself and broadcast it. (WarningTx payout).(diagram 8+9)
    if we dont have the key, set a timer to wait until t1 expires.(diagram 10)
12. timeout event, t1 has expired: Rust automatic: broadcasts RedirectTx.(diagram 10+11),
13. timeout event, t2 has expired: Rust automatic: broadcasts ClaimTx (diagram 12+13)
