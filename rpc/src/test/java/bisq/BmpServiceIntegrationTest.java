package bisq;

import bmp_protocol.BmpProtocolServiceGrpc;
import bmp_protocol.BmpProtocol.*;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class BmpServiceIntegrationTest {

    private ManagedChannel alice_channel;
    private ManagedChannel bob_channel;
    private BmpProtocolServiceGrpc.BmpProtocolServiceBlockingStub aliceStub;
    private BmpProtocolServiceGrpc.BmpProtocolServiceBlockingStub bobStub;
    private final NigiriCli nigiri = new NigiriCli();

    @BeforeAll
    void setup() {
        alice_channel = ManagedChannelBuilder.forAddress("localhost", 50052)
                .usePlaintext()
                .build();
        bob_channel = ManagedChannelBuilder.forAddress("localhost", 50051)
                .usePlaintext()
                .build();

        aliceStub = BmpProtocolServiceGrpc.newBlockingStub(alice_channel);
        bobStub = BmpProtocolServiceGrpc.newBlockingStub(bob_channel);

        // Mine some blocks on Nigiri to ensure its wallet has funds for any fees.
        System.out.println("Mining initial blocks for Nigiri...");
        nigiri.mineBlocks(101);
    }

    @AfterAll
    void tearDown() throws InterruptedException {
        if (alice_channel != null) {
            System.out.println("Shutting down alice gRPC channel.");
            alice_channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
        }
        if (bob_channel != null) {
            System.out.println("Shutting down bob  gRPC channel.");
            bob_channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void testHappyPathFullProtocolAndBroadcast() throws IOException, InterruptedException {

        System.out.println("Starting transaction... ");
        // ===  Initialize Trades for Alice (Seller) and Bob (Buyer) ===
        InitializeRequest aliceInitReq = InitializeRequest.newBuilder()
                .setRole(Role.SELLER)
                .setSellerAmountSats(100_000) // Alice's trade amount + deposit
                .setBuyerAmountSats(50_000)  // Bob's deposit
                .build();
        InitializeResponse aliceInitRes = aliceStub.initialize(aliceInitReq);
        String aliceTradeId = aliceInitRes.getTradeId();
        assertNotNull(aliceTradeId);
        System.out.println("Alice (Seller) initialized with trade_id: " + aliceTradeId);

        InitializeRequest bobInitReq = InitializeRequest.newBuilder()
                .setRole(Role.BUYER)
                .setSellerAmountSats(100_000)
                .setBuyerAmountSats(50_000)
                .build();
        InitializeResponse bobInitRes = bobStub.initialize(bobInitReq);
        String bobTradeId = bobInitRes.getTradeId();
        assertNotNull(bobTradeId);
        System.out.println("Bob (Buyer) initialized with trade_id: " + bobTradeId);

        // ===  Execute 5-Round Protocol ===

        // -- ROUND 1: Both parties generate their public data --
        Round1Request aliceRound1Req = Round1Request.newBuilder().setTradeId(aliceTradeId).build();
        Round1Response aliceRound1Data = aliceStub.executeRound1(aliceRound1Req);
        System.out.println("Alice finished Round 1.");
        assertFalse(aliceRound1Data.getDepPartPsbt().isEmpty(), "Alice's Round 1 PSBT is empty");

        Round1Request bobRound1Req = Round1Request.newBuilder().setTradeId(bobTradeId).build();
        Round1Response bobRound1Data = bobStub.executeRound1(bobRound1Req);
        System.out.println("Bob finished Round 1.");
        assertFalse(bobRound1Data.getDepPartPsbt().isEmpty(), "Bob's Round 1 PSBT is empty");


        // -- ROUND 2: Exchange Round 1 data and generate Round 2 data --
        Round2Request aliceRound2Req = Round2Request.newBuilder()
                .setTradeId(aliceTradeId)
                .setPeerRound1Response(bobRound1Data) // Alice gets Bob's R1 data
                .build();
        Round2Response aliceRound2Data = aliceStub.executeRound2(aliceRound2Req);
        System.out.println("Alice finished Round 2.");

        Round2Request bobRound2Req = Round2Request.newBuilder()
                .setTradeId(bobTradeId)
                .setPeerRound1Response(aliceRound1Data) // Bob gets Alice's R1 data
                .build();
        Round2Response bobRound2Data = bobStub.executeRound2(bobRound2Req);
        System.out.println("Bob finished Round 2.");
        assertFalse(bobRound2Data.getPAgg().isEmpty(), "Bob's Round 2 aggregated key is empty");


        // -- ROUND 3: Exchange Round 2 data and generate Round 3 data --
        Round3Request aliceRound3Req = Round3Request.newBuilder()
                .setTradeId(aliceTradeId)
                .setPeerRound2Response(bobRound2Data) // Alice gets Bob's R2 data
                .build();
        Round3Response aliceRound3Data = aliceStub.executeRound3(aliceRound3Req);
        System.out.println("Alice finished Round 3.");

        Round3Request bobRound3Req = Round3Request.newBuilder()
                .setTradeId(bobTradeId)
                .setPeerRound2Response(aliceRound2Data) // Bob gets Alice's R2 data
                .build();
        Round3Response bobRound3Data = bobStub.executeRound3(bobRound3Req);
        System.out.println("Bob finished Round 3.");

        // ** Important: Capture the Deposit TXID here. It will be verified at the end. **
        // Both should have the same TXID
        assertEquals(aliceRound3Data.getDepositTxid(), bobRound3Data.getDepositTxid());
        String depositTxid = getReversedTxId(aliceRound3Data.getDepositTxid());
        assertNotNull(depositTxid);
        assertFalse(depositTxid.isEmpty());
        System.out.println("Deposit Transaction ID calculated: " + depositTxid);


        // -- ROUND 4: Exchange Round 3 data and generate Round 4 data --
        Round4Request aliceRound4Req = Round4Request.newBuilder()
                .setTradeId(aliceTradeId)
                .setPeerRound3Response(bobRound3Data) // Alice gets Bob's R3 data
                .build();
        Round4Response aliceRound4Data = aliceStub.executeRound4(aliceRound4Req);
        System.out.println("Alice finished Round 4.");

        Round4Request bobRound4Req = Round4Request.newBuilder()
                .setTradeId(bobTradeId)
                .setPeerRound3Response(aliceRound3Data) // Bob gets Alice's R3 data
                .build();
        Round4Response bobRound4Data = bobStub.executeRound4(bobRound4Req);
        System.out.println("Bob finished Round 4.");
        assertFalse(bobRound4Data.getDepositTxSigned().isEmpty(), "Bob's Round 4 signed PSBT is empty");


        // -- ROUND 5: Exchange Round 4 data, finalize and broadcast --
        // This is the final step where the transaction is broadcasted.
        // Alice broadcasts.
        Round5Request aliceRound5Req = Round5Request.newBuilder()
                .setTradeId(aliceTradeId)
                .setPeerRound4Response(bobRound4Data) // Alice gets Bob's R4 data
                .build();
        aliceStub.executeRound5(aliceRound5Req);
        System.out.println("Alice finished Round 5. Transaction should be broadcast.");

        // Bob also finalizes his state.
        Round5Request bobRound5Req = Round5Request.newBuilder()
                .setTradeId(bobTradeId)
                .setPeerRound4Response(aliceRound4Data) // Bob gets Alice's R4 data
                .build();
        bobStub.executeRound5(bobRound5Req);
        System.out.println("Bob finished Round 5.");

        // === 3. Verify Transaction on Blockchain ===
        System.out.println("Verifying transaction on the blockchain...");

        // Give the network a moment to process the transaction, then mine a block.
        Thread.sleep(1000);
        nigiri.mineBlocks(1);
        System.out.println("Mined a block to confirm the transaction.");

        String rawTx = nigiri.getRawTransaction(depositTxid);
        assertNotNull(rawTx, "FAILURE: Transaction was NOT found on the blockchain!");
        assertFalse(rawTx.isEmpty(), "FAILURE: Transaction was NOT found on the blockchain!");

        System.out.println("\nSUCCESS: Deposit transaction " + depositTxid + " found on-chain!");
        System.out.println("Raw TX Hex: " + rawTx.substring(0, Math.min(80, rawTx.length())) + "...");
    }

    /**
     * Converts a protobuf ByteString containing a raw transaction hash into the standard
     * reversed-hex format used by Bitcoin explorers and RPC clients.
     *
     * @param txidBytes The ByteString from the gRPC response.
     * @return A string representing the transaction ID in reversed-hex format.
     */
    private String getReversedTxId(ByteString txidBytes) {
        byte[] bytes = txidBytes.toByteArray();
        // Reverse the byte array
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = temp;
        }
        // Convert to hex string
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
