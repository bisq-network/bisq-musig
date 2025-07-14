package bisq;

import bmp_protocol.BmpProtocol.InitializeRequest;
import bmp_protocol.BmpProtocol.InitializeResponse;
import bmp_protocol.BmpProtocol.Role;
import bmp_protocol.BmpProtocol.Round1Request;
import bmp_protocol.BmpProtocol.Round1Response;
import bmp_protocol.BmpProtocol.Round2Request;
import bmp_protocol.BmpProtocol.Round2Response;
import bmp_protocol.BmpProtocol.Round3Request;
import bmp_protocol.BmpProtocol.Round3Response;
import bmp_protocol.BmpProtocol.Round4Request;
import bmp_protocol.BmpProtocol.Round4Response;
import bmp_protocol.BmpProtocol.Round5Request;
import bmp_protocol.BmpProtocolServiceGrpc;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class BmpClient {

    public static void main(String[] args) throws InterruptedException {
        System.out.println("Waiting for gRPC server to start...");
        Thread.sleep(1000); // 1-second delay

        System.out.println("Connecting to gRPC server...");
        ManagedChannel channel =
                ManagedChannelBuilder.forAddress("localhost", 50051).usePlaintext().build();
        BmpProtocolServiceGrpc.BmpProtocolServiceBlockingStub client =
                BmpProtocolServiceGrpc.newBlockingStub(channel);

        try {
        } finally {
            System.out.println("Shutting down channel.");
            channel.shutdown();
        }
    }

    private static void runBmpProtocolTest(
            BmpProtocolServiceGrpc.BmpProtocolServiceBlockingStub client) {
        System.out.println("Initializing seller and buyer...");
        // Initialize the seller and buyer
        InitializeResponse sellerInitResponse =
                client.initialize(
                        InitializeRequest.newBuilder()
                                .setTradeId("mock_trade_id_1")
                                .setRole(Role.SELLER)
                                .setSellerAmountSats(10000)
                                .setBuyerAmountSats(5000)
                                .build());
        String sellerTradeId = sellerInitResponse.getTradeId();
        System.out.println("Seller initialized with trade ID: " + sellerTradeId);

        InitializeResponse buyerInitResponse =
                client.initialize(
                        InitializeRequest.newBuilder()
                                .setTradeId("mock_trade_id_2")
                                .setRole(Role.BUYER)
                                .setSellerAmountSats(10000)
                                .setBuyerAmountSats(5000)
                                .build());
        String buyerTradeId = buyerInitResponse.getTradeId();
        System.out.println("Buyer initialized with trade ID: " + buyerTradeId);

        // Round 1
        System.out.println("\n--- Executing Round 1 ---");
        Round1Response sellerRound1Response =
                client.executeRound1(Round1Request.newBuilder().setTradeId(sellerTradeId).build());
        System.out.println("Seller Round 1 Response: " + sellerRound1Response);
        Round1Response buyerRound1Response =
                client.executeRound1(Round1Request.newBuilder().setTradeId(buyerTradeId).build());
        System.out.println("Buyer Round 1 Response: " + buyerRound1Response);

        // Round 2
        System.out.println("\n--- Executing Round 2 ---");
        Round2Response sellerRound2Response =
                client.executeRound2(
                        Round2Request.newBuilder()
                                .setTradeId(sellerTradeId)
                                .setPeerRound1Response(buyerRound1Response)
                                .build());
        System.out.println("Seller Round 2 Response: " + sellerRound2Response);
        Round2Response buyerRound2Response =
                client.executeRound2(
                        Round2Request.newBuilder()
                                .setTradeId(buyerTradeId)
                                .setPeerRound1Response(sellerRound1Response)
                                .build());
        System.out.println("Buyer Round 2 Response: " + buyerRound2Response);

        // Round 3
        System.out.println("\n--- Executing Round 3 ---");
        Round3Response sellerRound3Response =
                client.executeRound3(
                        Round3Request.newBuilder()
                                .setTradeId(sellerTradeId)
                                .setPeerRound2Response(buyerRound2Response)
                                .build());
        System.out.println("Seller Round 3 Response: " + sellerRound3Response);
        Round3Response buyerRound3Response =
                client.executeRound3(
                        Round3Request.newBuilder()
                                .setTradeId(buyerTradeId)
                                .setPeerRound2Response(sellerRound2Response)
                                .build());
        System.out.println("Buyer Round 3 Response: " + buyerRound3Response);

        // Round 4
        System.out.println("\n--- Executing Round 4 ---");
        Round4Response sellerRound4Response =
                client.executeRound4(
                        Round4Request.newBuilder()
                                .setTradeId(sellerTradeId)
                                .setPeerRound3Response(buyerRound3Response)
                                .build());
        System.out.println("Seller Round 4 Response: " + sellerRound4Response);
        Round4Response buyerRound4Response =
                client.executeRound4(
                        Round4Request.newBuilder()
                                .setTradeId(buyerTradeId)
                                .setPeerRound3Response(sellerRound3Response)
                                .build());
        System.out.println("Buyer Round 4 Response: " + buyerRound4Response);

        // Round 5
        System.out.println("\n--- Executing Round 5 ---");
        client.executeRound5(
                Round5Request.newBuilder()
                        .setTradeId(sellerTradeId)
                        .setPeerRound4Response(buyerRound4Response)
                        .build());
        System.out.println("Seller Round 5 executed.");
        client.executeRound5(
                Round5Request.newBuilder()
                        .setTradeId(buyerTradeId)
                        .setPeerRound4Response(sellerRound4Response)
                        .build());
        System.out.println("Buyer Round 5 executed.");

        System.out.println("\nBMP protocol executed successfully!");
    }
}
