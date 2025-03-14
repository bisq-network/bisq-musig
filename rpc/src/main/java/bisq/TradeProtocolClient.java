package bisq;

import com.google.common.collect.ImmutableMap;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import musigrpc.MusigGrpc;
import musigrpc.Rpc.*;

import java.util.List;
import java.util.stream.Collectors;

public class TradeProtocolClient {
    public static void main(String[] args) {
        var channel = Grpc.newChannelBuilderForAddress(
                "127.0.0.1",
                50051,
                InsecureChannelCredentials.create()
        ).build();

        var musigStub = MusigGrpc.newBlockingStub(channel);
        testMusigService_twoParties(musigStub, 0, ClosureType.COOPERATIVE);
        testMusigService_twoParties(musigStub, 1, ClosureType.UNCOOPERATIVE);

        channel.shutdown();
    }

    /**
     * Clean (unmediated) closure types.
     **/
    private enum ClosureType {
        COOPERATIVE, UNCOOPERATIVE
    }

    private static void testMusigService_twoParties(MusigGrpc.MusigBlockingStub stub,
                                                    int tradeNum,
                                                    ClosureType closureType) {
        // Two peers, buyer-as-taker & seller-as-maker, talk to their respective Rust servers via
        // gRPC, simulated here as two sessions (trade IDs) with the same test server.
        //
        // Communication with the gRPC server is interspersed with messages exchanged between the
        // peers. These are the messages A-G defined in $SRC_ROOT/musig_trade_protocol_messages.txt,
        // with messages A-D used to set up the trade. The Java client is (for the most part) just
        // forwarding on fields that were received in the last one or two gRPC responses.

        String buyerTradeId = "buyer-trade-" + tradeNum;
        String sellerTradeId = "seller-trade-" + tradeNum;

        var buyerPubKeyShareResponse = stub.initTrade(PubKeySharesRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setMyRole(Role.BUYER_AS_TAKER)
                .build());
        System.out.println("Got reply: " + buyerPubKeyShareResponse);

        // Buyer sends Message A to seller.

        var sellerPubKeyShareResponse = stub.initTrade(PubKeySharesRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .setMyRole(Role.SELLER_AS_MAKER)
                .build());
        System.out.println("Got reply: " + sellerPubKeyShareResponse);

        var sellerNonceShareMessage = stub.getNonceShares(NonceSharesRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .setBuyerOutputPeersPubKeyShare(buyerPubKeyShareResponse.getBuyerOutputPubKeyShare())
                .setSellerOutputPeersPubKeyShare(buyerPubKeyShareResponse.getSellerOutputPubKeyShare())
                .setDepositTxFeeRate(50_000)  // 12.5 sats per vbyte
                .setPreparedTxFeeRate(40_000) // 10.0 sats per vbyte
                .setTradeAmount(200_000)
                .setBuyersSecurityDeposit(30_000)
                .setSellersSecurityDeposit(30_000)
                .build());
        System.out.println("Got reply: " + sellerNonceShareMessage);

        // Seller sends Message B to buyer.

        var buyerNonceShareMessage = stub.getNonceShares(NonceSharesRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setBuyerOutputPeersPubKeyShare(sellerPubKeyShareResponse.getBuyerOutputPubKeyShare())
                .setSellerOutputPeersPubKeyShare(sellerPubKeyShareResponse.getSellerOutputPubKeyShare())
                .setDepositTxFeeRate(50_000)  // 12.5 sats per vbyte
                .setPreparedTxFeeRate(40_000) // 10.0 sats per vbyte
                .setTradeAmount(200_000)
                .setBuyersSecurityDeposit(30_000)
                .setSellersSecurityDeposit(30_000)
                .build());
        System.out.println("Got reply: " + buyerNonceShareMessage);

        var buyerPartialSignatureMessage = stub.getPartialSignatures(PartialSignaturesRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setPeersNonceShares(sellerNonceShareMessage)
                .addAllReceivers(mockReceivers())
                .build());
        System.out.println("Got reply: " + buyerPartialSignatureMessage);

        // Buyer sends Message C to seller.

        var sellerPartialSignatureMessage = stub.getPartialSignatures(PartialSignaturesRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .setPeersNonceShares(buyerNonceShareMessage)
                .addAllReceivers(mockReceivers())
                .build());
        System.out.println("Got reply: " + sellerPartialSignatureMessage);

        var sellerDepositPsbt = stub.signDepositTx(DepositTxSignatureRequest.newBuilder()
                .setTradeId(sellerTradeId)
                // REDACT buyer's swapTxInputPartialSignature:
                .setPeersPartialSignatures(buyerPartialSignatureMessage.toBuilder().clearSwapTxInputPartialSignature())
                .build());
        System.out.println("Got reply: " + sellerDepositPsbt);

        // Seller sends Message D to buyer.

        var buyerDepositPsbt = stub.signDepositTx(DepositTxSignatureRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setPeersPartialSignatures(sellerPartialSignatureMessage)
                .build());
        System.out.println("Got reply: " + buyerDepositPsbt);

        // *** BUYER BROADCASTS DEPOSIT TX ***
        var depositTxConfirmationIter = stub.publishDepositTx(PublishDepositTxRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .build());
        depositTxConfirmationIter.forEachRemaining(reply -> System.out.println("Got reply: " + reply));
        // ***********************************

        // Buyer sends Message E to seller.

        var swapTxSignatureResponse = stub.signSwapTx(SwapTxSignatureRequest.newBuilder()
                .setTradeId(sellerTradeId)
                // NOW send the redacted buyer's swapTxInputPartialSignature:
                .setSwapTxInputPeersPartialSignature(buyerPartialSignatureMessage.getSwapTxInputPartialSignature())
                .build());
        System.out.println("Got reply: " + swapTxSignatureResponse);

        if (closureType == ClosureType.COOPERATIVE) {
            // Seller sends Message F to buyer.

            // *** BUYER CLOSES TRADE ***
            var buyersCloseTradeResponse = stub.closeTrade(CloseTradeRequest.newBuilder()
                    .setTradeId(buyerTradeId)
                    .setMyOutputPeersPrvKeyShare(swapTxSignatureResponse.getPeerOutputPrvKeyShare())
                    .build());
            System.out.println("Got reply: " + buyersCloseTradeResponse);
            // **************************

            // Buyer sends Message G to seller.

            // *** SELLER CLOSES TRADE ***
            var sellersCloseTradeResponse = stub.closeTrade(CloseTradeRequest.newBuilder()
                    .setTradeId(sellerTradeId)
                    .setMyOutputPeersPrvKeyShare(buyersCloseTradeResponse.getPeerOutputPrvKeyShare())
                    .build());
            System.out.println("Got reply: " + sellersCloseTradeResponse);
            // ***************************
        } else if (closureType == ClosureType.UNCOOPERATIVE) {
            // Seller attempts to send Message F to buyer, then waits...

            // Seller never gets expected Message G from buyer -- gives up waiting.

            // *** SELLER FORCE-CLOSES TRADE ***
            var sellersCloseTradeResponse = stub.closeTrade(CloseTradeRequest.newBuilder()
                    .setTradeId(sellerTradeId)
                    .build());
            System.out.println("Got reply: " + sellersCloseTradeResponse);
            // *********************************

            // Buyer never got Message F from seller -- picks up Swap Tx from bitcoin network instead.

            // *** BUYER CLOSES TRADE ***
            var buyersCloseTradeResponse = stub.closeTrade(CloseTradeRequest.newBuilder()
                    .setTradeId(buyerTradeId)
                    .setSwapTx(swapTxSignatureResponse.getSwapTx())
                    .build());
            System.out.println("Got reply: " + buyersCloseTradeResponse);
            // **************************
        }
    }

    @SuppressWarnings("SpellCheckingInspection")
    private static List<ReceiverAddressAndAmount> mockReceivers() {
        return ImmutableMap.of(
                        "tb1pwxlp4v9v7v03nx0e7vunlc87d4936wnyqegw0fuahudypan64wys5stxh7", 200_000,
                        "tb1qpg889v22f3gefuvwpe3963t5a00nvfmkhlgqw5", 80_000,
                        "2N2x2bA28AsLZZEHss4SjFoyToQV5YYZsJM", 12_345
                )
                .entrySet().stream()
                .map(e -> ReceiverAddressAndAmount.newBuilder().setAddress(e.getKey()).setAmount(e.getValue()).build())
                .collect(Collectors.toList());
    }
}
