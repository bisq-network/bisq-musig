package bisq;

import com.google.common.collect.ImmutableMap;
import com.google.protobuf.ByteString;
import io.grpc.Channel;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import musigrpc.MusigGrpc;
import musigrpc.Rpc.*;

import java.util.List;
import java.util.stream.Collectors;

public class TradeProtocolClient {
    private final MusigGrpc.MusigBlockingStub stub;

    public TradeProtocolClient(Channel channel) {
        this.stub = MusigGrpc.newBlockingStub(channel);
    }

    public static void main(String[] args) {
        var channel = Grpc.newChannelBuilderForAddress(
                "127.0.0.1",
                50051,
                InsecureChannelCredentials.create()
        ).build();

        try {
            var client = new TradeProtocolClient(channel);
            client.testMusigService_twoParties(0, TradeType.TAKER_IS_BUYER, ClosureType.COOPERATIVE);
            client.testMusigService_twoParties(1, TradeType.TAKER_IS_BUYER, ClosureType.UNCOOPERATIVE);
            client.testMusigService_twoParties(2, TradeType.TAKER_IS_SELLER, ClosureType.COOPERATIVE);
            client.testMusigService_twoParties(3, TradeType.TAKER_IS_SELLER, ClosureType.UNCOOPERATIVE);
        } finally {
            channel.shutdown();
        }
    }

    private enum TradeType {
        TAKER_IS_BUYER, TAKER_IS_SELLER
    }

    /**
     * Clean (unmediated) closure types.
     **/
    private enum ClosureType {
        COOPERATIVE, UNCOOPERATIVE
    }

    private void testMusigService_twoParties(int tradeNum, TradeType tradeType, ClosureType closureType) {
        // Two peers, buyer & seller (one taker, one maker), talk to their respective Rust servers
        // via gRPC, simulated here as two sessions (trade IDs) with the same test server.
        //
        // Communication with the gRPC server is interspersed with messages exchanged between the
        // peers. These are the messages A-G defined in $SRC_ROOT/musig_trade_protocol_messages.txt,
        // with messages A-D used to set up the trade. The Java client is (for the most part) just
        // forwarding on fields that were received in the last one or two gRPC responses.

        String buyerTradeId = "buyer-trade-" + tradeNum;
        String sellerTradeId = "seller-trade-" + tradeNum;

        ByteString swapTxInputBuyerPartialSignature = switch (tradeType) {
            case TAKER_IS_BUYER -> setupTakerIsBuyerTrade(buyerTradeId, sellerTradeId);
            case TAKER_IS_SELLER -> setupTakerIsSellerTrade(buyerTradeId, sellerTradeId);
        };

        doRestOfTrade(buyerTradeId, sellerTradeId, swapTxInputBuyerPartialSignature, closureType);
    }

    private ByteString setupTakerIsBuyerTrade(String buyerTradeId, String sellerTradeId) {
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

        // Buyer sends Message C to seller. (Buyer's swapTxInputPartialSignature is withheld from it.)

        var sellerPartialSignatureMessage = stub.getPartialSignatures(PartialSignaturesRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .setPeersNonceShares(buyerNonceShareMessage)
                .addAllReceivers(mockReceivers())
                .build());
        System.out.println("Got reply: " + sellerPartialSignatureMessage);

        var sellerDepositPsbt = stub.signDepositTx(DepositTxSignatureRequest.newBuilder()
                .setTradeId(sellerTradeId)
                // REDACT buyer's swapTxInputPartialSignature (as not yet known by seller):
                .setPeersPartialSignatures(buyerPartialSignatureMessage.toBuilder().clearSwapTxInputPartialSignature())
                .build());
        System.out.println("Got reply: " + sellerDepositPsbt);

        // Seller subscribes to be notified of Deposit Tx confirmation:
        var sellerDepositTxConfirmationIter = stub.subscribeTxConfirmationStatus(SubscribeTxConfirmationStatusRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .build());

        // Seller sends Message D to buyer. (Seller's swapTxInputPartialSignature is NOT withheld from it.)

        var buyerDepositPsbt = stub.signDepositTx(DepositTxSignatureRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setPeersPartialSignatures(sellerPartialSignatureMessage)
                .build());
        System.out.println("Got reply: " + buyerDepositPsbt);

        // *** BUYER BROADCASTS DEPOSIT TX ***
        var buyerDepositTxConfirmationIter = stub.publishDepositTx(PublishDepositTxRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .build());
        // ***********************************

        // DELAY: Both traders await Deposit Tx confirmation:
        buyerDepositTxConfirmationIter.forEachRemaining(reply -> System.out.println("Got reply: " + reply));
        sellerDepositTxConfirmationIter.forEachRemaining(reply -> System.out.println("Got reply: " + reply));

        return buyerPartialSignatureMessage.getSwapTxInputPartialSignature();
    }

    private ByteString setupTakerIsSellerTrade(String buyerTradeId, String sellerTradeId) {
        var sellerPubKeyShareResponse = stub.initTrade(PubKeySharesRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .setMyRole(Role.SELLER_AS_TAKER)
                .build());
        System.out.println("Got reply: " + sellerPubKeyShareResponse);

        // Seller sends Message A to buyer.

        var buyerPubKeyShareResponse = stub.initTrade(PubKeySharesRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setMyRole(Role.BUYER_AS_MAKER)
                .build());
        System.out.println("Got reply: " + buyerPubKeyShareResponse);

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

        // Buyer sends Message B to seller.

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

        var sellerPartialSignatureMessage = stub.getPartialSignatures(PartialSignaturesRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .setPeersNonceShares(buyerNonceShareMessage)
                .addAllReceivers(mockReceivers())
                .build());
        System.out.println("Got reply: " + sellerPartialSignatureMessage);

        // Seller sends Message C to buyer. (Seller's swapTxInputPartialSignature is NOT withheld from it.)

        var buyerPartialSignatureMessage = stub.getPartialSignatures(PartialSignaturesRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setPeersNonceShares(sellerNonceShareMessage)
                .addAllReceivers(mockReceivers())
                .build());
        System.out.println("Got reply: " + buyerPartialSignatureMessage);

        var buyerDepositPsbt = stub.signDepositTx(DepositTxSignatureRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .setPeersPartialSignatures(sellerPartialSignatureMessage)
                .build());
        System.out.println("Got reply: " + buyerDepositPsbt);

        // Buyer subscribes to be notified of Deposit Tx confirmation:
        var buyerDepositTxConfirmationIter = stub.subscribeTxConfirmationStatus(SubscribeTxConfirmationStatusRequest.newBuilder()
                .setTradeId(buyerTradeId)
                .build());

        // Buyer sends Message D to seller. (Buyer's swapTxInputPartialSignature is withheld from it.)

        var sellerDepositPsbt = stub.signDepositTx(DepositTxSignatureRequest.newBuilder()
                .setTradeId(sellerTradeId)
                // REDACT buyer's swapTxInputPartialSignature (as not yet known by seller):
                .setPeersPartialSignatures(buyerPartialSignatureMessage.toBuilder().clearSwapTxInputPartialSignature())
                .build());
        System.out.println("Got reply: " + sellerDepositPsbt);

        // *** SELLER BROADCASTS DEPOSIT TX ***
        var sellerDepositTxConfirmationIter = stub.publishDepositTx(PublishDepositTxRequest.newBuilder()
                .setTradeId(sellerTradeId)
                .build());
        // ***********************************

        // DELAY: Both traders await Deposit Tx confirmation:
        buyerDepositTxConfirmationIter.forEachRemaining(reply -> System.out.println("Got reply: " + reply));
        sellerDepositTxConfirmationIter.forEachRemaining(reply -> System.out.println("Got reply: " + reply));

        return buyerPartialSignatureMessage.getSwapTxInputPartialSignature();
    }

    private void doRestOfTrade(String buyerTradeId, String sellerTradeId, ByteString swapTxInputBuyerPartialSignature, ClosureType closureType) {
        // DELAY: Buyer makes fiat payment.

        // Buyer sends Message E to seller. (Includes previously withheld buyer's swapTxInputPartialSignature.)

        // (Seller should compute Swap Tx signature immediately upon receipt of Message E, instead of waiting until the
        // end of the trade, to make sure that there's no problem with it and raise a dispute ASAP otherwise.)
        var swapTxSignatureResponse = stub.signSwapTx(SwapTxSignatureRequest.newBuilder()
                .setTradeId(sellerTradeId)
                // NOW send the redacted buyer's swapTxInputPartialSignature:
                .setSwapTxInputPeersPartialSignature(swapTxInputBuyerPartialSignature)
                .build());
        System.out.println("Got reply: " + swapTxSignatureResponse);

        // DELAY: Seller checks buyer's fiat payment.

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
