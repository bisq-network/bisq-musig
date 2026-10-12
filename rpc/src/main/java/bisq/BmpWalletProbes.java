package bisq;

import bisq.wallet.protobuf.OpenOrCreateWalletRequest;
import bisq.wallet.protobuf.WalletGrpc;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

/** Probes shared by the {@code wallet.Wallet} test clients. */
final class BmpWalletProbes {
    private BmpWalletProbes() {
    }

    /**
     * Whether {@code password} is the one currently protecting the wallet, probed by re-opening
     * the (already open) wallet with it.
     * <p>
     * Only meaningful once the wallet is open: with no wallet on disk, {@code OpenOrCreateWallet}
     * would create one protected by {@code password} instead of answering the question.
     */
    static boolean opensWith(WalletGrpc.WalletBlockingStub stub, String password) {
        try {
            return stub.openOrCreateWallet(OpenOrCreateWalletRequest.newBuilder()
                    .setPassword(password)
                    .build()).getSuccess();
        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.PERMISSION_DENIED) {
                return false;
            }
            throw e;
        }
    }
}
