package bisq;

import bisq.wallet.protobuf.ChangePasswordRequest;
import bisq.wallet.protobuf.GetBalanceRequest;
import bisq.wallet.protobuf.GetSeedWordsRequest;
import bisq.wallet.protobuf.GetNewAddressRequest;
import bisq.wallet.protobuf.GetUnusedAddressRequest;
import bisq.wallet.protobuf.GetWalletAddressesRequest;
import bisq.wallet.protobuf.IsWalletEncryptedRequest;
import bisq.wallet.protobuf.IsWalletReadyRequest;
import bisq.wallet.protobuf.ListTransactionsRequest;
import bisq.wallet.protobuf.ListUtxosRequest;
import bisq.wallet.protobuf.OpenOrCreateWalletRequest;
import bisq.wallet.protobuf.SendToAddressRequest;
import bisq.wallet.protobuf.Transaction;
import bisq.wallet.protobuf.Utxo;
import bisq.wallet.protobuf.WalletGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Exercises every RPC of the {@code wallet.Wallet} service that musigd serves from
 * {@code BMPWalletServiceImpl}, i.e. every method bisq2's {@code bisq.wallet.WalletService}
 * calls through its {@code WalletGrpcClient}.
 * <p>
 * The generated stubs used here come from {@code src/main/proto/bmp_wallet.proto}, which is a
 * copy of bisq2's own {@code wallet.proto} — same package, service, methods and field numbers —
 * so passing this test means bisq2 can point its {@code WalletGrpcClient} at musigd unchanged.
 * <p>
 * Run against a musigd started with a wallet directory, e.g.
 * <pre>
 *   cargo run --bin musigd -- --port 50051 --wallet-dir /tmp/bmp-wallet
 *   mvn -f rpc/pom.xml -P bmp-wallet compile exec:java
 * </pre>
 * Host/port can be overridden with {@code -Dwallet.host=... -Dwallet.port=...}.
 * <p>
 * The wallet itself is opened (or created) through the {@code OpenOrCreateWallet} RPC as the
 * first check — musigd takes no wallet password on its command line — and is expected to be
 * password-free, as the password checks restore that state on the way out.
 */
public class BmpWalletServiceTest {
    private static final String TEST_PASSWORD = "bmp-wallet-service-test";
    /** A regtest P2WPKH address; only ever used as a send target that is expected to fail. */
    private static final String REGTEST_ADDRESS = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    private final WalletGrpc.WalletBlockingStub stub;
    private final List<String> failures = new ArrayList<>();
    private int passed;

    private BmpWalletServiceTest(WalletGrpc.WalletBlockingStub stub) {
        this.stub = stub;
    }

    public static void main(String[] args) {
        String host = System.getProperty("wallet.host", "127.0.0.1");
        int port = Integer.getInteger("wallet.port", 50051);

        System.out.printf("Connecting to the wallet service at %s:%d...%n", host, port);
        ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port).usePlaintext().build();
        try {
            BmpWalletServiceTest test =
                    new BmpWalletServiceTest(WalletGrpc.newBlockingStub(channel));
            test.runAll();
            System.exit(test.report());
        } finally {
            channel.shutdown();
            try {
                channel.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void runAll() {
        // The wallet must be opened before anything else works.
        check("OpenOrCreateWallet", this::openOrCreateWallet);
        // Read-only probes first, so a failure here doesn't leave the wallet half-reconfigured.
        check("IsWalletReady", this::isWalletReady);
        check("GetBalance", this::getBalance);
        check("GetSeedWords", this::getSeedWords);
        check("GetNewAddress + GetUnusedAddress + GetWalletAddresses", this::addresses);
        check("ListTransactions", this::listTransactions);
        check("ListUtxos", this::listUtxos);
        check("SendToAddress", this::sendToAddress);
        // Mutating, and restores the original state on the way out.
        check("IsWalletEncrypted + ChangePassword", this::changePasswordRoundTrip);
    }

    // --- individual checks -------------------------------------------------------------------

    private void openOrCreateWallet() {
        // An empty password: the smoke test expects (and leaves behind) an unprotected wallet.
        boolean success = stub.openOrCreateWallet(
                OpenOrCreateWalletRequest.newBuilder().build()).getSuccess();
        assertTrue(success, "OpenOrCreateWallet must report success");
        System.out.println("    wallet opened (or created)");
    }

    private void isWalletReady() {
        // Either answer is legitimate — an unsynced wallet reports false — but the call itself
        // must succeed, which is what proves the method is wired to BMPWalletServiceImpl.
        boolean ready = stub.isWalletReady(IsWalletReadyRequest.newBuilder().build()).getReady();
        System.out.println("    ready=" + ready);
    }

    private void getBalance() {
        var response = stub.getBalance(GetBalanceRequest.newBuilder().build());
        long parts = response.getConfirmed() + response.getTrustedPending()
                + response.getUntrustedPending() + response.getImmature();
        assertTrue(response.getBalance() >= 0, "balance must not be negative");
        assertTrue(parts >= response.getBalance(),
                "breakdown (" + parts + ") must cover the spendable total (" + response.getBalance() + ")");
        System.out.printf("    balance=%d confirmed=%d trustedPending=%d untrustedPending=%d immature=%d%n",
                response.getBalance(), response.getConfirmed(), response.getTrustedPending(),
                response.getUntrustedPending(), response.getImmature());
    }

    private void getSeedWords() {
        List<String> words =
                stub.getSeedWords(GetSeedWordsRequest.newBuilder().build()).getSeedWordsList();
        assertTrue(words.size() == 12 || words.size() == 24,
                "expected a 12- or 24-word mnemonic, got " + words.size());
        words.forEach(word -> assertTrue(!word.isBlank(), "seed word must not be blank"));
        // Deliberately not printed — this is the wallet's private key material.
        System.out.println("    got a " + words.size() + "-word mnemonic");
    }

    private void addresses() {
        String address =
                stub.getUnusedAddress(GetUnusedAddressRequest.newBuilder().build()).getAddress();
        assertTrue(!address.isBlank(), "address must not be blank");

        String fresh = stub.getNewAddress(GetNewAddressRequest.newBuilder().build()).getAddress();
        assertTrue(!fresh.isBlank(), "new address must not be blank");
        assertTrue(!fresh.equals(address), "GetNewAddress must not repeat the last address");

        List<String> all = stub.getWalletAddresses(GetWalletAddressesRequest.newBuilder().build())
                .getAddressesList();
        assertTrue(all.contains(address),
                "a revealed address (" + address + ") must appear among the wallet's addresses");
        assertTrue(all.contains(fresh),
                "a new address (" + fresh + ") must appear among the wallet's addresses");
        System.out.printf("    unused=%s, new=%s, %d address(es) revealed%n", address, fresh, all.size());
    }

    private void listTransactions() {
        List<Transaction> txs =
                stub.listTransactions(ListTransactionsRequest.newBuilder().build())
                        .getTransactionsList();
        for (Transaction tx : txs) {
            assertTrue(!tx.getTxId().isBlank(), "txId must be set");
            assertTrue(tx.getOutputsCount() > 0, "a transaction must have outputs");
            // bisq2 decodes this with Instant.ofEpochSecond, so a millisecond value would land
            // ~50000 years in the future. Guard against that class of mistake.
            assertTrue(tx.getDate() < 4_000_000_000L,
                    "date must be in seconds, got " + tx.getDate());
        }
        System.out.println("    " + txs.size() + " transaction(s)");
    }

    private void listUtxos() {
        List<Utxo> utxos = stub.listUtxos(ListUtxosRequest.newBuilder().build()).getUtxosList();
        for (Utxo utxo : utxos) {
            assertTrue(!utxo.getTxId().isBlank(), "txId must be set");
            assertTrue(utxo.getAmount() > 0, "a UTXO must carry a positive amount");
        }
        System.out.println("    " + utxos.size() + " UTXO(s)");
    }

    private void sendToAddress() {
        var request = SendToAddressRequest.newBuilder()
                .setAddress(REGTEST_ADDRESS)
                .setAmount(10_000)
                .build();
        try {
            String txId = stub.sendToAddress(request).getTxId();
            assertTrue(!txId.isBlank(), "txId must be set when the send succeeds");
            System.out.println("    broadcast txId=" + txId);
        } catch (StatusRuntimeException e) {
            // A fresh regtest wallet has no coins, and musigd may have been started without a
            // broadcaster, so failure is the norm here. What matters is that the method is
            // implemented and reached the wallet — UNIMPLEMENTED would mean it never did.
            assertTrue(e.getStatus().getCode() != Status.Code.UNIMPLEMENTED,
                    "SendToAddress is not wired up");
            System.out.println("    declined as expected: " + e.getStatus().getCode()
                    + " - " + e.getStatus().getDescription());
        }
    }

    private void changePasswordRoundTrip() {
        boolean encryptedBefore = isEncrypted();
        assertTrue(!encryptedBefore,
                "expected an unencrypted wallet to start from; refusing to re-key one that "
                        + "already has a password");

        // Setting a password is a change from the empty password.
        stub.changePassword(ChangePasswordRequest.newBuilder()
                .setNewPassword(TEST_PASSWORD)
                .build());
        assertTrue(isEncrypted(), "wallet must report itself encrypted after ChangePassword");

        // The seed must still be readable through the rotated SQLCipher key.
        assertTrue(!stub.getSeedWords(GetSeedWordsRequest.newBuilder().build())
                .getSeedWordsList().isEmpty(), "seed unreadable after re-keying");

        try {
            stub.changePassword(ChangePasswordRequest.newBuilder()
                    .setOldPassword("definitely-wrong")
                    .setNewPassword("irrelevant")
                    .build());
            fail("ChangePassword accepted a wrong old password");
        } catch (StatusRuntimeException e) {
            assertTrue(e.getStatus().getCode() == Status.Code.PERMISSION_DENIED,
                    "expected PERMISSION_DENIED for a wrong password, got " + e.getStatus().getCode());
        }
        assertTrue(isEncrypted(), "a rejected ChangePassword must leave the wallet encrypted");

        // An empty new password removes protection, restoring the original state.
        stub.changePassword(ChangePasswordRequest.newBuilder()
                .setOldPassword(TEST_PASSWORD)
                .build());
        assertTrue(!isEncrypted(), "wallet must report itself unencrypted after the password "
                + "was removed");
        System.out.println("    set password -> reject wrong password -> remove password ok");
    }

    private boolean isEncrypted() {
        return stub.isWalletEncrypted(IsWalletEncryptedRequest.newBuilder().build()).getEncrypted();
    }

    // --- tiny test harness -------------------------------------------------------------------

    private void check(String name, Runnable body) {
        System.out.println("- " + name);
        try {
            body.run();
            passed++;
        } catch (AssertionError | StatusRuntimeException e) {
            System.out.println("    FAILED: " + e);
            failures.add(name + ": " + e.getMessage());
        }
    }

    private int report() {
        System.out.println();
        System.out.printf("%d check(s) passed, %d failed.%n", passed, failures.size());
        failures.forEach(failure -> System.out.println("  FAILED " + failure));
        return failures.isEmpty() ? 0 : 1;
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void fail(String message) {
        throw new AssertionError(message);
    }
}
