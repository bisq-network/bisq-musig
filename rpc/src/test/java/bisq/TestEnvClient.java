package bisq;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bitcoin RPC client for TestEnv integration tests
 *
 * <p>Environment variables:
 * <ul>
 *   <li>{@code TESTENV_RPC_URL}
 *   <li>{@code TESTENV_RPC_USER}
 *   <li>{@code TESTENV_RPC_PASS}
 * </ul>
 */
public class TestEnvClient {
    private final HttpClient httpClient;
    private final String rpcUrl;
    private final String rpcUser;
    private final String rpcPass;

    public static TestEnvClient fromEnv() {
        // Load from properties file if available
        Properties props = loadTestEnvProperties();

        // Try system properties first (set by Maven via systemPropertyVariables)
        // Then fall back to loaded properties, then environment variables
        String rpcUrl = System.getProperty("bitcoinRpcUrl");
        if (rpcUrl == null && props != null) {
            rpcUrl = props.getProperty("bitcoinRpcUrl");
        }
        if (rpcUrl == null) {
            rpcUrl = System.getenv("TESTENV_RPC_URL");
        }
        if (rpcUrl == null) {
            rpcUrl = System.getenv("BITCOIN_RPC_URL");
        }

        String rpcUser = System.getProperty("bitcoinRpcUser");
        if (rpcUser == null && props != null) {
            rpcUser = props.getProperty("bitcoinRpcUser");
        }
        if (rpcUser == null) {
            rpcUser = System.getenv("TESTENV_RPC_USER");
        }
        if (rpcUser == null) {
            rpcUser = System.getenv("BITCOIN_RPC_USER");
        }
        if (rpcUser == null) {
            rpcUser = "bitcoin";
        }

        String rpcPass = System.getProperty("bitcoinRpcPass");
        if (rpcPass == null && props != null) {
            rpcPass = props.getProperty("bitcoinRpcPass");
        }
        if (rpcPass == null) {
            rpcPass = System.getenv("TESTENV_RPC_PASS");
        }
        if (rpcPass == null) {
            rpcPass = System.getenv("BITCOIN_RPC_PASS");
        }

        if (rpcUrl == null) {
            throw new RuntimeException("\n" +
                    "========== FAILED TO INITIALIZE RPC CLIENT ==========\n" +
                    "TESTENV_RPC_URL not found. Please provide RPC configuration via one of:\n\n" +
                    "1. Maven command-line properties:\n" +
                    "   mvn -DbitcoinRpcUrl=http://localhost:18332 " +
                    "-DbitcoinRpcUser=bitcoin -DbitcoinRpcPass=<password> -f rpc/pom.xml clean verify\n\n" +
                    "2. Environment variables:\n" +
                    "   export TESTENV_RPC_URL=http://localhost:18332\n" +
                    "   export TESTENV_RPC_USER=bitcoin\n" +
                    "   export TESTENV_RPC_PASS=<password>\n" +
                    "   mvn -f rpc/pom.xml clean verify\n\n" +
                    "3. Properties file at target/testenv.properties:\n" +
                    "   bitcoinRpcUrl=http://localhost:18332\n" +
                    "   bitcoinRpcUser=bitcoin\n" +
                    "   bitcoinRpcPass=<password>\n" +
                    "   mvn -f rpc/pom.xml clean verify\n\n" +
                    "Alternative env variable names: BITCOIN_RPC_URL, BITCOIN_RPC_USER, BITCOIN_RPC_PASS\n" +
                    "========================================================"
            );
        }

        if (rpcPass == null) {
            throw new RuntimeException("\n" +
                    "========== FAILED TO INITIALIZE RPC CLIENT ==========\n" +
                    "TESTENV_RPC_PASS not found. Please provide RPC password via one of:\n\n" +
                    "1. Maven command-line property:\n" +
                    "   mvn -DbitcoinRpcPass=<password> -f rpc/pom.xml clean verify\n\n" +
                    "2. Environment variables:\n" +
                    "   export TESTENV_RPC_PASS=<password>\n" +
                    "   mvn -f rpc/pom.xml clean verify\n\n" +
                    "   OR export BITCOIN_RPC_PASS=<password>\n\n" +
                    "3. Properties file at target/testenv.properties with property 'bitcoinRpcPass'\n" +
                    "========================================================"
            );
        }

        return new TestEnvClient(rpcUrl, rpcUser, rpcPass);
    }

    /**
     * Load TestEnv configuration from testenv.properties file if it exists
     */
    private static Properties loadTestEnvProperties() {
        try {
            // Try to load from target/testenv.properties
            Path propFile = Path.of("target/testenv.properties");
            if (Files.exists(propFile)) {
                Properties props = new Properties();
                props.load(Files.newInputStream(propFile));
                return props;
            }
        } catch (IOException e) {
            // File not found or unreadable, fall back to other sources
            System.err.println("Warning: Could not load testenv.properties: " + e.getMessage());
        }
        return null;
    }

    public TestEnvClient(String rpcUrl, String rpcUser, String rpcPass) {
        this.rpcUrl = rpcUrl;
        this.rpcUser = rpcUser;
        this.rpcPass = rpcPass;
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Generic RPC call
     */
    private String rpcCall(String method, String paramsJson) {
        try {
            String body = """
                    {
                      "jsonrpc":"1.0",
                      "id":"java",
                      "method":"%s",
                      "params":%s
                    }
                    """.formatted(method, paramsJson);

            String auth = Base64.getEncoder()
                    .encodeToString((rpcUser + ":" + rpcPass).getBytes());

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(rpcUrl))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Basic " + auth)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            return response.body();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("RPC call failed", e);
        }
    }

    /**
     * Mine blocks on regtest
     */
    public void mineBlocks(int count) {
        String address = getNewAddress();
        rpcCall("generatetoaddress", "[" + count + ",\"" + address + "\"]");
    }

    /**
     * Fund an address
     */
    public String fundAddress(String address, double amount) {
        String result = rpcCall("sendtoaddress", "[\"" + address + "\"," + amount + "]");
        return extractResult(result);
    }

    /**
     * Get raw transaction hex
     */
    public String getRawTransaction(String txid) {
        String result = rpcCall("getrawtransaction", "[\"" + txid + "\"]");
        return extractResult(result);
    }

    /**
     * Get current block height
     */
    public int getBlockCount() {
        String result = rpcCall("getblockcount", "[]");
        return Integer.parseInt(extractResult(result));
    }

    /**
     * Get wallet balance
     */
    public double getBalance() {
        String result = rpcCall("getbalance", "[]");
        return Double.parseDouble(extractResult(result));
    }

    /**
     * Generate a new address
     */
    public String getNewAddress() {
        String result = rpcCall("getnewaddress", "[]");
        return extractResult(result);
    }

    /**
     * Wait for transaction
     */
    public boolean waitForTransaction(String txid) {
        final long TIMEOUT_MS = 30_000;
        final long CHECK_INTERVAL_MS = 500;

        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < TIMEOUT_MS) {
            try {
                String tx = getRawTransaction(txid);
                if (tx != null && !tx.isBlank()) {
                    return true;
                }
            } catch (RuntimeException ignored) {
            }

            try {
                //noinspection BusyWait
                Thread.sleep(CHECK_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /**
     * Extract "result" field from JSON
     */
    private String extractResult(String json) {
        Pattern pattern = Pattern.compile("\"result\"\\s*:\\s*(\"([^\"]*)\"|[0-9.]+)");
        Matcher matcher = pattern.matcher(json);

        if (matcher.find()) {
            String full = matcher.group(1);
            if (full.startsWith("\"")) {
                return matcher.group(2);
            }
            return full;
        }
        throw new RuntimeException("Invalid RPC response: " + json);
    }

    @Override
    public String toString() {
        return "TestEnvClient{rpcUrl='" + rpcUrl + "', rpcUser='" + rpcUser + "'}";
    }
}
