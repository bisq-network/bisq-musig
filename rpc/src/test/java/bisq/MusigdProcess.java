package bisq;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Starts and stops a {@code musigd} process with a throwaway BMP wallet, for integration tests
 * that need a real wallet backed by a real chain.
 *
 * <p>The binary is located via the {@code musigd.bin} system property, falling back to
 * {@code target/debug/musigd} relative to the workspace root. Build it first with
 * {@code cargo build --bin musigd}.
 */
public class MusigdProcess implements AutoCloseable {
    private static final long STARTUP_TIMEOUT_MS = 60_000;

    private final Process process;
    private final Path walletDir;
    private final Path logFile;
    private final int port;

    private MusigdProcess(Process process, Path walletDir, Path logFile, int port) {
        this.process = process;
        this.walletDir = walletDir;
        this.logFile = logFile;
        this.port = port;
    }

    /**
     * Launches musigd on {@code port} with a fresh wallet directory.
     *
     * @param p2pAddr bitcoind's P2P address for compact-block-filter syncing, or {@code null} to
     *                run without chain syncing
     * @param pollSeconds how often the wallet re-syncs; keep it short so tests don't crawl
     */
    public static MusigdProcess start(int port,
                                      String rpcUrl,
                                      String rpcUser,
                                      String rpcPass,
                                      String p2pAddr,
                                      int pollSeconds) throws IOException {
        Path binary = locateBinary();
        Path walletDir = Files.createTempDirectory("bmp-wallet-it-");
        Path logFile = Files.createTempFile("musigd-it-", ".log");

        List<String> command = new ArrayList<>(List.of(
                binary.toString(),
                "--port", String.valueOf(port),
                "--wallet-dir", walletDir.toString(),
                "--wallet-network", "regtest",
                "--wallet-poll-secs", String.valueOf(pollSeconds),
                "--bitcoin-rpc-url", rpcUrl,
                "--bitcoin-rpc-user", rpcUser,
                "--bitcoin-rpc-pass", rpcPass));
        if (p2pAddr != null && !p2pAddr.isBlank()) {
            command.add("--wallet-peer");
            command.add(p2pAddr);
        }

        System.out.println("Starting musigd: " + String.join(" ", command));
        ProcessBuilder builder = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(logFile.toFile());
        builder.environment().put("RUST_LOG", "info");

        MusigdProcess musigd =
                new MusigdProcess(builder.start(), walletDir, logFile, port);
        try {
            musigd.awaitPort();
        } catch (RuntimeException e) {
            musigd.close();
            throw e;
        }
        return musigd;
    }

    private static Path locateBinary() {
        String configured = System.getProperty("musigd.bin");
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured);
        }
        // The Maven module lives at <workspace>/rpc, so the cargo target dir is one level up.
        Path fallback = Path.of("..", "target", "debug", "musigd").normalize().toAbsolutePath();
        if (!Files.isExecutable(fallback)) {
            throw new IllegalStateException(
                    "musigd binary not found at " + fallback + ". Build it with "
                            + "`cargo build --bin musigd`, or point -Dmusigd.bin at it.");
        }
        return fallback;
    }

    /** Blocks until the gRPC port accepts a connection, or the process dies / we time out. */
    private void awaitPort() {
        long deadline = System.currentTimeMillis() + STARTUP_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive()) {
                throw new IllegalStateException(
                        "musigd exited during startup (code " + process.exitValue() + "):\n" + tailLog());
            }
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
                System.out.println("musigd is accepting connections on port " + port);
                return;
            } catch (IOException notYet) {
                sleep(250);
            }
        }
        throw new IllegalStateException(
                "musigd did not open port " + port + " within " + STARTUP_TIMEOUT_MS + "ms:\n" + tailLog());
    }

    /** The last few log lines, for putting a real cause in an assertion failure. */
    public String tailLog() {
        try {
            List<String> lines = Files.readAllLines(logFile);
            return String.join("\n", lines.subList(Math.max(0, lines.size() - 40), lines.size()));
        } catch (IOException e) {
            return "<could not read " + logFile + ": " + e.getMessage() + ">";
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while waiting for musigd", e);
        }
    }

    @Override
    public void close() {
        if (process.isAlive()) {
            process.destroy();
            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
            }
        }
        deleteRecursively(walletDir);
        // The log's usefulness is in `tailLog()`, which failures already embed in their message,
        // so there's nothing left to keep the file around for.
        try {
            Files.deleteIfExists(logFile);
        } catch (IOException ignored) {
            // Best effort — it's a temp file.
        }
    }

    private static void deleteRecursively(Path path) {
        try (var paths = Files.walk(path)) {
            paths.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // Best effort — it's a temp dir.
                }
            });
        } catch (IOException ignored) {
            // Best effort.
        }
    }
}
