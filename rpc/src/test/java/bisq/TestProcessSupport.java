package bisq;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** What the process launchers of the integration tests ({@code MusigdProcess}, {@code TestEnvProcess}) share. */
final class TestProcessSupport {
    private static final int TAIL_LINES = 40;

    private TestProcessSupport() {
    }

    /**
     * Resolves a cargo-built binary: the path given by the system property {@code property} if
     * set, else {@code target/debug/<binaryName>} relative to the workspace root. Either way the
     * result must exist and be executable, so a missing binary fails here with advice rather than
     * later with a bare "Cannot run program" from {@link ProcessBuilder#start()}.
     */
    static Path locateBinary(String property, String binaryName, String buildHint) {
        String configured = System.getProperty(property);
        Path binary = configured != null && !configured.isBlank()
                ? Path.of(configured)
                // The Maven module lives at <workspace>/rpc, so the cargo target dir is one level up.
                : Path.of("..", "target", "debug", binaryName).normalize().toAbsolutePath();
        if (!Files.isExecutable(binary)) {
            throw new IllegalStateException(binaryName + " binary not found at " + binary
                    + ". Build it with `" + buildHint + "`, or point -D" + property + " at it.");
        }
        return binary;
    }

    /** The last few lines of {@code logFile}, for putting a real cause in an assertion failure. */
    static String tailLog(Path logFile) {
        try {
            List<String> lines = Files.readAllLines(logFile);
            return String.join("\n", lines.subList(Math.max(0, lines.size() - TAIL_LINES), lines.size()));
        } catch (IOException e) {
            return "<could not read " + logFile + ": " + e.getMessage() + ">";
        }
    }
}
