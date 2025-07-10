package bisq;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * A helper class to run Nigiri commands from Java.
 */
public class NigiriCli {

    public void fundAddress(String address, double amount) {
        // Command: nigiri rpc sendtoaddress <address> <amount>
        executeCommand("nigiri", "rpc", "sendtoaddress", address, String.valueOf(amount));
    }

    public void mineBlocks(int count) {
        // Command: nigiri rpc -generate <count>
        executeCommand("nigiri", "rpc", "-generate", String.valueOf(count));
    }

    public String getRawTransaction(String txid) {
        // Command: nigiri rpc getrawtransaction <txid>
        return executeCommand("nigiri", "rpc", "getrawtransaction", txid);
    }
    
    private String executeCommand(String... command) {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true); // Combine stdout and stderr

        try {
            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }

            // Wait for the process to complete, with a timeout
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroy();
                throw new RuntimeException("Command timed out: " + String.join(" ", command));
            }

            int exitCode = process.exitValue();
            if (exitCode != 0) {
                System.err.println("Command failed with exit code " + exitCode + ": " + String.join(" ", command));
                System.err.println("Output: " + output);
                return null; // Return null on failure
            }
            
            return output.toString().trim();

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            Thread.currentThread().interrupt();
            return null;
        }
    }
}
