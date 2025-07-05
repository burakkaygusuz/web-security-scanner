package io.github.burakkaygusuz;

import org.jline.reader.*;
import org.jline.terminal.*;
import org.slf4j.*;

import java.io.IOException;
import java.util.List;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        String targetUrl = null;

        if (args.length == 1) {
            targetUrl = args[0];
        }

        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            try (Terminal terminal = TerminalBuilder.builder().build()) {
                LineReader reader = LineReaderBuilder.builder()
                        .terminal(terminal)
                        .build();

                while (true) {
                    try {
                        String line = reader.readLine("Enter target URL (or 'exit' to quit): ");
                        if (line.equalsIgnoreCase("exit")) {
                            return;
                        }

                        if (line.trim().isEmpty()) {
                            logger.info("URL cannot be empty. Please try again.");
                            continue;
                        }
                        targetUrl = line.trim();
                        break; 
                    } catch (UserInterruptException e) {
                        return;
                    } catch (EndOfFileException e) {
                        return;
                    }
                }
            } catch (IOException e) {
                logger.error("Error initializing terminal: {}", e.getMessage());
                System.exit(1);
            }
        }

        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            logger.info("No target URL provided. Exiting.");
            System.exit(0);
        }

        WebSecurityScanner scanner = new WebSecurityScanner(targetUrl);
        try {
            List<Vulnerability> vulnerabilities = scanner.scan();

            logger.info("\nScan Complete!");
            logger.info("Total URLs scanned: {}", scanner.getVisitedUrlsCount());
            logger.info("Vulnerabilities found: {}", vulnerabilities.size());
        } finally {
            scanner.close();
        }
    }
}