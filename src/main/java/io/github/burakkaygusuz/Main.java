package io.github.burakkaygusuz;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.IOException;
import java.util.List;

public class Main {
    public static final String GREEN = "\u001b[0;32m";
    public static final String RESET = "\u001b[0m";

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
                            System.out.println("URL cannot be empty. Please try again.");
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
                System.err.println("Error initializing terminal: " + e.getMessage());
                System.exit(1);
            }
        }

        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            System.out.println("No target URL provided. Exiting.");
            System.exit(0);
        }

        WebSecurityScanner scanner = new WebSecurityScanner(targetUrl);
        try {
            List<Vulnerability> vulnerabilities = scanner.scan();

            System.out.println(GREEN + "\nScan Complete!" + RESET);
            System.out.println("Total URLs scanned: " + scanner.getVisitedUrlsCount());
            System.out.println("Vulnerabilities found: " + vulnerabilities.size());
        } finally {
            scanner.close();
        }
    }
}