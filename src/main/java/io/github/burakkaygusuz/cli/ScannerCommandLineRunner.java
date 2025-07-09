package io.github.burakkaygusuz.cli;

import io.github.burakkaygusuz.WebSecurityScanner;
import io.github.burakkaygusuz.model.Vulnerability;
import java.io.IOException;
import java.util.List;
import org.jline.reader.*;
import org.jline.terminal.*;
import org.slf4j.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Spring Boot CommandLineRunner that preserves the original CLI functionality. Only runs when
 * 'scanner.cli.enabled=true' property is set.
 */
@Component
@ConditionalOnProperty(name = "scanner.cli.enabled", havingValue = "true", matchIfMissing = false)
public class ScannerCommandLineRunner implements CommandLineRunner {

  private static final Logger logger = LoggerFactory.getLogger(ScannerCommandLineRunner.class);

  private final WebSecurityScanner webSecurityScanner;

  public ScannerCommandLineRunner(WebSecurityScanner webSecurityScanner) {
    this.webSecurityScanner = webSecurityScanner;
  }

  @Override
  public void run(String... args) throws Exception {
    logger.info("Starting CLI Scanner...");

    String targetUrl = null;

    if (args.length == 1) {
      targetUrl = args[0];
    }

    if (targetUrl == null || targetUrl.trim().isEmpty()) {
      try (Terminal terminal = TerminalBuilder.builder().build()) {
        LineReader reader = LineReaderBuilder.builder().terminal(terminal).build();

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
          } catch (UserInterruptException | EndOfFileException e) {
            logger.info("User interrupted or reached end of file. Exiting...");
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

    webSecurityScanner.setTargetUrl(targetUrl);
    try {
      List<Vulnerability> vulnerabilities = webSecurityScanner.scan();

      if (!vulnerabilities.isEmpty()) {
        printVulnerabilitiesTable(vulnerabilities);
      }

      logger.info(
          "\nScan Complete! Total URLs scanned: {}, Vulnerabilities found: {}",
          webSecurityScanner.getVisitedUrlsCount(),
          vulnerabilities.size());
    } finally {
      webSecurityScanner.close();
    }
  }

  private static void printVulnerabilitiesTable(List<Vulnerability> vulnerabilities) {
    // ANSI Color Codes
    final String RESET = "\033[0m";
    final String RED = "\033[0;31m"; // SQL Injection
    final String YELLOW = "\033[0;33m"; // XSS
    final String BLUE = "\033[0;34m"; // Sensitive Information Exposure
    final String CYAN = "\033[0;36m"; // Table headers
    final String MAGENTA = "\033[0;35m"; // CSRF-related vulnerabilities

    int typeWidth = "Type".length();
    int urlWidth = "URL".length();
    int parameterWidth = "Parameter".length();
    int payloadWidth = "Payload".length();

    for (Vulnerability vul : vulnerabilities) {
      typeWidth = Math.max(typeWidth, vul.getTypeName().length());
      urlWidth = Math.max(urlWidth, vul.url().length());
      parameterWidth =
          Math.max(parameterWidth, vul.parameter() != null ? vul.parameter().length() : 0);
      payloadWidth = Math.max(payloadWidth, vul.payload() != null ? vul.payload().length() : 0);
    }

    typeWidth += 2;
    urlWidth += 2;
    parameterWidth += 2;
    payloadWidth += 2;

    String format =
        "| %-"
            + typeWidth
            + "s | %-"
            + urlWidth
            + "s | %-"
            + parameterWidth
            + "s | %-"
            + payloadWidth
            + "s |%n";
    String separator =
        "+%s+%s+%s+%s+"
            .formatted(
                "-".repeat(typeWidth + 2),
                "-".repeat(urlWidth + 2),
                "-".repeat(parameterWidth + 2),
                "-".repeat(payloadWidth + 2));

    System.out.println(separator);
    System.out.printf(CYAN + format + RESET, "Type", "URL", "Parameter", "Payload");
    System.out.println(separator);

    for (Vulnerability vul : vulnerabilities) {
      String color =
          switch (vul.type()) {
            case SQL_INJECTION -> RED;
            case CROSS_SITE_SCRIPTING -> YELLOW;
            case SENSITIVE_INFO_EXPOSURE -> BLUE;
            case NO_CSRF_TOKEN,
                INVALID_CSRF_TOKEN,
                REUSED_CSRF_TOKEN,
                EXPIRED_CSRF_TOKEN,
                WEAK_REFERER_VALIDATION,
                MISSING_SAMESITE_COOKIE ->
                MAGENTA;
            default -> RESET;
          };
      System.out.printf(
          color + format + RESET,
          vul.getTypeName(),
          vul.url(),
          vul.parameter() != null ? vul.parameter() : "N/A",
          vul.payload() != null ? vul.payload() : "N/A");
    }
    System.out.println(separator);
  }
}
