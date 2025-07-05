package io.github.burakkaygusuz;

import java.util.List;

public class Main {
    public static final String GREEN = "\033[0;32m";
    public static final String RESET = "\033[0m";

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java WebSecurityScanner <target_url>");
            System.exit(1);
        }

        String targetUrl = args[0];
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