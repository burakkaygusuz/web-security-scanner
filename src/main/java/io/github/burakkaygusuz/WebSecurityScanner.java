package io.github.burakkaygusuz;

import io.github.burakkaygusuz.config.ConfigLoader;
import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.crawler.WebCrawler;
import io.github.burakkaygusuz.scanner.VulnerabilityScanner;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import io.github.burakkaygusuz.util.UrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class WebSecurityScanner {

    private static final Logger logger = LoggerFactory.getLogger(WebSecurityScanner.class);

    private final String targetUrl;
    private final ScannerConfig config;
    private final HttpClientService httpClientService;
    private final ReportService reportService;
    private final VulnerabilityScanner vulnerabilityScanner;
    private final WebCrawler webCrawler;

    public WebSecurityScanner(String targetUrl) {
        this.config = ConfigLoader.loadConfig();
        
        if (!UrlUtils.isValidUrl(targetUrl)) {
            throw new IllegalArgumentException("Invalid target URL: " + targetUrl);
        }
        
        this.targetUrl = targetUrl;
        this.httpClientService = new HttpClientService(config);
        this.reportService = new ReportService();
        this.vulnerabilityScanner = new VulnerabilityScanner(config, httpClientService, reportService);
        this.webCrawler = new WebCrawler(targetUrl, config, httpClientService, this::scheduleVulnerabilityChecks);
    }

    public List<Vulnerability> scan() {
        logger.info("\nStarting security scan of {}\n", targetUrl);

        webCrawler.crawl(targetUrl, 0);
        vulnerabilityScanner.shutdown();
        
        try {
            if (!vulnerabilityScanner.getExecutor().awaitTermination(60, TimeUnit.MINUTES)) {
                vulnerabilityScanner.getExecutor().shutdownNow();
            }
        } catch (InterruptedException e) {
            vulnerabilityScanner.getExecutor().shutdownNow();
        }

        return reportService.getVulnerabilities();
    }

    public void close() {
        httpClientService.close();
    }

    private void scheduleVulnerabilityChecks(String url) {
        vulnerabilityScanner.scanUrl(url);
    }

    public int getVisitedUrlsCount() {
        return webCrawler.getVisitedUrlsCount();
    }
}
