package io.github.burakkaygusuz;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.crawler.WebCrawler;
import io.github.burakkaygusuz.model.Vulnerability;
import io.github.burakkaygusuz.scanner.VulnerabilityScanner;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import io.github.burakkaygusuz.util.UrlUtils;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class WebSecurityScanner {

  private static final Logger logger = LoggerFactory.getLogger(WebSecurityScanner.class);

  private final ScannerConfig config;
  private final HttpClientService httpClientService;
  private final ReportService reportService;
  private final VulnerabilityScanner vulnerabilityScanner;

  private String targetUrl;
  private WebCrawler webCrawler;

  public WebSecurityScanner(
      ScannerConfig config,
      HttpClientService httpClientService,
      ReportService reportService,
      VulnerabilityScanner vulnerabilityScanner) {
    this.config = config;
    this.httpClientService = httpClientService;
    this.reportService = reportService;
    this.vulnerabilityScanner = vulnerabilityScanner;
  }

  public void setTargetUrl(String targetUrl) {
    if (!UrlUtils.isValidUrl(targetUrl)) {
      throw new IllegalArgumentException("Invalid target URL: " + targetUrl);
    }
    this.targetUrl = targetUrl;
    this.webCrawler =
        new WebCrawler(targetUrl, config, httpClientService, this::scheduleVulnerabilityChecks);
  }

  public List<Vulnerability> scan() {
    if (targetUrl == null) {
      throw new IllegalStateException("Target URL must be set before scanning");
    }

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
    return webCrawler != null ? webCrawler.getVisitedUrlsCount() : 0;
  }
}
