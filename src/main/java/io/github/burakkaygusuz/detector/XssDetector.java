package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.Vulnerability;
import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import io.github.burakkaygusuz.util.UrlUtils;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XssDetector {

  private static final Logger logger = LoggerFactory.getLogger(XssDetector.class);

  private final ScannerConfig config;
  private final HttpClientService httpClientService;
  private final ReportService reportService;

  public XssDetector(
      ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
    this.config = config;
    this.httpClientService = httpClientService;
    this.reportService = reportService;
  }

  public void checkXss(String url) {
    List<String> xssPayloads = config.xssPayloads();

    for (String payload : xssPayloads) {
      try {
        URI uri = new URI(url);
        String query = uri.getQuery();

        if (query != null) {
          Map<String, String> params = UrlUtils.parseParameters(query);

          for (Map.Entry<String, String> param : params.entrySet()) {
            try {
              String encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
              String testUrl = UrlUtils.buildTestUrl(url, param.getKey(), encodedPayload);

              try (Response response = httpClientService.executeRequestWithRateLimit(testUrl)) {
                if (!response.isSuccessful()) {
                  continue;
                }

                String responseText = httpClientService.safeReadResponse(response);
                if (responseText.contains(payload)) {
                  reportService.reportVulnerability(
                      new Vulnerability(
                          "Cross-Site Scripting (XSS)", url, param.getKey(), payload));
                }
              }
            } catch (Exception e) {
              logger.warn(
                  "Error with rate limiter for XSS test on parameter {}: {}",
                  param.getKey(),
                  e.getMessage());
            }
          }
        }
      } catch (Exception e) {
        logger.warn("Error checking XSS on {}: {}", url, e.getMessage());
      }
    }
  }
}
