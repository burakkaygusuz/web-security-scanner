package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.model.Vulnerability;
import io.github.burakkaygusuz.model.VulnerabilityType;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SensitiveInfoDetector {

  private static final Logger logger = LoggerFactory.getLogger(SensitiveInfoDetector.class);

  private final ScannerConfig config;
  private final HttpClientService httpClientService;
  private final ReportService reportService;

  public SensitiveInfoDetector(
      ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
    this.config = config;
    this.httpClientService = httpClientService;
    this.reportService = reportService;
  }

  public void checkSensitiveInfo(String url) {
    Map<String, Pattern> sensitivePatterns = new HashMap<>();

    for (Map.Entry<String, String> entry : config.sensitivePatterns().entrySet()) {
      try {
        Pattern pattern = Pattern.compile(entry.getValue(), Pattern.CASE_INSENSITIVE);
        sensitivePatterns.put(entry.getKey(), pattern);
      } catch (Exception e) {
        logger.warn("Invalid regex pattern for {}: {}", entry.getKey(), entry.getValue());
      }
    }

    try (Response response = httpClientService.executeRequest(url)) {
      if (!response.isSuccessful()) {
        return;
      }

      String responseText = httpClientService.safeReadResponse(response);
      if (responseText.isEmpty()) {
        return;
      }

      for (Map.Entry<String, Pattern> entry : sensitivePatterns.entrySet()) {
        Pattern pattern = entry.getValue();
        Matcher matcher = pattern.matcher(responseText);

        while (matcher.find()) {
          reportService.reportVulnerability(
              new Vulnerability(
                  VulnerabilityType.SENSITIVE_INFO_EXPOSURE,
                  url,
                  entry.getKey(),
                  entry.getValue().pattern()));
        }
      }
    } catch (Exception e) {
      logger.warn(
          "Error with rate limiter for sensitive info check on {}: {}", url, e.getMessage());
    }
  }
}
