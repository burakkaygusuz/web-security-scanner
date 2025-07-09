package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.model.VulnerabilityType;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;

/**
 * Wrapper class for SqlInjectionDetector to implement VulnerabilityDetector interface. Follows
 * Adapter Pattern to make existing detector compatible with the interface.
 */
public class SqlInjectionDetectorWrapper implements VulnerabilityDetector {

  private final SqlInjectionDetector detector;

  public SqlInjectionDetectorWrapper(
      ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
    this.detector = new SqlInjectionDetector(config, httpClientService, reportService);
  }

  @Override
  public void detect(String url) {
    detector.checkSqlInjection(url);
  }

  @Override
  public String getDetectorType() {
    return VulnerabilityType.SQL_INJECTION.getDisplayName();
  }
}
