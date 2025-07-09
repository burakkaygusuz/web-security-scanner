package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.model.VulnerabilityType;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;

/**
 * Wrapper class for XssDetector to implement VulnerabilityDetector interface. Follows Adapter
 * Pattern to make existing detector compatible with the interface.
 */
public class XssDetectorWrapper implements VulnerabilityDetector {

  private final XssDetector detector;

  public XssDetectorWrapper(
      ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
    this.detector = new XssDetector(config, httpClientService, reportService);
  }

  @Override
  public void detect(String url) {
    detector.checkXss(url);
  }

  @Override
  public String getDetectorType() {
    return VulnerabilityType.CROSS_SITE_SCRIPTING.getDisplayName();
  }
}
