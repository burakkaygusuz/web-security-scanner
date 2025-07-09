package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.model.VulnerabilityType;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;

/**
 * Wrapper class for SensitiveInfoDetector to implement VulnerabilityDetector interface. Follows
 * Adapter Pattern to make existing detector compatible with the interface.
 */
public class SensitiveInfoDetectorWrapper implements VulnerabilityDetector {

  private final SensitiveInfoDetector detector;

  public SensitiveInfoDetectorWrapper(
      ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
    this.detector = new SensitiveInfoDetector(config, httpClientService, reportService);
  }

  @Override
  public void detect(String url) {
    detector.checkSensitiveInfo(url);
  }

  @Override
  public String getDetectorType() {
    return VulnerabilityType.SENSITIVE_INFO_EXPOSURE.getDisplayName();
  }
}
