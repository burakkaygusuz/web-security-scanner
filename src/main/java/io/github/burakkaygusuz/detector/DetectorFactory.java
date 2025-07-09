package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.model.VulnerabilityType;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

/**
 * Factory for creating vulnerability detectors. Follows Factory Pattern to centralize detector
 * creation logic.
 */
@Component
public class DetectorFactory {

  private final ScannerConfig config;
  private final HttpClientService httpClientService;
  private final ReportService reportService;

  private static final Set<String> SUPPORTED_DETECTOR_TYPES;

  static {
    SUPPORTED_DETECTOR_TYPES = getSupportedTypes();
  }

  public DetectorFactory(
      ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
    this.config = config;
    this.httpClientService = httpClientService;
    this.reportService = reportService;
  }

  /**
   * Creates all available vulnerability detectors.
   *
   * @return list of configured detectors
   */
  public List<VulnerabilityDetector> createAllDetectors() {
    List<VulnerabilityDetector> detectors = new ArrayList<>();

    detectors.add(new SqlInjectionDetectorWrapper(config, httpClientService, reportService));
    detectors.add(new XssDetectorWrapper(config, httpClientService, reportService));
    detectors.add(new SensitiveInfoDetectorWrapper(config, httpClientService, reportService));

    if (config.csrfSettings() != null) {
      detectors.add(
          new CsrfDetectorWrapper(config.csrfSettings(), httpClientService, reportService));
    }

    return detectors;
  }

  /**
   * Creates a specific type of detector.
   *
   * @param detectorType the type of detector to create
   * @return the detector instance
   * @throws IllegalArgumentException if detector type is not supported
   */
  public VulnerabilityDetector createDetector(String detectorType) {
    if (detectorType == null || detectorType.trim().isEmpty()) {
      throw new IllegalArgumentException("Detector type cannot be null or empty");
    }

    VulnerabilityType.DetectorType type = VulnerabilityType.DetectorType.fromString(detectorType);

    return switch (type) {
      case SQL_INJECTION ->
          new SqlInjectionDetectorWrapper(config, httpClientService, reportService);
      case XSS -> new XssDetectorWrapper(config, httpClientService, reportService);
      case SENSITIVE_INFO ->
          new SensitiveInfoDetectorWrapper(config, httpClientService, reportService);
      case CSRF -> {
        if (config.csrfSettings() == null) {
          throw new IllegalStateException("CSRF settings not configured");
        }
        yield new CsrfDetectorWrapper(config.csrfSettings(), httpClientService, reportService);
      }
      case UNKNOWN ->
          throw new IllegalArgumentException(
              "Unsupported detector type: "
                  + detectorType
                  + ". Supported types: "
                  + SUPPORTED_DETECTOR_TYPES);
    };
  }

  /**
   * Creates a detector based on VulnerabilityType.DetectorType enum.
   *
   * @param detectorType the detector type enum
   * @return the detector instance
   * @throws IllegalArgumentException if detector type is not supported
   */
  public VulnerabilityDetector createDetector(VulnerabilityType.DetectorType detectorType) {
    if (detectorType == null) {
      throw new IllegalArgumentException("Detector type cannot be null");
    }

    return switch (detectorType) {
      case SQL_INJECTION ->
          new SqlInjectionDetectorWrapper(config, httpClientService, reportService);
      case XSS -> new XssDetectorWrapper(config, httpClientService, reportService);
      case SENSITIVE_INFO ->
          new SensitiveInfoDetectorWrapper(config, httpClientService, reportService);
      case CSRF -> {
        if (config.csrfSettings() == null) {
          throw new IllegalStateException("CSRF settings not configured");
        }
        yield new CsrfDetectorWrapper(config.csrfSettings(), httpClientService, reportService);
      }
      case UNKNOWN ->
          throw new IllegalArgumentException("Unsupported detector type: " + detectorType);
    };
  }

  /**
   * Gets the set of supported detector types.
   *
   * @return set of supported detector type names
   */
  public Set<String> getSupportedDetectorTypes() {
    return SUPPORTED_DETECTOR_TYPES;
  }

  /**
   * Checks if a detector type is supported.
   *
   * @param detectorType the type to check
   * @return true if supported, false otherwise
   */
  public boolean isDetectorTypeSupported(String detectorType) {
    return VulnerabilityType.DetectorType.fromString(detectorType)
        != VulnerabilityType.DetectorType.UNKNOWN;
  }

  /**
   * Helper method to generate supported detector types from VulnerabilityType.DetectorType enum.
   *
   * @return set of all supported detector type aliases
   */
  private static Set<String> getSupportedTypes() {
    return Stream.of(VulnerabilityType.DetectorType.values())
        .filter(type -> type != VulnerabilityType.DetectorType.UNKNOWN)
        .flatMap(type -> Stream.of(type.getAliases()))
        .collect(java.util.stream.Collectors.toSet());
  }
}
