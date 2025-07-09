package io.github.burakkaygusuz.config;

import jakarta.validation.constraints.Min;

/** Configuration properties for scan settings. Used as nested configuration in ScannerConfig. */
public class ScanSettings {

  @Min(1)
  private int maxDepth = 3;

  @Min(1)
  private int timeoutSeconds = 30;

  @Min(1)
  private int rateLimitRequestsPerSecond = 3;

  @Min(1)
  private int rateLimitTimeoutSeconds = 30;

  public int getMaxDepth() {
    return maxDepth;
  }

  public void setMaxDepth(int maxDepth) {
    this.maxDepth = maxDepth;
  }

  public int getTimeoutSeconds() {
    return timeoutSeconds;
  }

  public void setTimeoutSeconds(int timeoutSeconds) {
    this.timeoutSeconds = timeoutSeconds;
  }

  public int getRateLimitRequestsPerSecond() {
    return rateLimitRequestsPerSecond;
  }

  public void setRateLimitRequestsPerSecond(int rateLimitRequestsPerSecond) {
    this.rateLimitRequestsPerSecond = rateLimitRequestsPerSecond;
  }

  public int getRateLimitTimeoutSeconds() {
    return rateLimitTimeoutSeconds;
  }

  public void setRateLimitTimeoutSeconds(int rateLimitTimeoutSeconds) {
    this.rateLimitTimeoutSeconds = rateLimitTimeoutSeconds;
  }

  /**
   * Creates default scan settings. Note: With Spring Boot, defaults are handled via field
   * initialization.
   *
   * @return default scan settings
   */
  public static ScanSettings defaultSettings() {
    return new ScanSettings();
  }
}
