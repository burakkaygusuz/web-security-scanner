package io.github.burakkaygusuz.config;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ScanSettings(
    @JsonProperty("max_depth") int maxDepth, @JsonProperty("timeout_seconds") int timeoutSeconds) {
  public ScanSettings {
    if (maxDepth < 1) {
      throw new IllegalArgumentException("Max depth must be at least 1");
    }
    if (timeoutSeconds < 1) {
      throw new IllegalArgumentException("Timeout must be at least 1 second");
    }
  }

  public static ScanSettings defaultSettings() {
    return new ScanSettings(3, 30);
  }
}
