package io.github.burakkaygusuz.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record ScannerConfig(
    @JsonProperty("sql_payloads") List<String> sqlPayloads,
    @JsonProperty("xss_payloads") List<String> xssPayloads,
    @JsonProperty("sensitive_patterns") Map<String, String> sensitivePatterns,
    @JsonProperty("scan_settings") ScanSettings scanSettings) {
  public ScannerConfig {
    Objects.requireNonNull(sqlPayloads, "SQL payloads cannot be null");
    Objects.requireNonNull(xssPayloads, "XSS payloads cannot be null");
    Objects.requireNonNull(sensitivePatterns, "Sensitive patterns cannot be null");
    Objects.requireNonNull(scanSettings, "Scan settings cannot be null");

    sqlPayloads = List.copyOf(sqlPayloads);
    xssPayloads = List.copyOf(xssPayloads);
    sensitivePatterns = Map.copyOf(sensitivePatterns);
  }
}
