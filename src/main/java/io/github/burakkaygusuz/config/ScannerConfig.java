package io.github.burakkaygusuz.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

/**
 * Main Spring Boot configuration properties for the web security scanner. Properties are loaded
 * from application.yml under 'scanner' prefix.
 */
@ConfigurationProperties(prefix = "scanner")
@Validated
@Component
public class ScannerConfig {

  /** SQL injection payloads for testing */
  @NotNull
  private List<String> sqlPayloads =
      List.of(
          "'",
          "1' OR '1'='1",
          "' OR 1=1--",
          "' UNION SELECT NULL--",
          "'; DROP TABLE users--",
          "' AND (SELECT COUNT(*) FROM sysobjects)>0--");

  /** XSS payloads for testing */
  @NotNull
  private List<String> xssPayloads =
      List.of(
          "<script>alert('XSS')</script>",
          "<img src=x onerror=alert('XSS')>",
          "javascript:alert('XSS')",
          "<svg onload=alert('XSS')>",
          "'><script>alert('XSS')</script>",
          "\"><script>alert('XSS')</script>");

  /** Sensitive data patterns for detection */
  @NotNull
  private Map<String, String> sensitivePatterns =
      Map.of(
          "email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
          "phone", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b",
          "ssn", "\\b\\d{3}-\\d{2}-\\d{4}\\b",
          "api_key", "api[_-]?key[_-]?(['\"`])([a-zA-Z0-9]{32,45})\\1",
          "credit_card", "\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b");

  /** Scan settings - nested configuration */
  @Valid @NotNull private ScanSettings scanSettings = new ScanSettings();

  /** CSRF settings - nested configuration */
  @Valid @NotNull private CsrfSettings csrfSettings = new CsrfSettings();

  public List<String> getSqlPayloads() {
    return sqlPayloads;
  }

  public void setSqlPayloads(List<String> sqlPayloads) {
    this.sqlPayloads = sqlPayloads;
  }

  public List<String> getXssPayloads() {
    return xssPayloads;
  }

  public void setXssPayloads(List<String> xssPayloads) {
    this.xssPayloads = xssPayloads;
  }

  public Map<String, String> getSensitivePatterns() {
    return sensitivePatterns;
  }

  public void setSensitivePatterns(Map<String, String> sensitivePatterns) {
    this.sensitivePatterns = sensitivePatterns;
  }

  public ScanSettings getScanSettings() {
    return scanSettings;
  }

  public void setScanSettings(ScanSettings scanSettings) {
    this.scanSettings = scanSettings;
  }

  public CsrfSettings getCsrfSettings() {
    return csrfSettings;
  }

  public void setCsrfSettings(CsrfSettings csrfSettings) {
    this.csrfSettings = csrfSettings;
  }

  // Backward compatibility methods for record-style access
  public List<String> sqlPayloads() {
    return getSqlPayloads();
  }

  public List<String> xssPayloads() {
    return getXssPayloads();
  }

  public Map<String, String> sensitivePatterns() {
    return getSensitivePatterns();
  }

  public ScanSettings scanSettings() {
    return getScanSettings();
  }

  public CsrfSettings csrfSettings() {
    return getCsrfSettings();
  }
}
