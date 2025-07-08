package io.github.burakkaygusuz.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigLoader {

  private static final Logger logger = LoggerFactory.getLogger(ConfigLoader.class);
  private static final ObjectMapper objectMapper = new ObjectMapper();

  private static final List<String> DEFAULT_SQL_PAYLOADS =
      Arrays.asList(
          "'",
          "1' OR '1'='1",
          "' OR 1=1--",
          "' UNION SELECT NULL--",
          "'; DROP TABLE users--",
          "' AND (SELECT COUNT(*) FROM sysobjects)>0--");

  private static final List<String> DEFAULT_XSS_PAYLOADS =
      Arrays.asList(
          "<script>alert('XSS')</script>",
          "<img src=x onerror=alert('XSS')>",
          "javascript:alert('XSS')",
          "<svg onload=alert('XSS')>",
          "'><script>alert('XSS')</script>",
          "\"><script>alert('XSS')</script>");

  private static final Map<String, String> DEFAULT_SENSITIVE_PATTERNS =
      Map.ofEntries(
          Map.entry("email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
          Map.entry("phone", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b"),
          Map.entry("ssn", "\\b\\d{3}-\\d{2}-\\d{4}\\b"),
          Map.entry("api_key", "api[_-]?key[_-]?(['\"`])([a-zA-Z0-9]{32,45})\\1"),
          Map.entry("credit_card", "\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b"));

  public static ScannerConfig loadConfig() {
    try {
      InputStream configStream = ConfigLoader.class.getResourceAsStream("/scanner-config.json");
      if (configStream != null) {
        ScannerConfig config = objectMapper.readValue(configStream, ScannerConfig.class);
        logger.info("Loaded configuration from scanner-config.json");
        return validateAndFillDefaults(config);
      }
    } catch (IOException e) {
      logger.warn("Failed to load configuration from JSON: {}", e.getMessage());
    }

    logger.info("Using default configuration");
    return createDefaultConfig();
  }

  private static ScannerConfig validateAndFillDefaults(ScannerConfig config) {
    List<String> sqlPayloads =
        (config.sqlPayloads() == null || config.sqlPayloads().isEmpty())
            ? DEFAULT_SQL_PAYLOADS
            : config.sqlPayloads();

    List<String> xssPayloads =
        (config.xssPayloads() == null || config.xssPayloads().isEmpty())
            ? DEFAULT_XSS_PAYLOADS
            : config.xssPayloads();

    Map<String, String> sensitivePatterns =
        (config.sensitivePatterns() == null || config.sensitivePatterns().isEmpty())
            ? new HashMap<>(DEFAULT_SENSITIVE_PATTERNS)
            : config.sensitivePatterns();

    ScanSettings scanSettings =
        (config.scanSettings() == null) ? ScanSettings.defaultSettings() : config.scanSettings();

    return new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
  }

  private static ScannerConfig createDefaultConfig() {
    return new ScannerConfig(
        DEFAULT_SQL_PAYLOADS,
        DEFAULT_XSS_PAYLOADS,
        new HashMap<>(DEFAULT_SENSITIVE_PATTERNS),
        ScanSettings.defaultSettings());
  }
}
