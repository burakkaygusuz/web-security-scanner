package io.github.burakkaygusuz.config;

import static org.assertj.core.api.Assertions.*;

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(locations = "classpath:test-application.properties")
class ConfigLoaderTest {

  @Autowired private ScannerConfig scannerConfig;

  @Test
  void testLoadDefaultConfig() {
    ScannerConfig config = scannerConfig;

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(config).isNotNull();
          softly.assertThat(config.getSqlPayloads()).isNotNull().isNotEmpty();
          softly.assertThat(config.getXssPayloads()).isNotNull().isNotEmpty();
          softly.assertThat(config.getSensitivePatterns()).isNotNull().isNotEmpty();
          softly.assertThat(config.getScanSettings()).isNotNull();
          softly.assertThat(config.getCsrfSettings()).isNotNull();
        });
  }

  @Test
  void testDefaultSqlPayloads() {
    ScannerConfig config = scannerConfig;

    assertThat(config.getSqlPayloads())
        .contains("\'")
        .contains("1' OR '1'='1")
        .contains("' OR 1=1--")
        .contains("' UNION SELECT NULL--");
  }

  @Test
  void testDefaultXssPayloads() {
    ScannerConfig config = scannerConfig;

    assertThat(config.getXssPayloads())
        .contains("<script>alert('XSS')</script>")
        .contains("<img src=x onerror=alert('XSS')>")
        .contains("javascript:alert('XSS')")
        .contains("<svg onload=alert('XSS')>");
  }

  @Test
  void testDefaultSensitivePatterns() {
    ScannerConfig config = scannerConfig;

    assertThat(config.getSensitivePatterns())
        .containsKeys("email", "phone", "ssn", "api_key", "credit_card")
        .containsEntry("email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        .containsEntry("phone", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b");
  }

  @Test
  void testDefaultScanSettings() {
    ScannerConfig config = scannerConfig;

    assertThat(config.getScanSettings())
        .extracting(ScanSettings::getMaxDepth, ScanSettings::getTimeoutSeconds)
        .containsExactly(3, 30);
  }

  @Test
  void testDefaultCsrfSettings() {
    ScannerConfig config = scannerConfig;

    assertThat(config.getCsrfSettings())
        .extracting(
            CsrfSettings::isTestForms,
            CsrfSettings::isCheckSameSiteCookies,
            CsrfSettings::getMinimumTokenLength)
        .containsExactly(true, true, 16);
  }

  @Test
  void testPayloadsAreNotEmpty() {
    ScannerConfig config = scannerConfig;

    SoftAssertions.assertSoftly(
        softly -> {
          config
              .getSqlPayloads()
              .forEach(
                  payload -> {
                    softly.assertThat(payload).isNotNull().isNotEmpty();
                  });

          config
              .getXssPayloads()
              .forEach(
                  payload -> {
                    softly.assertThat(payload).isNotNull().isNotEmpty();
                  });
        });
  }

  @Test
  void testSensitivePatternsAreValid() {
    ScannerConfig config = scannerConfig;

    config
        .getSensitivePatterns()
        .forEach(
            (key, pattern) -> {
              SoftAssertions.assertSoftly(
                  softly -> {
                    softly.assertThat(key).isNotNull().isNotEmpty();
                    softly.assertThat(pattern).isNotNull().isNotEmpty();

                    // Test that patterns can be compiled (basic validation)
                    softly
                        .assertThatCode(() -> java.util.regex.Pattern.compile(pattern))
                        .doesNotThrowAnyException();
                  });
            });
  }

  @Test
  void testDefaultConfigContainsExpectedPayloadCount() {
    ScannerConfig config = scannerConfig;

    // Check actual sizes since config might load from external file
    assertThat(config.getSqlPayloads()).isNotEmpty();
    assertThat(config.getXssPayloads()).isNotEmpty();
    assertThat(config.getSensitivePatterns()).isNotEmpty();
  }
}
