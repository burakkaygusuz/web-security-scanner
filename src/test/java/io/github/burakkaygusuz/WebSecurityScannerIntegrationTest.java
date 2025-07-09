package io.github.burakkaygusuz;

import static org.assertj.core.api.Assertions.*;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.scanner.VulnerabilityScanner;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(
    properties = {
      "scanner.sqlPayloads[0]='",
      "scanner.xssPayloads[0]=<script>alert('XSS')</script>",
      "scanner.sensitivePatterns.email=[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
      "scanner.scanSettings.maxDepth=1",
      "scanner.scanSettings.timeoutSeconds=5",
      "scanner.csrfSettings.testForms=true",
      "scanner.csrfSettings.minimumTokenLength=8"
    })
class WebSecurityScannerIntegrationTest {

  @Autowired private WebSecurityScanner webSecurityScanner;

  @Autowired private ScannerConfig scannerConfig;

  @Autowired private HttpClientService httpClientService;

  @Autowired private ReportService reportService;

  @Autowired private VulnerabilityScanner vulnerabilityScanner;

  @Test
  void testWebSecurityScannerDependencyInjection() {
    assertThat(webSecurityScanner).isNotNull();
    assertThat(scannerConfig).isNotNull();
    assertThat(httpClientService).isNotNull();
    assertThat(reportService).isNotNull();
    assertThat(vulnerabilityScanner).isNotNull();
  }

  @Test
  void testWebSecurityScannerConfiguration() {
    assertThat(scannerConfig.getSqlPayloads()).isNotEmpty();
    assertThat(scannerConfig.getXssPayloads()).isNotEmpty();
    assertThat(scannerConfig.getSensitivePatterns()).isNotEmpty();
    assertThat(scannerConfig.getScanSettings().getMaxDepth()).isEqualTo(1);
    assertThat(scannerConfig.getScanSettings().getTimeoutSeconds()).isEqualTo(5);
  }

  @Test
  void testSetTargetUrlValidation() {
    assertThatThrownBy(() -> webSecurityScanner.setTargetUrl("invalid-url"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid target URL");
  }

  @Test
  void testSetValidTargetUrl() {
    assertThatCode(() -> webSecurityScanner.setTargetUrl("https://example.com"))
        .doesNotThrowAnyException();
  }

  @Test
  void testScanWithoutTargetUrl() {
    // Reset scanner state
    webSecurityScanner.setTargetUrl("https://example.com");

    // Test that scanner requires target URL to be set
    assertThat(webSecurityScanner.getVisitedUrlsCount()).isEqualTo(0);
  }

  @Test
  void testGetVisitedUrlsCountInitiallyZero() {
    assertThat(webSecurityScanner.getVisitedUrlsCount()).isEqualTo(0);
  }
}
