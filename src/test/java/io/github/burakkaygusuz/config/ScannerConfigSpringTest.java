package io.github.burakkaygusuz.config;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(
    properties = {
      "scanner.sqlPayloads[0]='",
      "scanner.sqlPayloads[1]=1' OR '1'='1",
      "scanner.xssPayloads[0]=<script>alert('XSS')</script>",
      "scanner.sensitivePatterns.email=[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
      "scanner.scanSettings.maxDepth=2",
      "scanner.scanSettings.timeoutSeconds=15",
      "scanner.csrfSettings.testForms=true",
      "scanner.csrfSettings.minimumTokenLength=8"
    })
class ScannerConfigSpringTest {

  @Autowired private ScannerConfig scannerConfig;

  @Test
  void testConfigurationPropertiesInjection() {
    assertThat(scannerConfig).isNotNull();
    assertThat(scannerConfig.getSqlPayloads()).isNotEmpty();
    assertThat(scannerConfig.getXssPayloads()).isNotEmpty();
    assertThat(scannerConfig.getSensitivePatterns()).isNotEmpty();
    assertThat(scannerConfig.getScanSettings()).isNotNull();
    assertThat(scannerConfig.getCsrfSettings()).isNotNull();
  }

  @Test
  void testPropertyBinding() {
    assertThat(scannerConfig.getSqlPayloads()).contains("'", "1' OR '1'='1");
    assertThat(scannerConfig.getXssPayloads()).contains("<script>alert('XSS')</script>");
    assertThat(scannerConfig.getSensitivePatterns()).containsKey("email");
    assertThat(scannerConfig.getScanSettings().getMaxDepth()).isEqualTo(2);
    assertThat(scannerConfig.getScanSettings().getTimeoutSeconds()).isEqualTo(15);
    assertThat(scannerConfig.getCsrfSettings().isTestForms()).isTrue();
    assertThat(scannerConfig.getCsrfSettings().getMinimumTokenLength()).isEqualTo(8);
  }

  @Test
  void testNestedConfiguration() {
    assertThat(scannerConfig.getScanSettings()).isNotNull();
    assertThat(scannerConfig.getCsrfSettings()).isNotNull();

    // Test nested properties
    assertThat(scannerConfig.getScanSettings().getMaxDepth()).isEqualTo(2);
    assertThat(scannerConfig.getScanSettings().getTimeoutSeconds()).isEqualTo(15);
    assertThat(scannerConfig.getCsrfSettings().isTestForms()).isTrue();
    assertThat(scannerConfig.getCsrfSettings().getMinimumTokenLength()).isEqualTo(8);
  }
}
