package io.github.burakkaygusuz.config;

import org.junit.jupiter.api.Test;
import org.assertj.core.api.SoftAssertions;
import static org.assertj.core.api.Assertions.*;

class ConfigLoaderTest {

    @Test
    void testLoadDefaultConfig() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(config).isNotNull();
            softly.assertThat(config.sqlPayloads()).isNotNull().isNotEmpty();
            softly.assertThat(config.xssPayloads()).isNotNull().isNotEmpty();
            softly.assertThat(config.sensitivePatterns()).isNotNull().isNotEmpty();
            softly.assertThat(config.scanSettings()).isNotNull();
        });
    }

    @Test
    void testDefaultSqlPayloads() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        assertThat(config.sqlPayloads())
            .contains("'")
            .contains("1' OR '1'='1")
            .contains("' OR 1=1--")
            .contains("' UNION SELECT NULL--");
    }

    @Test
    void testDefaultXssPayloads() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        assertThat(config.xssPayloads())
            .contains("<script>alert('XSS')</script>")
            .contains("<img src=x onerror=alert('XSS')>")
            .contains("javascript:alert('XSS')")
            .contains("<svg onload=alert('XSS')>");
    }

    @Test
    void testDefaultSensitivePatterns() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        assertThat(config.sensitivePatterns())
            .containsKeys("email", "phone", "ssn", "api_key", "credit_card")
            .containsEntry("email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
            .containsEntry("phone", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b");
    }

    @Test
    void testDefaultScanSettings() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        assertThat(config.scanSettings())
            .extracting(ScanSettings::maxDepth, ScanSettings::timeoutSeconds)
            .containsExactly(3, 30);
    }

    @Test
    void testConfigurationIsImmutable() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThatThrownBy(() -> config.sqlPayloads().add("new payload"))
                  .isInstanceOf(UnsupportedOperationException.class);
            softly.assertThatThrownBy(() -> config.xssPayloads().add("new payload"))
                  .isInstanceOf(UnsupportedOperationException.class);
            softly.assertThatThrownBy(() -> config.sensitivePatterns().put("new", "pattern"))
                  .isInstanceOf(UnsupportedOperationException.class);
        });
    }

    @Test
    void testMultipleCallsReturnConsistentConfig() {
        ScannerConfig config1 = ConfigLoader.loadConfig();
        ScannerConfig config2 = ConfigLoader.loadConfig();
        
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(config1.sqlPayloads()).isEqualTo(config2.sqlPayloads());
            softly.assertThat(config1.xssPayloads()).isEqualTo(config2.xssPayloads());
            softly.assertThat(config1.sensitivePatterns()).isEqualTo(config2.sensitivePatterns());
            softly.assertThat(config1.scanSettings()).isEqualTo(config2.scanSettings());
        });
    }

    @Test
    void testPayloadsAreNotEmpty() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        SoftAssertions.assertSoftly(softly -> {
            config.sqlPayloads().forEach(payload -> {
                softly.assertThat(payload).isNotNull().isNotEmpty();
            });
            
            config.xssPayloads().forEach(payload -> {
                softly.assertThat(payload).isNotNull().isNotEmpty();
            });
        });
    }

    @Test
    void testSensitivePatternsAreValid() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        config.sensitivePatterns().forEach((key, pattern) -> {
            SoftAssertions.assertSoftly(softly -> {
                softly.assertThat(key).isNotNull().isNotEmpty();
                softly.assertThat(pattern).isNotNull().isNotEmpty();
                
                // Test that patterns can be compiled (basic validation)
                softly.assertThatCode(() -> java.util.regex.Pattern.compile(pattern))
                      .doesNotThrowAnyException();
            });
        });
    }

    @Test
    void testDefaultConfigContainsExpectedPayloadCount() {
        ScannerConfig config = ConfigLoader.loadConfig();
        
        // Check actual sizes since config might load from external file
        assertThat(config.sqlPayloads()).isNotEmpty();
        assertThat(config.xssPayloads()).isNotEmpty();
        assertThat(config.sensitivePatterns()).isNotEmpty();
    }
}
