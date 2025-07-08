package io.github.burakkaygusuz.config;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ScannerConfigTest {

    @Test
    void testValidScannerConfig() {
        List<String> sqlPayloads = List.of("'", "1' OR '1'='1");
        List<String> xssPayloads = List.of("<script>alert('XSS')</script>");
        Map<String, String> sensitivePatterns = Map.of("email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        ScanSettings scanSettings = ScanSettings.defaultSettings();
        
        ScannerConfig config = new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
        
        assertEquals(sqlPayloads, config.sqlPayloads());
        assertEquals(xssPayloads, config.xssPayloads());
        assertEquals(sensitivePatterns, config.sensitivePatterns());
        assertEquals(scanSettings, config.scanSettings());
    }

    @Test
    void testNullSqlPayloads() {
        assertThrows(NullPointerException.class, () -> {
            new ScannerConfig(null, List.of("<script>"), Map.of(), ScanSettings.defaultSettings());
        });
    }

    @Test
    void testNullXssPayloads() {
        assertThrows(NullPointerException.class, () -> {
            new ScannerConfig(List.of("'"), null, Map.of(), ScanSettings.defaultSettings());
        });
    }

    @Test
    void testNullSensitivePatterns() {
        assertThrows(NullPointerException.class, () -> {
            new ScannerConfig(List.of("'"), List.of("<script>"), null, ScanSettings.defaultSettings());
        });
    }

    @Test
    void testNullScanSettings() {
        assertThrows(NullPointerException.class, () -> {
            new ScannerConfig(List.of("'"), List.of("<script>"), Map.of(), null);
        });
    }

    @Test
    void testEmptyCollections() {
        List<String> emptyList = List.of();
        Map<String, String> emptyMap = Map.of();
        ScanSettings scanSettings = ScanSettings.defaultSettings();
        
        ScannerConfig config = new ScannerConfig(emptyList, emptyList, emptyMap, scanSettings);
        
        assertTrue(config.sqlPayloads().isEmpty());
        assertTrue(config.xssPayloads().isEmpty());
        assertTrue(config.sensitivePatterns().isEmpty());
        assertEquals(scanSettings, config.scanSettings());
    }

    @Test
    void testImmutability() {
        List<String> sqlPayloads = List.of("'", "1' OR '1'='1");
        List<String> xssPayloads = List.of("<script>alert('XSS')</script>");
        Map<String, String> sensitivePatterns = Map.of("email", "test@example.com");
        ScanSettings scanSettings = ScanSettings.defaultSettings();
        
        ScannerConfig config = new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
        
        // Lists and maps should be immutable
        assertThrows(UnsupportedOperationException.class, () -> {
            config.sqlPayloads().add("new payload");
        });
        
        assertThrows(UnsupportedOperationException.class, () -> {
            config.xssPayloads().add("new payload");
        });
        
        assertThrows(UnsupportedOperationException.class, () -> {
            config.sensitivePatterns().put("new", "pattern");
        });
    }

    @Test
    void testEquality() {
        List<String> sqlPayloads = List.of("'");
        List<String> xssPayloads = List.of("<script>");
        Map<String, String> sensitivePatterns = Map.of("email", "pattern");
        ScanSettings scanSettings = ScanSettings.defaultSettings();
        
        ScannerConfig config1 = new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
        ScannerConfig config2 = new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
        ScannerConfig config3 = new ScannerConfig(List.of("different"), xssPayloads, sensitivePatterns, scanSettings);
        
        assertEquals(config1, config2);
        assertNotEquals(config1, config3);
        assertEquals(config1.hashCode(), config2.hashCode());
    }

    @Test
    void testToString() {
        List<String> sqlPayloads = List.of("'");
        List<String> xssPayloads = List.of("<script>");
        Map<String, String> sensitivePatterns = Map.of("email", "pattern");
        ScanSettings scanSettings = ScanSettings.defaultSettings();
        
        ScannerConfig config = new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
        String toString = config.toString();
        
        assertTrue(toString.contains("ScannerConfig"));
        assertTrue(toString.contains("sqlPayloads"));
        assertTrue(toString.contains("xssPayloads"));
        assertTrue(toString.contains("sensitivePatterns"));
        assertTrue(toString.contains("scanSettings"));
    }

    @Test
    void testWithComplexData() {
        List<String> sqlPayloads = List.of(
            "'",
            "1' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--"
        );
        
        List<String> xssPayloads = List.of(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        );
        
        Map<String, String> sensitivePatterns = Map.of(
            "email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            "phone", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b",
            "ssn", "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        );
        
        ScanSettings scanSettings = new ScanSettings(5, 60);
        
        ScannerConfig config = new ScannerConfig(sqlPayloads, xssPayloads, sensitivePatterns, scanSettings);
        
        assertEquals(4, config.sqlPayloads().size());
        assertEquals(3, config.xssPayloads().size());
        assertEquals(3, config.sensitivePatterns().size());
        assertEquals(5, config.scanSettings().maxDepth());
        assertEquals(60, config.scanSettings().timeoutSeconds());
    }
}
