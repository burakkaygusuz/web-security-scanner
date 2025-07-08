package io.github.burakkaygusuz.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ScanSettingsTest {

    @Test
    void testValidScanSettings() {
        ScanSettings settings = new ScanSettings(5, 30);
        
        assertEquals(5, settings.maxDepth());
        assertEquals(30, settings.timeoutSeconds());
    }

    @Test
    void testMinimumValidValues() {
        ScanSettings settings = new ScanSettings(1, 1);
        
        assertEquals(1, settings.maxDepth());
        assertEquals(1, settings.timeoutSeconds());
    }

    @Test
    void testInvalidMaxDepthZero() {
        assertThrows(IllegalArgumentException.class, () -> {
            new ScanSettings(0, 30);
        });
    }

    @Test
    void testInvalidMaxDepthNegative() {
        assertThrows(IllegalArgumentException.class, () -> {
            new ScanSettings(-1, 30);
        });
    }

    @Test
    void testInvalidTimeoutZero() {
        assertThrows(IllegalArgumentException.class, () -> {
            new ScanSettings(5, 0);
        });
    }

    @Test
    void testInvalidTimeoutNegative() {
        assertThrows(IllegalArgumentException.class, () -> {
            new ScanSettings(5, -1);
        });
    }

    @Test
    void testDefaultSettings() {
        ScanSettings defaultSettings = ScanSettings.defaultSettings();
        
        assertEquals(3, defaultSettings.maxDepth());
        assertEquals(30, defaultSettings.timeoutSeconds());
    }

    @Test
    void testDefaultSettingsAreValid() {
        assertDoesNotThrow(() -> {
            ScanSettings.defaultSettings();
        });
    }

    @Test
    void testEquality() {
        ScanSettings settings1 = new ScanSettings(3, 30);
        ScanSettings settings2 = new ScanSettings(3, 30);
        ScanSettings settings3 = new ScanSettings(5, 30);
        
        assertEquals(settings1, settings2);
        assertNotEquals(settings1, settings3);
        assertEquals(settings1.hashCode(), settings2.hashCode());
    }

    @Test
    void testToString() {
        ScanSettings settings = new ScanSettings(3, 30);
        String toString = settings.toString();
        
        assertTrue(toString.contains("3"));
        assertTrue(toString.contains("30"));
        assertTrue(toString.contains("ScanSettings"));
    }

    @Test
    void testLargeValues() {
        ScanSettings settings = new ScanSettings(Integer.MAX_VALUE, Integer.MAX_VALUE);
        
        assertEquals(Integer.MAX_VALUE, settings.maxDepth());
        assertEquals(Integer.MAX_VALUE, settings.timeoutSeconds());
    }
}
