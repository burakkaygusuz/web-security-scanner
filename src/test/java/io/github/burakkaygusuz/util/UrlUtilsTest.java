package io.github.burakkaygusuz.util;

import org.junit.jupiter.api.Test;
import org.assertj.core.api.SoftAssertions;
import java.util.Map;
import static org.assertj.core.api.Assertions.*;

class UrlUtilsTest {

    @Test
    void testParseParametersWithValidQuery() {
        String query = "id=123&name=john&email=john@example.com";
        Map<String, String> params = UrlUtils.parseParameters(query);
        
        assertThat(params)
            .hasSize(3)
            .containsEntry("id", "123")
            .containsEntry("name", "john")
            .containsEntry("email", "john@example.com");
    }

    @Test
    void testParseParametersWithEmptyQuery() {
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(UrlUtils.parseParameters("")).isEmpty();
            softly.assertThat(UrlUtils.parseParameters(null)).isEmpty();
        });
    }

    @Test
    void testParseParametersWithValuelessParameter() {
        String query = "id=123&flag&name=john";
        Map<String, String> params = UrlUtils.parseParameters(query);
        
        assertThat(params)
            .hasSize(3)
            .containsEntry("id", "123")
            .containsEntry("flag", "")
            .containsEntry("name", "john");
    }

    @Test
    void testParseParametersWithEmptyParameter() {
        String query = "id=123&&name=john";
        Map<String, String> params = UrlUtils.parseParameters(query);
        
        assertThat(params)
            .hasSize(2)
            .containsEntry("id", "123")
            .containsEntry("name", "john");
    }

    @Test
    void testParseParametersWithEmptyKey() {
        String query = "=value&id=123";
        Map<String, String> params = UrlUtils.parseParameters(query);
        
        assertThat(params)
            .hasSize(1)
            .containsEntry("id", "123");
    }

    @Test
    void testParseParametersWithSpecialCharacters() {
        String query = "search=hello+world&filter=category%3Dbooks";
        Map<String, String> params = UrlUtils.parseParameters(query);
        
        assertThat(params)
            .hasSize(2)
            .containsEntry("search", "hello+world")
            .containsEntry("filter", "category%3Dbooks");
    }

    @Test
    void testBuildTestUrlWithValidUrl() {
        String originalUrl = "https://example.com/search?id=123&name=john";
        String testUrl = UrlUtils.buildTestUrl(originalUrl, "id", "999");
        
        assertThat(testUrl)
            .contains("id=999")
            .contains("name=john")
            .startsWith("https://example.com/search");
    }

    @Test
    void testBuildTestUrlWithNewParameter() {
        String originalUrl = "https://example.com/search?id=123";
        String testUrl = UrlUtils.buildTestUrl(originalUrl, "newParam", "newValue");
        
        assertThat(testUrl)
            .contains("id=123")
            .contains("newParam=newValue");
    }

    @Test
    void testBuildTestUrlWithNoQuery() {
        String originalUrl = "https://example.com/search";
        String testUrl = UrlUtils.buildTestUrl(originalUrl, "id", "123");
        
        assertThat(testUrl).isEqualTo(originalUrl);
    }

    @Test
    void testBuildTestUrlWithInvalidUrl() {
        String invalidUrl = "not-a-valid-url";
        String testUrl = UrlUtils.buildTestUrl(invalidUrl, "id", "123");
        
        assertThat(testUrl).isEqualTo(invalidUrl);
    }

    @Test
    void testIsValidUrlWithValidUrls() {
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(UrlUtils.isValidUrl("https://example.com")).isTrue();
            softly.assertThat(UrlUtils.isValidUrl("http://example.com")).isTrue();
            softly.assertThat(UrlUtils.isValidUrl("https://example.com/path")).isTrue();
            softly.assertThat(UrlUtils.isValidUrl("https://example.com:8080/path?param=value")).isTrue();
            softly.assertThat(UrlUtils.isValidUrl("http://localhost:3000")).isTrue();
            softly.assertThat(UrlUtils.isValidUrl("https://sub.example.com")).isTrue();
        });
    }

    @Test
    void testIsValidUrlWithInvalidUrls() {
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(UrlUtils.isValidUrl(null)).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("   ")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("not-a-url")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("ftp://example.com")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("://example.com")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("https://")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("example.com")).isFalse();
        });
    }

    @Test
    void testIsValidUrlWithEdgeCases() {
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(UrlUtils.isValidUrl("https:// example.com")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("https://[invalid")).isFalse();
            softly.assertThat(UrlUtils.isValidUrl("  https://example.com  ")).isTrue();
        });
    }

    @Test
    void testBuildTestUrlPreservesFragment() {
        String originalUrl = "https://example.com/search?id=123#section1";
        String testUrl = UrlUtils.buildTestUrl(originalUrl, "id", "999");
        
        assertThat(testUrl)
            .contains("id=999")
            .contains("#section1");
    }

    @Test
    void testBuildTestUrlWithMultipleEqualSigns() {
        String originalUrl = "https://example.com/search?data=key=value&id=123";
        String testUrl = UrlUtils.buildTestUrl(originalUrl, "id", "999");
        
        assertThat(testUrl)
            .contains("id=999")
            .contains("data=key=value");
    }

    @Test
    void testParseParametersWithMultipleEqualSigns() {
        String query = "data=key=value&config=a=b=c";
        Map<String, String> params = UrlUtils.parseParameters(query);
        
        assertThat(params)
            .hasSize(2)
            .containsEntry("data", "key=value")
            .containsEntry("config", "a=b=c");
    }
}
