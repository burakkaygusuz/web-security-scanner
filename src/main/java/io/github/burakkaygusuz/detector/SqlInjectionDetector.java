package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.Vulnerability;
import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import io.github.burakkaygusuz.util.UrlUtils;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class SqlInjectionDetector {
    
    private static final Logger logger = LoggerFactory.getLogger(SqlInjectionDetector.class);
    
    private final ScannerConfig config;
    private final HttpClientService httpClientService;
    private final ReportService reportService;
    
    public SqlInjectionDetector(ScannerConfig config, HttpClientService httpClientService, ReportService reportService) {
        this.config = config;
        this.httpClientService = httpClientService;
        this.reportService = reportService;
    }
    
    public void checkSqlInjection(String url) {
        List<String> sqlPayloads = config.sqlPayloads();

        for (String payload : sqlPayloads) {
            try {
                String query = new URI(url).getQuery();

                if (query != null) {
                    Map<String, String> params = UrlUtils.parseParameters(query);
                    
                    for (Map.Entry<String, String> param : params.entrySet()) {
                        try {
                            String testUrl = UrlUtils.buildTestUrl(url, param.getKey(), payload);

                            try (Response response = httpClientService.executeRequestWithRateLimit(testUrl)) {
                                if (!response.isSuccessful()) {
                                    continue;
                                }
                                
                                String responseText = httpClientService.safeReadResponse(response).toLowerCase();
                                if (containsSqlErrorIndicators(responseText)) {
                                    reportService.reportVulnerability(new Vulnerability(
                                        "SQL Injection",
                                        url,
                                        param.getKey(),
                                        payload));
                                }
                            }
                        } catch (Exception e) {
                            logger.warn("Error with rate limiter for SQL injection test on parameter {}: {}", param.getKey(), e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                logger.warn("Error checking SQL Injection on {}: {}", url, e.getMessage());
            }
        }
    }
    
    private boolean containsSqlErrorIndicators(String responseText) {
        String sqlErrorPatterns = """
            sql mysql sqlite postgresql oracle mariadb
            syntax error mysql_fetch mysql_query warning: error:
            odbc microsoft access jdbc ora- sql server
            """;
        
        return sqlErrorPatterns.lines()
            .flatMap(line -> java.util.Arrays.stream(line.split("\\s+")))
            .filter(indicator -> !indicator.isEmpty())
            .anyMatch(responseText::contains);
    }
}
