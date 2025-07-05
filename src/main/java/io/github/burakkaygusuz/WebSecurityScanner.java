package io.github.burakkaygusuz;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.burakkaygusuz.config.ConfigLoader;
import io.github.burakkaygusuz.config.ScannerConfig;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;

public class WebSecurityScanner {

  private static final Logger logger = LoggerFactory.getLogger(WebSecurityScanner.class);
  private static final long MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB
  
  private static final Map<String, String> BROWSER_HEADERS = Map.ofEntries(
      Map.entry("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
      Map.entry("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
      Map.entry("Accept-Language", "en-US,en;q=0.5"),
      Map.entry("DNT", "1"),
      Map.entry("Connection", "keep-alive"),
      Map.entry("Upgrade-Insecure-Requests", "1")
  );

  private final String targetUrl;
  private final String targetHost;
  private final int maxDepth;

  private final Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
  private final List<Vulnerability> vulnerabilities = Collections.synchronizedList(new ArrayList<>());
  private final List<CompletableFuture<Void>> vulnerabilityTasks = Collections.synchronizedList(new ArrayList<>());

  private final OkHttpClient httpClient;
  private final ExecutorService executor;
  private final ScannerConfig config;
  private final RateLimiter rateLimiter;

  public WebSecurityScanner(String targetUrl) {
    this.config = ConfigLoader.loadConfig();
    
    if (!isValidUrl(targetUrl)) {
      throw new IllegalArgumentException("Invalid target URL: " + targetUrl);
    }
    
    this.targetUrl = targetUrl;
    this.maxDepth = this.config.scanSettings().maxDepth();
    
    try {
      URI uri = new URI(targetUrl);
      this.targetHost = uri.getHost();
      if (this.targetHost == null) {
        throw new IllegalArgumentException("URL must have a valid host: " + targetUrl);
      }
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid target URL: " + targetUrl, e);
    }
    
    this.httpClient = new OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(config.scanSettings().timeoutSeconds(), TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .retryOnConnectionFailure(true)
        .addInterceptor(chain -> {
          Request originalRequest = chain.request();
          Request newRequest = addBrowserHeaders(originalRequest);
          return chain.proceed(newRequest);
        })
        .build();
    
    this.executor = Executors.newFixedThreadPool(10);
    
    RateLimiterConfig rateLimiterConfig = RateLimiterConfig.custom()
        .limitForPeriod(3)
        .limitRefreshPeriod(Duration.ofSeconds(1))
        .timeoutDuration(Duration.ofSeconds(30)) // 3 requests per second
        .build();
    this.rateLimiter = RateLimiter.of("scanner-rate-limiter", rateLimiterConfig);
  }

  public List<Vulnerability> scan() {
    logger.info("\nStarting security scan of {}\n", targetUrl);

    crawl(targetUrl, 0);

    logger.info("Waiting for {} vulnerability checks to complete...", vulnerabilityTasks.size());
    CompletableFuture.allOf(vulnerabilityTasks.toArray(new CompletableFuture[0]))
        .orTimeout(120, TimeUnit.SECONDS)
        .join();

    executor.shutdown();
    
    try {
      if (!executor.awaitTermination(60, TimeUnit.MINUTES)) {
        executor.shutdownNow();
      }
    } catch (InterruptedException e) {
      executor.shutdownNow();
    }

    return vulnerabilities;
  }

  public void close() {
    ExecutorService okHttpExecutor = httpClient.dispatcher().executorService();
    okHttpExecutor.shutdown();
    try {
      if (!okHttpExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
        logger.warn("OkHttp dispatcher did not terminate in 5 seconds. Forcing shutdown...");
        okHttpExecutor.shutdownNow();
      }
    } catch (InterruptedException e) {
      okHttpExecutor.shutdownNow();
      Thread.currentThread().interrupt();
    }
    httpClient.connectionPool().evictAll();
    if (httpClient.cache() != null) {
      try {
        httpClient.cache().close();
      } catch (IOException e) {
        logger.error("Error closing OkHttp cache: {}", e.getMessage());
      }
    }
  }

  private void crawl(String url, int depth) {
    if (depth > maxDepth || !visitedUrls.add(url)) {
      return;
    }

    logger.info("Crawling: {}", url);
    
    vulnerabilityTasks.add(CompletableFuture.runAsync(() -> checkSqlInjection(url), executor));
    vulnerabilityTasks.add(CompletableFuture.runAsync(() -> checkXss(url), executor));
    vulnerabilityTasks.add(CompletableFuture.runAsync(() -> checkSensitiveInfo(url), executor));

    try {
      Request request = new Request.Builder().url(url).build();
      try (Response response = httpClient.newCall(request).execute()) {
        if (!response.isSuccessful()) {
          logger.warn("Non-successful response for {}: {}", url, response.code());
          return;
        }
        
        String contentType = response.header("Content-Type", "");
        if (contentType.toLowerCase().contains("text/html") || 
            contentType.toLowerCase().contains("application/xhtml+xml")) {
          
          String html = safeReadResponse(response);
          if (!html.isEmpty()) {
            Document doc = Jsoup.parse(html, url);
            Elements links = doc.select("a[href]");
            logger.info("Found {} links on page: {}", links.size(), url);
            

            for (Element link : links) {
              String nextUrl = link.absUrl("href");
              if (nextUrl.isBlank()) {
                continue;
              }
              try {
                URI nextUri = new URI(nextUrl);
                if (targetHost.equalsIgnoreCase(nextUri.getHost())) {
                  logger.info("Following link: {} (depth {})", nextUrl, depth + 1);
                  crawl(nextUrl, depth + 1);
                }
              } catch (URISyntaxException e) {
                logger.warn("Malformed URL encountered while crawling: {} ({})", nextUrl, e.getMessage());
              }
            }
          }
        }
      }
    } catch (IOException e) {
      logger.error("Error crawling {}: {}", url, e.getMessage());
    }
  }

  private void checkSensitiveInfo(String url) {
    Map<String, Pattern> sensitivePatterns = new HashMap<>();
    
    for (Map.Entry<String, String> entry : config.sensitivePatterns().entrySet()) {
      try {
        Pattern pattern = Pattern.compile(entry.getValue(), Pattern.CASE_INSENSITIVE);
        sensitivePatterns.put(entry.getKey(), pattern);
      } catch (Exception e) {
        logger.warn("Invalid regex pattern for {}: {}", entry.getKey(), entry.getValue());
      }
    }

    try {
      rateLimiter.executeSupplier(() -> {
        try {
          Request request = new Request.Builder().url(url).build();
          try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
              return null;
            }
            
            String responseText = safeReadResponse(response);
            if (responseText.isEmpty()) {
              return null;
            }

            for (Map.Entry<String, Pattern> entry : sensitivePatterns.entrySet()) {
              Pattern pattern = entry.getValue();
              Matcher matcher = pattern.matcher(responseText);

              while (matcher.find()) {
                reportVulnerability(new Vulnerability(
                    "Sensitive Information Exposure",
                    url,
                    entry.getKey(),
                    entry.getValue().pattern()));
              }
            }
          }
        } catch (Exception e) {
          logger.warn("Error checking sensitive info on {}: {}", url, e.getMessage());
        }
        return null;
      });
    } catch (Exception e) {
      logger.warn("Error with rate limiter for sensitive info check on {}: {}", url, e.getMessage());
    }
  }

  private void checkXss(String url) {
    List<String> xssPayloads = config.xssPayloads();

    for (String payload : xssPayloads) {
      try {
        URI uri = new URI(url);
        String query = uri.getQuery();

        if (query != null) {
          Map<String, String> params = parseParameters(query);
          
          for (Map.Entry<String, String> param : params.entrySet()) {
            try {
              String encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
              String testUrl = buildTestUrl(url, param.getKey(), encodedPayload);

              rateLimiter.executeSupplier(() -> {
                try {
                  Request request = new Request.Builder().url(testUrl).build();
                  try (Response response = httpClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                      return null;
                    }
                    
                    String responseText = safeReadResponse(response);
                    if (responseText.contains(payload)) {
                      reportVulnerability(new Vulnerability(
                          "Cross-Site Scripting (XSS)",
                          url,
                          param.getKey(),
                          payload));
                    }
                  }
                } catch (Exception e) {
                  logger.warn("Error testing XSS payload on parameter {}: {}", param.getKey(), e.getMessage());
                }
                return null;
              });
            } catch (Exception e) {
              logger.warn("Error with rate limiter for XSS test on parameter {}: {}", param.getKey(), e.getMessage());
            }
          }
        }
      } catch (Exception e) {
        logger.warn("Error checking XSS on {}: {}", url, e.getMessage());
      }
    }
  }

  private void checkSqlInjection(String url) {
    List<String> sqlPayloads = config.sqlPayloads();

    for (String payload : sqlPayloads) {
      try {
        String query = new URI(url).getQuery();

        if (query != null) {
          Map<String, String> params = parseParameters(query);
          
          for (Map.Entry<String, String> param : params.entrySet()) {
            try {
              String testUrl = buildTestUrl(url, param.getKey(), payload);

              rateLimiter.executeSupplier(() -> {
                try {
                  Request request = new Request.Builder().url(testUrl).build();
                  try (Response response = httpClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                      return null;
                    }
                    
                    String responseText = safeReadResponse(response).toLowerCase();
                    if (containsSqlErrorIndicators(responseText)) {
                      reportVulnerability(new Vulnerability(
                          "SQL Injection",
                          url,
                          param.getKey(),
                          payload));
                    }
                  }
                } catch (Exception e) {
                  logger.warn("Error testing SQL payload on parameter {}: {}", param.getKey(), e.getMessage());
                }
                return null;
              });
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

  private synchronized void reportVulnerability(Vulnerability vulnerability) {
    if (vulnerabilities.stream().noneMatch(v -> v.equals(vulnerability))) {
      vulnerabilities.add(vulnerability);    
    }
  }

  public int getVisitedUrlsCount() {
    return visitedUrls.size();
  }


  private boolean isValidUrl(String url) {
    if (url == null || url.trim().isEmpty()) {
      return false;
    }
    
    try {
      URI uri = new URI(url.trim());
      String scheme = uri.getScheme();
      String host = uri.getHost();
      
      return host != null && 
             ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private String safeReadResponse(Response response) throws IOException {
    if (response.body() == null) {
      return "";
    }
    
    String contentType = response.header("Content-Type", "");
    if (!isSafeContentType(contentType)) {
      return "";
    }
    
    long contentLength = response.body().contentLength();
    if (contentLength > MAX_RESPONSE_SIZE) {
      throw new IOException("Response too large: " + contentLength + " bytes");
    }
    
    return response.body().string();
  }

  private boolean isSafeContentType(String contentType) {
    if (contentType == null || contentType.isEmpty()) {
      return true; // Default to safe if unknown
    }
    
    String lowerContentType = contentType.toLowerCase();
    return lowerContentType.contains("text/") || 
           lowerContentType.contains("application/json") ||
           lowerContentType.contains("application/xml") ||
           lowerContentType.contains("application/xhtml+xml");
  }

  private Map<String, String> parseParameters(String query) {
    Map<String, String> params = new HashMap<>();
    if (query == null || query.isEmpty()) {
      return params;
    }
    
    for (String param : query.split("&")) {
      if (param.isEmpty()) continue;
      
      String[] parts = param.split("=", 2);
      String key = parts[0];
      String value = parts.length > 1 ? parts[1] : "";
      
      if (!key.isEmpty()) {
        params.put(key, value);
      }
    }
    return params;
  }

  private String buildTestUrl(String originalUrl, String paramKey, String newValue) {
    try {
      URI uri = new URI(originalUrl);
      String query = uri.getQuery();
      
      if (query == null) {
        return originalUrl;
      }
      
      Map<String, String> params = parseParameters(query);
      params.put(paramKey, newValue);
      
      StringBuilder newQuery = new StringBuilder();
      for (Map.Entry<String, String> entry : params.entrySet()) {
        if (newQuery.length() > 0) {
          newQuery.append("&");
        }
        newQuery.append(entry.getKey()).append("=").append(entry.getValue());
      }
      
      return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), 
                     newQuery.toString(), uri.getFragment()).toString();
    } catch (URISyntaxException e) {
      logger.warn("Error building test URL: {}", e.getMessage());
      return originalUrl;
    }
  }

  private boolean containsSqlErrorIndicators(String responseText) {
    String[] sqlErrorIndicators = {
        "sql", "mysql", "sqlite", "postgresql", "oracle", "mariadb",
        "syntax error", "mysql_fetch", "mysql_query", "warning:", "error:",
        "odbc", "microsoft access", "jdbc", "ora-", "sql server"
    };
    
    for (String indicator : sqlErrorIndicators) {
      if (responseText.contains(indicator)) {
        return true;
      }
    }
    return false;
  }


  private Request addBrowserHeaders(Request originalRequest) {
    Request.Builder builder = originalRequest.newBuilder();
    BROWSER_HEADERS.forEach(builder::header);
    
    return builder.build();
  }

}
