package io.github.burakkaygusuz.service;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class HttpClientService {

  private static final org.slf4j.Logger logger =
      org.slf4j.LoggerFactory.getLogger(HttpClientService.class);

  private static final long MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB

  private static final Map<String, String> BROWSER_HEADERS =
      Map.ofEntries(
          Map.entry(
              "User-Agent",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
          Map.entry(
              "Accept",
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
          Map.entry("Accept-Language", "en-US,en;q=0.5"),
          Map.entry("DNT", "1"),
          Map.entry("Connection", "keep-alive"),
          Map.entry("Upgrade-Insecure-Requests", "1"));

  private final OkHttpClient httpClient;
  private final RateLimiter rateLimiter;

  public HttpClientService(ScannerConfig config) {
    this.httpClient =
        new OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(config.scanSettings().timeoutSeconds(), TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .retryOnConnectionFailure(true)
            .addInterceptor(
                chain -> {
                  Request originalRequest = chain.request();
                  Request newRequest = addBrowserHeaders(originalRequest);
                  return chain.proceed(newRequest);
                })
            .build();

    RateLimiterConfig rateLimiterConfig =
        RateLimiterConfig.custom()
            .limitForPeriod(3)
            .limitRefreshPeriod(Duration.ofSeconds(1))
            .timeoutDuration(Duration.ofSeconds(30))
            .build();
    this.rateLimiter = RateLimiter.of("scanner-rate-limiter", rateLimiterConfig);
  }

  public Response executeRequest(String url) throws IOException {
    Request request = new Request.Builder().url(url).build();
    return httpClient.newCall(request).execute();
  }

  public Response executeRequestWithRateLimit(String url) throws IOException {
    return rateLimiter.executeSupplier(
        () -> {
          try {
            return executeRequest(url);
          } catch (Exception e) {
            if (e instanceof IOException ioe) {
              throw new RuntimeException("HTTP request failed: " + ioe.getMessage(), ioe);
            } else if (e instanceof RuntimeException re) {
              throw re;
            } else {
              throw new RuntimeException("Unexpected error during HTTP request", e);
            }
          }
        });
  }

  public String safeReadResponse(Response response) throws IOException {
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
      return true;
    }

    String lowerContentType = contentType.toLowerCase();
    return lowerContentType.contains("text/")
        || lowerContentType.contains("application/json")
        || lowerContentType.contains("application/xml")
        || lowerContentType.contains("application/xhtml+xml");
  }

  private Request addBrowserHeaders(Request originalRequest) {
    Request.Builder builder = originalRequest.newBuilder();
    BROWSER_HEADERS.forEach(builder::header);
    return builder.build();
  }

  public void close() {
    if (httpClient.cache() != null) {
      try {
        httpClient.cache().close();
      } catch (IOException e) {
        logger.warn("Error closing HTTP client cache: {}", e.getMessage());
      }
    }
    httpClient.connectionPool().evictAll();
  }
}
