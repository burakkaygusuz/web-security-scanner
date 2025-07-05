package io.github.burakkaygusuz;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class WebSecurityScanner {

  private final String targetUrl;
  private final String targetHost;
  private final int maxDepth;

  private final Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
  private final List<Vulnerability> vulnerabilities = new ArrayList<>();

  private final OkHttpClient httpClient;
  private final ExecutorService executor = Executors.newFixedThreadPool(10);

  private static final String RESET = "\u001B[0m";
  private static final String RED = "\u001B[31m";
  private static final String GREEN = "\u001B[32m";
  private static final String BLUE = "\u001B[34m";

  public WebSecurityScanner(String targetUrl, int maxDepth) {
    this.targetUrl = targetUrl;
    this.maxDepth = maxDepth;
    try {
      this.targetHost = new URI(targetUrl).getHost();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid target URL: " + targetUrl, e);
    }
    this.httpClient = new OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build();
  }

  public WebSecurityScanner(String targetUrl) {
    this(targetUrl, 3);
  }

  public List<Vulnerability> scan() {
    System.out.println(BLUE + "\nStarting security scan of " + targetUrl + RESET + "\n");

    crawl(targetUrl, 0);

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
        System.err.println("OkHttp dispatcher did not terminate in 5 seconds. Forcing shutdown...");
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
        System.err.println("Error closing OkHttp cache: " + e.getMessage());
      }
    }
  }

  private void crawl(String url, int depth) {
    if (depth > maxDepth || !visitedUrls.add(url)) {
      return;
    }

    System.out.println("Crawling: " + url);
    executor.submit(() -> {
      checkSqlInjection(url);
      checkXss(url);
      checkSensitiveInfo(url);
    });

    try {
      Request request = new Request.Builder().url(url).build();
      Response response = httpClient.newCall(request).execute();
      String contentType = response.header("Content-Type");

      if (contentType != null && contentType.toLowerCase().contains("text/html")) {
        String html = response.body().string();
        Document doc = Jsoup.parse(html, url);
        Elements links = doc.select("a[href]");

        for (Element link : links) {
          String nextUrl = link.absUrl("href");
          if (nextUrl.isBlank()) {
            continue;
          }
          try {
            URI nextUri = new URI(nextUrl);
            if (targetHost.equalsIgnoreCase(nextUri.getHost())) {
              crawl(nextUrl, depth + 1);
            }
          } catch (URISyntaxException e) {
            // Ignore malformed URLs
          }
        }
      }
    } catch (IOException e) {
      System.err.println("Error crawling " + url + ": " + e.getMessage());
    }
  }

  private void checkSensitiveInfo(String url) {
    Map<String, Pattern> sensitivePatterns = new HashMap<>();
    sensitivePatterns.put("email", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"));
    sensitivePatterns.put("phone", Pattern.compile("\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b"));
    sensitivePatterns.put("ssn", Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"));
    sensitivePatterns.put("api_key",
        Pattern.compile("api[_-]?key[_-]?(['\"`])([a-zA-Z0-9]{32,45})\\1",
            Pattern.CASE_INSENSITIVE));

    try {
      Request request = new Request.Builder().url(url).build();
      Response response = httpClient.newCall(request).execute();
      String responseText = response.body().string();

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
    } catch (Exception e) {
      // System.err.println("Error checking sensitive information on " + url + ": " +
      // e.getMessage());
    }
  }

  private void checkXss(String url) {
    String[] xssPayloads = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    };

    for (String payload : xssPayloads) {
      try {
        URI uri = new URI(url);
        String query = uri.getQuery();

        if (query != null) {
          String[] params = query.split("&");
          for (String param : params) {
            String[] keyValue = param.split("=");
            if (keyValue.length == 2) {
              String encodedPayload = java.net.URLEncoder.encode(payload, "UTF-8");
              String testUrl = url.replace(param, keyValue[0] + "=" + encodedPayload);

              Request request = new Request.Builder().url(testUrl).build();
              Response response = httpClient.newCall(request).execute();
              String responseText = response.body().string();

              if (responseText.contains(payload)) {
                reportVulnerability(new Vulnerability(
                    "Cross-Site Scripting (XSS)",
                    url,
                    keyValue[0],
                    payload));
              }
            }
          }
        }
      } catch (Exception e) {
        // System.err.println("Error testing XSS on " + url + ": " + e.getMessage());
      }
    }
  }

  private void checkSqlInjection(String url) {
    String[] sqlPayloads = { "'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--" };

    for (String payload : sqlPayloads) {
      try {
        URI uri = new URI(url);
        String query = uri.getQuery();

        if (query != null) {
          String[] params = query.split("&");
          for (String param : params) {
            String[] keyValue = param.split("=");
            if (keyValue.length == 2) {
              String testUrl = url.replace(param, keyValue[0] + "=" + payload);

              Request request = new Request.Builder().url(testUrl).build();
              Response response = httpClient.newCall(request).execute();
              String responseText = response.body().string().toLowerCase();

              if (responseText.contains("sql") || responseText.contains("mysql") ||
                  responseText.contains("sqlite") || responseText.contains("postgresql") ||
                  responseText.contains("oracle")) {

                reportVulnerability(new Vulnerability(
                    "SQL Injection",
                    url,
                    keyValue[0],
                    payload));
              }
            }
          }
        }
      } catch (Exception e) {
        // System.err.println("Error testing SQL injection on " + url + ": " +
        // e.getMessage());
      }
    }
  }

  private synchronized void reportVulnerability(Vulnerability vulnerability) {
    if (vulnerabilities.stream().noneMatch(v -> v.equals(vulnerability))) {
      vulnerabilities.add(vulnerability);
      System.out.println(RED + "[VULNERABILITY FOUND]" + RESET);
      System.out.println("Type: " + vulnerability.type());
      System.out.println("URL: " + vulnerability.url());
      System.out.println("Parameter: " + vulnerability.parameter());
      System.out.println("Payload: " + vulnerability.payload());
      System.out.println();
    }
  }

  public int getVisitedUrlsCount() {
    return visitedUrls.size();
  }
}