package io.github.burakkaygusuz.crawler;

import io.github.burakkaygusuz.config.ScannerConfig;
import io.github.burakkaygusuz.service.HttpClientService;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import okhttp3.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebCrawler {

  private static final Logger logger = LoggerFactory.getLogger(WebCrawler.class);

  private final String targetHost;
  private final int maxDepth;
  private final HttpClientService httpClientService;
  private final Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
  private final Consumer<String> urlFoundCallback;

  public WebCrawler(
      String targetUrl,
      ScannerConfig config,
      HttpClientService httpClientService,
      Consumer<String> urlFoundCallback) {
    this.httpClientService = httpClientService;
    this.maxDepth = config.scanSettings().getMaxDepth();
    this.urlFoundCallback = urlFoundCallback;

    try {
      URI uri = new URI(targetUrl);
      this.targetHost = uri.getHost();
      if (this.targetHost == null) {
        throw new IllegalArgumentException("URL must have a valid host: " + targetUrl);
      }
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid target URL: " + targetUrl, e);
    }
  }

  public void crawl(String url, int depth) {
    if (depth > maxDepth || !visitedUrls.add(url)) {
      return;
    }

    logger.info("Crawling: {}", url);

    if (urlFoundCallback != null) {
      urlFoundCallback.accept(url);
    }

    try {
      Response response = httpClientService.executeRequest(url);
      if (!response.isSuccessful()) {
        logger.warn("Non-successful response for {}: {}", url, response.code());
        return;
      }

      String contentType = response.header("Content-Type", "");
      if (contentType.toLowerCase().contains("text/html")
          || contentType.toLowerCase().contains("application/xhtml+xml")) {

        String html = httpClientService.safeReadResponse(response);
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
              logger.warn(
                  "Malformed URL encountered while crawling: {} ({})", nextUrl, e.getMessage());
            }
          }
        }
      }
      response.close();
    } catch (IOException e) {
      logger.error("Error crawling {}: {}", url, e.getMessage());
    }
  }

  public Set<String> getVisitedUrls() {
    return Collections.unmodifiableSet(visitedUrls);
  }

  public int getVisitedUrlsCount() {
    return visitedUrls.size();
  }
}
