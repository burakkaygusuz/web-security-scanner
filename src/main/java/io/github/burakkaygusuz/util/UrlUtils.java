package io.github.burakkaygusuz.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UrlUtils {

  private static final Logger logger = LoggerFactory.getLogger(UrlUtils.class);

  public static Map<String, String> parseParameters(String query) {
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

  public static String buildTestUrl(String originalUrl, String paramKey, String newValue) {
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

      return new URI(
              uri.getScheme(),
              uri.getAuthority(),
              uri.getPath(),
              newQuery.toString(),
              uri.getFragment())
          .toString();
    } catch (URISyntaxException e) {
      logger.warn("Error building test URL: {}", e.getMessage());
      return originalUrl;
    }
  }

  public static boolean isValidUrl(String url) {
    if (url == null || url.trim().isEmpty()) {
      return false;
    }

    try {
      URI uri = new URI(url.trim());
      String scheme = uri.getScheme();
      String host = uri.getHost();

      return host != null && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
    } catch (URISyntaxException e) {
      return false;
    }
  }
}
