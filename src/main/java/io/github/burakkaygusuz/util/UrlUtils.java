package io.github.burakkaygusuz.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UrlUtils {

  private static final Logger logger = LoggerFactory.getLogger(UrlUtils.class);

  /**
   * Builds form data string for an application/x-www-form-urlencoded request.
   *
   * @param inputs the map of form inputs
   * @param token optional CSRF token value
   * @param tokenName name of the CSRF token field
   * @return URL-encoded form data string
   */
  public static String buildFormData(Map<String, String> inputs, String token, String tokenName) {
    StringBuilder formDataBuilder = new StringBuilder();

    inputs.forEach(
        (key, value) -> {
          try {
            if (formDataBuilder.length() > 0) {
              formDataBuilder.append("&");
            }

            formDataBuilder
                .append(java.net.URLEncoder.encode(key, java.nio.charset.StandardCharsets.UTF_8))
                .append("=")
                .append(java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8));
          } catch (Exception e) {
            logger.warn("Error encoding form data: {}", e.getMessage());
          }
        });

    if (token != null && !inputs.containsKey(tokenName)) {
      try {
        if (formDataBuilder.length() > 0) {
          formDataBuilder.append('&');
        }
        formDataBuilder
            .append(java.net.URLEncoder.encode(tokenName, java.nio.charset.StandardCharsets.UTF_8))
            .append('=')
            .append(java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
      } catch (Exception e) {
        logger.warn("Error encoding CSRF token: {}", e.getMessage());
      }
    }

    return formDataBuilder.toString();
  }

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
