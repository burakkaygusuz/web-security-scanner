package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.CsrfSettings;
import io.github.burakkaygusuz.model.FormData;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wrapper class for CsrfDetector to implement VulnerabilityDetector interface. Follows Adapter
 * Pattern to make existing detector compatible with the interface.
 *
 * <p>This implementation provides a simplified form extraction for CSRF detection.
 */
public class CsrfDetectorWrapper implements VulnerabilityDetector {

  private static final Logger logger = LoggerFactory.getLogger(CsrfDetectorWrapper.class);

  private final CsrfDetector detector;
  private final HttpClientService httpClientService;

  private static final Pattern FORM_PATTERN =
      Pattern.compile("<form[^>]*>(.*?)</form>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  private static final Pattern ACTION_PATTERN =
      Pattern.compile("action\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  private static final Pattern METHOD_PATTERN =
      Pattern.compile("method\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  private static final Pattern INPUT_PATTERN =
      Pattern.compile(
          "<input[^>]*name\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);

  public CsrfDetectorWrapper(
      CsrfSettings csrfSettings, HttpClientService httpClientService, ReportService reportService) {
    this.detector = new CsrfDetector(csrfSettings, httpClientService, reportService);
    this.httpClientService = httpClientService;
  }

  @Override
  public void detect(String url) {
    try {
      try (Response response = httpClientService.executeRequest(url); ) {
        if (!response.isSuccessful() || response.body() == null) {
          return;
        }

        String pageContent = httpClientService.safeReadResponse(response);
        if (pageContent.isEmpty()) {
          return;
        }

        List<FormData> forms = parseSimpleForms(pageContent, url);

        detector.checkCsrfProtection(forms, url);
      }
    } catch (Exception e) {
      logger.warn("Error checking CSRF protection on {}: {}", url, e.getMessage());
    }
  }

  private List<FormData> parseSimpleForms(String htmlContent, String baseUrl) {
    List<FormData> forms = new java.util.ArrayList<>();

    Matcher formMatcher = FORM_PATTERN.matcher(htmlContent);

    while (formMatcher.find()) {
      try {
        String formTag = formMatcher.group(0);
        String formContent = formMatcher.group(1);

        String action = extractAction(formTag, baseUrl);
        String method = extractMethod(formTag);

        Map<String, String> inputs = extractInputs(formContent);

        boolean hasCSRFToken = inputs.keySet().stream().anyMatch(this::isCSRFTokenName);

        Optional<String> tokenName =
            inputs.keySet().stream().filter(this::isCSRFTokenName).findFirst();

        Optional<String> tokenValue =
            tokenName.isPresent()
                ? Optional.ofNullable(inputs.get(tokenName.get()))
                : Optional.empty();

        FormData formData =
            new FormData(action, method, hasCSRFToken, tokenName, tokenValue, inputs);
        forms.add(formData);

      } catch (Exception e) {
        logger.warn("Error parsing form: {}", e.getMessage());
      }
    }

    return forms;
  }

  private String extractAction(String formTag, String baseUrl) {
    Matcher matcher = ACTION_PATTERN.matcher(formTag);
    if (matcher.find()) {
      String action = matcher.group(1);
      if (action.isEmpty() || action.equals("#")) {
        return baseUrl;
      } else if (action.startsWith("/")) {
        return baseUrl.replaceAll("([^/]+//[^/]+)/.*", "$1") + action;
      } else if (!action.startsWith("http")) {
        return baseUrl + (baseUrl.endsWith("/") ? "" : "/") + action;
      }
      return action;
    }
    return baseUrl;
  }

  private String extractMethod(String formTag) {
    Matcher matcher = METHOD_PATTERN.matcher(formTag);
    return matcher.find() ? matcher.group(1) : "get";
  }

  private Map<String, String> extractInputs(String formContent) {
    Map<String, String> inputs = new HashMap<>();

    Matcher inputMatcher = INPUT_PATTERN.matcher(formContent);
    while (inputMatcher.find()) {
      String inputTag = inputMatcher.group(0);
      String name = inputMatcher.group(1);

      Pattern valuePattern =
          Pattern.compile("value\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
      Matcher valueMatcher = valuePattern.matcher(inputTag);
      String value = valueMatcher.find() ? valueMatcher.group(1) : "";

      inputs.put(name, value);
    }

    return inputs;
  }

  private boolean isCSRFTokenName(String name) {
    String lowerName = name.toLowerCase();
    return lowerName.contains("csrf")
        || lowerName.contains("token")
        || lowerName.contains("authenticity")
        || lowerName.equals("_token")
        || lowerName.equals("__requestverificationtoken");
  }

  @Override
  public String getDetectorType() {
    return "Cross-Site Request Forgery (CSRF)";
  }
}
