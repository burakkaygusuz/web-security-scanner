package io.github.burakkaygusuz.util;

import io.github.burakkaygusuz.model.FormData;
import io.github.burakkaygusuz.model.FormInput;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for parsing HTML forms from web pages. Used primarily for CSRF vulnerability
 * detection.
 */
public class FormParser {

  private static final Logger logger = LoggerFactory.getLogger(FormParser.class);

  private static final Pattern FORM_PATTERN =
      Pattern.compile("<form[^>]*>(.*?)</form>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  private static final Pattern ACTION_PATTERN =
      Pattern.compile("action\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  private static final Pattern METHOD_PATTERN =
      Pattern.compile("method\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  private static final Pattern INPUT_PATTERN =
      Pattern.compile("<input[^>]*>", Pattern.CASE_INSENSITIVE);

  private static final Pattern INPUT_NAME_PATTERN =
      Pattern.compile("name\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  private static final Pattern INPUT_TYPE_PATTERN =
      Pattern.compile("type\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  private static final Pattern INPUT_VALUE_PATTERN =
      Pattern.compile("value\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

  /**
   * Parses all forms from HTML content.
   *
   * @param htmlContent the HTML content to parse
   * @param baseUrl the base URL for resolving relative action URLs
   * @return list of parsed FormData objects
   */
  public static List<FormData> parseForms(String htmlContent, String baseUrl) {
    List<FormData> forms = new ArrayList<>();

    if (htmlContent == null || htmlContent.trim().isEmpty()) {
      return forms;
    }

    Matcher formMatcher = FORM_PATTERN.matcher(htmlContent);

    while (formMatcher.find()) {
      try {
        String formTag = formMatcher.group(0);
        String formContent = formMatcher.group(1);

        FormData formData = parseForm(formTag, formContent, baseUrl);
        if (formData != null) {
          forms.add(formData);
        }
      } catch (Exception e) {
        logger.warn("Error parsing form: {}", e.getMessage());
      }
    }

    return forms;
  }

  /** Parses a single form from its HTML content. */
  private static FormData parseForm(String formTag, String formContent, String baseUrl) {
    try {
      // Extract form attributes
      String action = extractAction(formTag, baseUrl);
      String method = extractMethod(formTag);

      // Parse form inputs
      List<FormInput> inputs = parseInputs(formContent);

      // Check for CSRF token
      boolean hasCSRFToken = inputs.stream().anyMatch(FormParser::isCSRFToken);
      Optional<String> tokenName =
          inputs.stream().filter(FormParser::isCSRFToken).map(FormInput::name).findFirst();
      Optional<String> tokenValue =
          inputs.stream().filter(FormParser::isCSRFToken).map(FormInput::value).findFirst();

      // Convert FormInput list to Map for compatibility with existing FormData
      Map<String, String> inputMap = new HashMap<>();
      for (FormInput input : inputs) {
        inputMap.put(input.name(), input.value());
      }

      return new FormData(action, method, hasCSRFToken, tokenName, tokenValue, inputMap);

    } catch (Exception e) {
      logger.warn("Error parsing individual form: {}", e.getMessage());
      return null;
    }
  }

  /** Extracts the action URL from form tag. */
  private static String extractAction(String formTag, String baseUrl) {
    Matcher actionMatcher = ACTION_PATTERN.matcher(formTag);

    if (actionMatcher.find()) {
      String action = actionMatcher.group(1);

      // Resolve relative URLs
      if (action.isEmpty() || action.equals("#")) {
        return baseUrl;
      } else if (action.startsWith("/")) {
        try {
          URI baseUri = new URI(baseUrl);
          return baseUri.getScheme()
              + "://"
              + baseUri.getHost()
              + (baseUri.getPort() != -1 ? ":" + baseUri.getPort() : "")
              + action;
        } catch (Exception e) {
          return baseUrl + action;
        }
      } else if (!action.startsWith("http")) {
        return baseUrl + (baseUrl.endsWith("/") ? "" : "/") + action;
      }

      return action;
    }

    return baseUrl; // Default to current page
  }

  /** Extracts the method from form tag. */
  private static String extractMethod(String formTag) {
    Matcher methodMatcher = METHOD_PATTERN.matcher(formTag);
    return methodMatcher.find() ? methodMatcher.group(1) : "get";
  }

  /** Parses all input elements from form content. */
  private static List<FormInput> parseInputs(String formContent) {
    List<FormInput> inputs = new ArrayList<>();

    Matcher inputMatcher = INPUT_PATTERN.matcher(formContent);

    while (inputMatcher.find()) {
      String inputTag = inputMatcher.group(0);

      String name = extractInputAttribute(inputTag, INPUT_NAME_PATTERN);
      String type = extractInputAttribute(inputTag, INPUT_TYPE_PATTERN);
      String value = extractInputAttribute(inputTag, INPUT_VALUE_PATTERN);

      if (!name.isEmpty()) {
        inputs.add(new FormInput(name, type.isEmpty() ? "text" : type, value));
      }
    }

    return inputs;
  }

  /** Extracts an attribute value from input tag using the given pattern. */
  private static String extractInputAttribute(String inputTag, Pattern pattern) {
    Matcher matcher = pattern.matcher(inputTag);
    return matcher.find() ? matcher.group(1) : "";
  }

  /** Checks if an input field is likely a CSRF token. */
  private static boolean isCSRFToken(FormInput input) {
    String name = input.name().toLowerCase();
    String type = input.type().toLowerCase();

    return "hidden".equals(type)
        && (name.contains("csrf")
            || name.contains("token")
            || name.contains("authenticity")
            || name.equals("_token")
            || name.equals("__RequestVerificationToken"));
  }
}
