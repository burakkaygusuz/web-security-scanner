package io.github.burakkaygusuz.analyzer;

import io.github.burakkaygusuz.config.CsrfSettings;
import io.github.burakkaygusuz.model.FormData;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSoup-based implementation of FormAnalyzer. This class handles the parsing of HTML forms using
 * JSoup library.
 */
public class JSoupFormAnalyzer implements FormAnalyzer {

  private static final Logger logger = LoggerFactory.getLogger(JSoupFormAnalyzer.class);

  private final CsrfSettings csrfSettings;

  public JSoupFormAnalyzer(CsrfSettings csrfSettings) {
    this.csrfSettings = csrfSettings;
  }

  @Override
  public List<FormData> analyzeForms(String htmlContent, String baseUrl) {
    try {
      Document document = Jsoup.parse(htmlContent, baseUrl);
      Elements forms = document.select("form");

      return forms.stream()
          .map(form -> extractFormData(form, baseUrl))
          .filter(Optional::isPresent)
          .map(Optional::get)
          .toList();
    } catch (Exception e) {
      logger.warn("Error parsing HTML forms: {}", e.getMessage());
      return List.of();
    }
  }

  /**
   * Extracts form data from a single form element.
   *
   * @param form the form element to analyze
   * @param baseUrl the base URL for resolving relative actions
   * @return extracted form data or empty if extraction fails
   */
  private Optional<FormData> extractFormData(Element form, String baseUrl) {
    try {
      String action = resolveAction(form, baseUrl);
      String method = form.attr("method").toUpperCase();
      if (method.isEmpty()) {
        method = "GET"; // Default HTTP method for forms
      }

      Map<String, String> inputs = extractInputs(form);
      Optional<String> tokenName = findTokenName(inputs);
      Optional<String> tokenValue = tokenName.map(inputs::get);

      boolean hasCSRFToken = tokenName.isPresent();

      return Optional.of(new FormData(action, method, hasCSRFToken, tokenName, tokenValue, inputs));
    } catch (Exception e) {
      logger.warn("Error extracting form data: {}", e.getMessage());
      return Optional.empty();
    }
  }

  /**
   * Resolves the form action URL relative to the base URL.
   *
   * @param form the form element
   * @param baseUrl the base URL
   * @return resolved action URL
   */
  private String resolveAction(Element form, String baseUrl) {
    String action = form.attr("action");
    if (action.isEmpty()) {
      return baseUrl; // Form submits to same page if no action specified
    }

    try {
      URI baseUri = new URI(baseUrl);
      URI actionUri = baseUri.resolve(action);
      return actionUri.toString();
    } catch (URISyntaxException e) {
      logger.warn("Error resolving form action URL: {}", e.getMessage());
      return action; // Return original action if resolution fails
    }
  }

  /**
   * Extracts all input elements from the form.
   *
   * @param form the form element
   * @return map of input names to values
   */
  private Map<String, String> extractInputs(Element form) {
    Map<String, String> inputs = new HashMap<>();

    // Extract input elements
    Elements inputElements = form.select("input, textarea, select");
    for (Element input : inputElements) {
      String name = input.attr("name");
      String value = input.attr("value");

      if (!name.isEmpty()) {
        inputs.put(name, value);
      }
    }

    return inputs;
  }

  /**
   * Attempts to find a CSRF token field among the inputs.
   *
   * @param inputs map of form inputs
   * @return optional token field name
   */
  private Optional<String> findTokenName(Map<String, String> inputs) {
    return inputs.keySet().stream().filter(csrfSettings::isKnownTokenField).findFirst();
  }
}
