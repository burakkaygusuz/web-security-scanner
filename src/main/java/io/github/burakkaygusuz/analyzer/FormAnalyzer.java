package io.github.burakkaygusuz.analyzer;

import io.github.burakkaygusuz.model.FormData;
import java.util.List;

/**
 * Interface for analyzing HTML forms to extract form data. This follows the Dependency Inversion
 * Principle by defining an abstraction that can have multiple implementations.
 */
public interface FormAnalyzer {

  /**
   * Analyzes the given HTML content and extracts all forms.
   *
   * @param htmlContent the HTML content to analyze
   * @param baseUrl the base URL for resolving relative form actions
   * @return list of extracted form data
   */
  List<FormData> analyzeForms(String htmlContent, String baseUrl);

  /**
   * Checks if the given HTML content contains any forms.
   *
   * @param htmlContent the HTML content to check
   * @return true if forms are present, false otherwise
   */
  default boolean hasForms(String htmlContent) {
    return !analyzeForms(htmlContent, "").isEmpty();
  }
}
