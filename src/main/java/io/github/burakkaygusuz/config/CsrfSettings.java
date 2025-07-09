package io.github.burakkaygusuz.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.List;

/**
 * Configuration properties for CSRF vulnerability testing. Used as nested configuration in
 * ScannerConfig.
 */
public class CsrfSettings {

  /** Whether to analyze forms for CSRF protection */
  private boolean testForms = true;

  /** Whether to check for SameSite cookie attributes */
  private boolean checkSameSiteCookies = true;

  /** Whether to validate CSRF token entropy/randomness */
  private boolean tokenEntropyCheck = true;

  /** Whether to simulate cross-origin requests */
  private boolean simulateCrossOrigin = false;

  /** List of common CSRF token field names to look for */
  @NotNull
  private List<String> commonTokenNames =
      List.of(
          "csrf_token",
          "csrftoken",
          "_token",
          "authenticity_token",
          "csrf",
          "_csrf",
          "csrfmiddlewaretoken",
          "csrfToken",
          "__RequestVerificationToken",
          "anti-forgery-token");

  /** Minimum acceptable length for CSRF tokens */
  @Min(8)
  private int minimumTokenLength = 16;

  public boolean isTestForms() {
    return testForms;
  }

  public void setTestForms(boolean testForms) {
    this.testForms = testForms;
  }

  public boolean isCheckSameSiteCookies() {
    return checkSameSiteCookies;
  }

  public void setCheckSameSiteCookies(boolean checkSameSiteCookies) {
    this.checkSameSiteCookies = checkSameSiteCookies;
  }

  public boolean isTokenEntropyCheck() {
    return tokenEntropyCheck;
  }

  public void setTokenEntropyCheck(boolean tokenEntropyCheck) {
    this.tokenEntropyCheck = tokenEntropyCheck;
  }

  public boolean isSimulateCrossOrigin() {
    return simulateCrossOrigin;
  }

  public void setSimulateCrossOrigin(boolean simulateCrossOrigin) {
    this.simulateCrossOrigin = simulateCrossOrigin;
  }

  public List<String> getCommonTokenNames() {
    return commonTokenNames;
  }

  public void setCommonTokenNames(List<String> commonTokenNames) {
    this.commonTokenNames = commonTokenNames;
  }

  public int getMinimumTokenLength() {
    return minimumTokenLength;
  }

  public void setMinimumTokenLength(int minimumTokenLength) {
    this.minimumTokenLength = minimumTokenLength;
  }

  /**
   * Creates default CSRF settings with sensible defaults. Note: With Spring Boot, defaults are
   * handled via field initialization.
   *
   * @return default CSRF settings
   */
  public static CsrfSettings defaultSettings() {
    return new CsrfSettings();
  }

  /**
   * Checks if the given field name is a known CSRF token field.
   *
   * @param fieldName the field name to check
   * @return true if it's a known CSRF token field name
   */
  public boolean isKnownTokenField(String fieldName) {
    if (fieldName == null) {
      return false;
    }

    String lowerFieldName = fieldName.toLowerCase();
    return commonTokenNames.stream()
        .anyMatch(tokenName -> lowerFieldName.contains(tokenName.toLowerCase()));
  }
}
