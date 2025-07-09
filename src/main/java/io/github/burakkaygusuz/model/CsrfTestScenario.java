package io.github.burakkaygusuz.model;

/**
 * Enumeration of different CSRF test scenarios. Each scenario represents a specific way to test
 * CSRF protection mechanisms.
 */
public enum CsrfTestScenario {

  /**
   * Test form submission without any CSRF token. This should be blocked if CSRF protection is
   * properly implemented.
   */
  NO_TOKEN_TEST("No CSRF Token", "Form submitted without CSRF token"),

  /**
   * Test form submission with an invalid/fake CSRF token. This should be blocked if token
   * validation is working.
   */
  INVALID_TOKEN_TEST("Invalid CSRF Token", "Form submitted with invalid CSRF token"),

  /**
   * Test form submission with an expired CSRF token. This should be blocked if token expiration is
   * implemented.
   */
  EXPIRED_TOKEN_TEST("Expired CSRF Token", "Form submitted with expired CSRF token"),

  /**
   * Test form submission with a previously used CSRF token. This should be blocked if token reuse
   * prevention is implemented.
   */
  REUSED_TOKEN_TEST("Reused CSRF Token", "Form submitted with reused CSRF token"),

  /**
   * Test for missing SameSite cookie attribute. This represents a weaker but still important CSRF
   * protection.
   */
  MISSING_SAMESITE_COOKIE("Missing SameSite Cookie", "Session cookies lack SameSite attribute"),

  /**
   * Test for missing or weak Referer header validation. This is an additional CSRF protection
   * mechanism.
   */
  WEAK_REFERER_VALIDATION("Weak Referer Validation", "Insufficient Referer header validation");

  private final String displayName;
  private final String description;

  CsrfTestScenario(String displayName, String description) {
    this.displayName = displayName;
    this.description = description;
  }

  /**
   * Gets the human-readable display name for this test scenario.
   *
   * @return display name
   */
  public String getDisplayName() {
    return displayName;
  }

  /**
   * Gets a detailed description of what this test scenario checks.
   *
   * @return description
   */
  public String getDescription() {
    return description;
  }

  /**
   * Determines the severity level for a vulnerability found in this scenario.
   *
   * @return severity level
   */
  public String getSeverity() {
    return switch (this) {
      case NO_TOKEN_TEST -> Severity.CRITICAL.getName();
      case INVALID_TOKEN_TEST, REUSED_TOKEN_TEST -> Severity.HIGH.getName();
      case EXPIRED_TOKEN_TEST, WEAK_REFERER_VALIDATION -> Severity.MEDIUM.getName();
      case MISSING_SAMESITE_COOKIE -> Severity.LOW.getName();
    };
  }

  /**
   * Gets the severity enum for this test scenario.
   *
   * @return severity enum
   */
  public Severity getSeverityEnum() {
    return switch (this) {
      case NO_TOKEN_TEST -> Severity.CRITICAL;
      case INVALID_TOKEN_TEST, REUSED_TOKEN_TEST -> Severity.HIGH;
      case EXPIRED_TOKEN_TEST, WEAK_REFERER_VALIDATION -> Severity.MEDIUM;
      case MISSING_SAMESITE_COOKIE -> Severity.LOW;
    };
  }
}
