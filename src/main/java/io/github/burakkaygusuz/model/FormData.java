package io.github.burakkaygusuz.model;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Represents form data extracted from HTML forms during CSRF vulnerability scanning.
 *
 * @param action The form action URL
 * @param method HTTP method (GET, POST, PUT, DELETE, etc.)
 * @param hasCSRFToken Whether the form contains a CSRF token
 * @param tokenName Name of the CSRF token field (if present)
 * @param tokenValue Value of the CSRF token (if present)
 * @param inputs Map of all form input fields and their values
 */
public record FormData(
    String action,
    String method,
    boolean hasCSRFToken,
    Optional<String> tokenName,
    Optional<String> tokenValue,
    Map<String, String> inputs) {

  public FormData {
    Objects.requireNonNull(action, "Form action cannot be null");
    Objects.requireNonNull(method, "Form method cannot be null");
    Objects.requireNonNull(tokenName, "Token name Optional cannot be null");
    Objects.requireNonNull(tokenValue, "Token value Optional cannot be null");
    Objects.requireNonNull(inputs, "Form inputs cannot be null");

    // Make inputs immutable
    inputs = Map.copyOf(inputs);
  }

  /**
   * Checks if this form uses a state-changing HTTP method.
   *
   * @return true if method is POST, PUT, DELETE, PATCH
   */
  public boolean isStateChanging() {
    return switch (method.toUpperCase()) {
      case "POST", "PUT", "DELETE", "PATCH" -> true;
      default -> false;
    };
  }

  /**
   * Gets the CSRF token name if present.
   *
   * @return CSRF token name or empty string if not present
   */
  public String getTokenNameOrEmpty() {
    return tokenName.orElse("");
  }

  /**
   * Gets the CSRF token value if present.
   *
   * @return CSRF token value or empty string if not present
   */
  public String getTokenValueOrEmpty() {
    return tokenValue.orElse("");
  }
}
