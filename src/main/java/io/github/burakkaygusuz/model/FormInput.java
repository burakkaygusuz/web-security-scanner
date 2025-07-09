package io.github.burakkaygusuz.model;

import java.util.Objects;

/**
 * Represents an HTML form input element.
 *
 * @param name The name attribute of the input
 * @param type The type attribute of the input (text, password, hidden, etc.)
 * @param value The value attribute of the input
 */
public record FormInput(String name, String type, String value) {

  public FormInput {
    Objects.requireNonNull(name, "Input name cannot be null");
    Objects.requireNonNull(type, "Input type cannot be null");
    Objects.requireNonNull(value, "Input value cannot be null");
  }

  public FormInput(String name, String type) {
    this(name, type, "");
  }

  public boolean isHidden() {
    return "hidden".equalsIgnoreCase(type);
  }

  public boolean isLikelyCSRFToken() {
    String lowerName = name.toLowerCase();
    return isHidden()
        && (lowerName.contains("csrf")
            || lowerName.contains("token")
            || lowerName.contains("authenticity")
            || lowerName.equals("_token")
            || lowerName.equals("__requestverificationtoken"));
  }
}
