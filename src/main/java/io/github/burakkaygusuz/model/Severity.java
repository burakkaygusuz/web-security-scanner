package io.github.burakkaygusuz.model;

/** Enumeration for vulnerability severity levels. */
public enum Severity {
  LOW("LOW", 1),
  MEDIUM("MEDIUM", 2),
  HIGH("HIGH", 3),
  CRITICAL("CRITICAL", 4);

  private final String name;
  private final int score;

  Severity(String name, int score) {
    this.name = name;
    this.score = score;
  }

  /**
   * Gets the string representation of the severity.
   *
   * @return severity name
   */
  public String getName() {
    return name;
  }

  /**
   * Gets the numeric score for the severity.
   *
   * @return severity score (1-4)
   */
  public int getScore() {
    return score;
  }

  /**
   * Gets all severity names as an array for backward compatibility.
   *
   * @return array of severity names
   */
  public static String[] getAllNames() {
    return new String[] {LOW.name, MEDIUM.name, HIGH.name, CRITICAL.name};
  }

  /**
   * Finds severity by name.
   *
   * @param name the severity name
   * @return the matching severity, or null if not found
   */
  public static Severity fromName(String name) {
    if (name == null) return null;

    for (Severity severity : values()) {
      if (severity.name.equals(name)) {
        return severity;
      }
    }
    return null;
  }

  @Override
  public String toString() {
    return name;
  }
}
