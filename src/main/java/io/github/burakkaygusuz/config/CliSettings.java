package io.github.burakkaygusuz.config;

public class CliSettings {

  private boolean enabled = true;
  private boolean autoShutdown = true;
  private boolean failOnVulnerabilities = false;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isAutoShutdown() {
    return autoShutdown;
  }

  public void setAutoShutdown(boolean autoShutdown) {
    this.autoShutdown = autoShutdown;
  }

  public boolean isFailOnVulnerabilities() {
    return failOnVulnerabilities;
  }

  public void setFailOnVulnerabilities(boolean failOnVulnerabilities) {
    this.failOnVulnerabilities = failOnVulnerabilities;
  }
}
