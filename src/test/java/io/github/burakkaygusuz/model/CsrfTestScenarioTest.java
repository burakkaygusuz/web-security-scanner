package io.github.burakkaygusuz.model;

import static org.assertj.core.api.Assertions.*;

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.Test;

class CsrfTestScenarioTest {

  @Test
  void testAllScenariosHaveRequiredProperties() {
    CsrfTestScenario[] scenarios = CsrfTestScenario.values();

    assertThat(scenarios).hasSize(6);

    for (CsrfTestScenario scenario : scenarios) {
      SoftAssertions.assertSoftly(
          softly -> {
            softly.assertThat(scenario.getDisplayName()).isNotNull().isNotEmpty();
            softly.assertThat(scenario.getDescription()).isNotNull().isNotEmpty();
            softly.assertThat(scenario.getSeverity()).isNotNull().isNotEmpty();
          });
    }
  }

  @Test
  void testScenarioDisplayNames() {
    SoftAssertions.assertSoftly(
        softly -> {
          softly
              .assertThat(CsrfTestScenario.NO_TOKEN_TEST.getDisplayName())
              .isEqualTo("No CSRF Token");
          softly
              .assertThat(CsrfTestScenario.INVALID_TOKEN_TEST.getDisplayName())
              .isEqualTo("Invalid CSRF Token");
          softly
              .assertThat(CsrfTestScenario.EXPIRED_TOKEN_TEST.getDisplayName())
              .isEqualTo("Expired CSRF Token");
          softly
              .assertThat(CsrfTestScenario.REUSED_TOKEN_TEST.getDisplayName())
              .isEqualTo("Reused CSRF Token");
          softly
              .assertThat(CsrfTestScenario.MISSING_SAMESITE_COOKIE.getDisplayName())
              .isEqualTo("Missing SameSite Cookie");
          softly
              .assertThat(CsrfTestScenario.WEAK_REFERER_VALIDATION.getDisplayName())
              .isEqualTo("Weak Referer Validation");
        });
  }

  @Test
  void testScenarioDescriptions() {
    SoftAssertions.assertSoftly(
        softly -> {
          softly
              .assertThat(CsrfTestScenario.NO_TOKEN_TEST.getDescription())
              .isEqualTo("Form submitted without CSRF token");
          softly
              .assertThat(CsrfTestScenario.INVALID_TOKEN_TEST.getDescription())
              .isEqualTo("Form submitted with invalid CSRF token");
          softly
              .assertThat(CsrfTestScenario.EXPIRED_TOKEN_TEST.getDescription())
              .isEqualTo("Form submitted with expired CSRF token");
          softly
              .assertThat(CsrfTestScenario.REUSED_TOKEN_TEST.getDescription())
              .isEqualTo("Form submitted with reused CSRF token");
          softly
              .assertThat(CsrfTestScenario.MISSING_SAMESITE_COOKIE.getDescription())
              .isEqualTo("Session cookies lack SameSite attribute");
          softly
              .assertThat(CsrfTestScenario.WEAK_REFERER_VALIDATION.getDescription())
              .isEqualTo("Insufficient Referer header validation");
        });
  }

  @Test
  void testSeverityLevels() {
    SoftAssertions.assertSoftly(
        softly -> {
          // CRITICAL scenarios
          softly.assertThat(CsrfTestScenario.NO_TOKEN_TEST.getSeverity()).isEqualTo("CRITICAL");

          // HIGH scenarios
          softly.assertThat(CsrfTestScenario.INVALID_TOKEN_TEST.getSeverity()).isEqualTo("HIGH");
          softly.assertThat(CsrfTestScenario.REUSED_TOKEN_TEST.getSeverity()).isEqualTo("HIGH");

          // MEDIUM scenarios
          softly.assertThat(CsrfTestScenario.EXPIRED_TOKEN_TEST.getSeverity()).isEqualTo("MEDIUM");
          softly
              .assertThat(CsrfTestScenario.WEAK_REFERER_VALIDATION.getSeverity())
              .isEqualTo("MEDIUM");

          // LOW scenarios
          softly
              .assertThat(CsrfTestScenario.MISSING_SAMESITE_COOKIE.getSeverity())
              .isEqualTo("LOW");
        });
  }

  @Test
  void testSeverityOrdering() {
    // Test that we have scenarios across all severity levels
    assertThat(CsrfTestScenario.values())
        .extracting(CsrfTestScenario::getSeverity)
        .contains("CRITICAL", "HIGH", "MEDIUM", "LOW");
  }

  @Test
  void testEnumConsistency() {
    // Test that enum values don't change unexpectedly
    assertThat(CsrfTestScenario.values())
        .extracting(Enum::name)
        .containsExactly(
            "NO_TOKEN_TEST",
            "INVALID_TOKEN_TEST",
            "EXPIRED_TOKEN_TEST",
            "REUSED_TOKEN_TEST",
            "MISSING_SAMESITE_COOKIE",
            "WEAK_REFERER_VALIDATION");
  }

  @Test
  void testToStringContainsEnumName() {
    for (CsrfTestScenario scenario : CsrfTestScenario.values()) {
      assertThat(scenario.toString()).contains(scenario.name());
    }
  }

  @Test
  void testCriticalScenarios() {
    assertThat(CsrfTestScenario.values())
        .filteredOn(scenario -> "CRITICAL".equals(scenario.getSeverity()))
        .hasSize(1)
        .containsExactly(CsrfTestScenario.NO_TOKEN_TEST);
  }

  @Test
  void testHighSeverityScenarios() {
    assertThat(CsrfTestScenario.values())
        .filteredOn(scenario -> "HIGH".equals(scenario.getSeverity()))
        .hasSize(2)
        .containsExactlyInAnyOrder(
            CsrfTestScenario.INVALID_TOKEN_TEST, CsrfTestScenario.REUSED_TOKEN_TEST);
  }

  @Test
  void testMediumSeverityScenarios() {
    assertThat(CsrfTestScenario.values())
        .filteredOn(scenario -> "MEDIUM".equals(scenario.getSeverity()))
        .hasSize(2)
        .containsExactlyInAnyOrder(
            CsrfTestScenario.EXPIRED_TOKEN_TEST, CsrfTestScenario.WEAK_REFERER_VALIDATION);
  }
}
