package io.github.burakkaygusuz.service;

import static org.assertj.core.api.Assertions.*;

import io.github.burakkaygusuz.Vulnerability;
import java.util.List;
import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReportServiceTest {

  private ReportService reportService;
  private Vulnerability sqlVulnerability;
  private Vulnerability xssVulnerability;
  private Vulnerability sensitiveInfoVulnerability;

  @BeforeEach
  void setUp() {
    reportService = new ReportService();

    sqlVulnerability =
        new Vulnerability("SQL Injection", "https://example.com/search?id=123", "id", "' OR 1=1--");

    xssVulnerability =
        new Vulnerability(
            "Cross-Site Scripting (XSS)",
            "https://example.com/search?q=test",
            "q",
            "<script>alert('XSS')</script>");

    sensitiveInfoVulnerability =
        new Vulnerability(
            "Sensitive Information Exposure",
            "https://example.com/profile",
            "email",
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
  }

  @Test
  void testReportVulnerability() {
    reportService.reportVulnerability(sqlVulnerability);

    assertThat(reportService).extracting(ReportService::getVulnerabilityCount).isEqualTo(1);

    assertThat(reportService.getVulnerabilities()).hasSize(1).containsExactly(sqlVulnerability);
  }

  @Test
  void testReportMultipleVulnerabilities() {
    reportService.reportVulnerability(sqlVulnerability);
    reportService.reportVulnerability(xssVulnerability);
    reportService.reportVulnerability(sensitiveInfoVulnerability);

    assertThat(reportService.getVulnerabilities())
        .hasSize(3)
        .containsExactly(sqlVulnerability, xssVulnerability, sensitiveInfoVulnerability);
  }

  @Test
  void testReportDuplicateVulnerability() {
    reportService.reportVulnerability(sqlVulnerability);
    reportService.reportVulnerability(sqlVulnerability); // Duplicate

    assertThat(reportService.getVulnerabilities()).hasSize(1).containsExactly(sqlVulnerability);
  }

  @Test
  void testGetVulnerabilitiesBySeverity() {
    reportService.reportVulnerability(sensitiveInfoVulnerability); // MEDIUM
    reportService.reportVulnerability(xssVulnerability); // HIGH
    reportService.reportVulnerability(sqlVulnerability); // CRITICAL

    assertThat(reportService.getVulnerabilitiesBySeverity())
        .hasSize(3)
        .extracting(Vulnerability::type)
        .containsExactly(
            "SQL Injection", // CRITICAL first
            "Cross-Site Scripting (XSS)", // HIGH second
            "Sensitive Information Exposure" // MEDIUM last
            );
  }

  @Test
  void testGetFirstVulnerabilityWhenEmpty() {
    assertThat(reportService.getFirstVulnerability()).isNull();
  }

  @Test
  void testGetLastVulnerabilityWhenEmpty() {
    assertThat(reportService.getLastVulnerability()).isNull();
  }

  @Test
  void testGetFirstAndLastVulnerability() {
    reportService.reportVulnerability(sqlVulnerability);
    reportService.reportVulnerability(xssVulnerability);
    reportService.reportVulnerability(sensitiveInfoVulnerability);

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(reportService.getFirstVulnerability()).isEqualTo(sqlVulnerability);
          softly
              .assertThat(reportService.getLastVulnerability())
              .isEqualTo(sensitiveInfoVulnerability);
        });
  }

  @Test
  void testGetFirstAndLastVulnerabilityWithSingleItem() {
    reportService.reportVulnerability(sqlVulnerability);

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(reportService.getFirstVulnerability()).isEqualTo(sqlVulnerability);
          softly.assertThat(reportService.getLastVulnerability()).isEqualTo(sqlVulnerability);
        });
  }

  @Test
  void testGetVulnerabilityCountWhenEmpty() {
    assertThat(reportService.getVulnerabilityCount()).isZero();
  }

  @Test
  void testClearVulnerabilities() {
    reportService.reportVulnerability(sqlVulnerability);
    reportService.reportVulnerability(xssVulnerability);

    assertThat(reportService.getVulnerabilityCount()).isEqualTo(2);

    reportService.clear();

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(reportService.getVulnerabilityCount()).isZero();
          softly.assertThat(reportService.getVulnerabilities()).isEmpty();
          softly.assertThat(reportService.getFirstVulnerability()).isNull();
          softly.assertThat(reportService.getLastVulnerability()).isNull();
        });
  }

  @Test
  void testGetVulnerabilitiesIsUnmodifiable() {
    reportService.reportVulnerability(sqlVulnerability);
    List<Vulnerability> vulnerabilities = reportService.getVulnerabilities();

    assertThatThrownBy(() -> vulnerabilities.add(xssVulnerability))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void testConcurrentAccess() throws InterruptedException {
    final int threadCount = 10;
    final int vulnerabilitiesPerThread = 100;
    Thread[] threads = new Thread[threadCount];

    for (int i = 0; i < threadCount; i++) {
      final int threadId = i;
      threads[i] =
          new Thread(
              () -> {
                for (int j = 0; j < vulnerabilitiesPerThread; j++) {
                  Vulnerability vuln =
                      new Vulnerability(
                          "SQL Injection",
                          "https://example.com/test" + threadId + "_" + j,
                          "id",
                          "' OR 1=1--");
                  reportService.reportVulnerability(vuln);
                }
              });
    }

    for (Thread thread : threads) {
      thread.start();
    }

    for (Thread thread : threads) {
      thread.join();
    }

    assertThat(reportService.getVulnerabilityCount())
        .isEqualTo(threadCount * vulnerabilitiesPerThread);
  }

  @Test
  void testSeveritySortingWithSameSeverityDifferentTypes() {
    Vulnerability customVulnerability =
        new Vulnerability("Unknown Type", "https://example.com/test", "param", "payload");

    reportService.reportVulnerability(customVulnerability); // LOW
    reportService.reportVulnerability(sensitiveInfoVulnerability); // MEDIUM

    assertThat(reportService.getVulnerabilitiesBySeverity())
        .hasSize(2)
        .extracting(Vulnerability::type)
        .containsExactly("Sensitive Information Exposure", "Unknown Type");
  }
}
