package io.github.burakkaygusuz.detector;

import io.github.burakkaygusuz.config.CsrfSettings;
import io.github.burakkaygusuz.model.CsrfTestScenario;
import io.github.burakkaygusuz.model.FormData;
import io.github.burakkaygusuz.model.Vulnerability;
import io.github.burakkaygusuz.service.HttpClientService;
import io.github.burakkaygusuz.service.ReportService;
import io.github.burakkaygusuz.util.UrlUtils;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import okhttp3.Headers;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CSRF vulnerability detector. Tests forms for common CSRF weaknesses and reports vulnerabilities.
 */
public class CsrfDetector {

  private static final Logger logger = LoggerFactory.getLogger(CsrfDetector.class);

  private final CsrfSettings csrfSettings;
  private final HttpClientService httpClientService;
  private final ReportService reportService;

  public CsrfDetector(
      CsrfSettings csrfSettings, HttpClientService httpClientService, ReportService reportService) {
    this.csrfSettings = csrfSettings;
    this.httpClientService = httpClientService;
    this.reportService = reportService;
  }

  /**
   * Checks for CSRF vulnerabilities in the provided forms.
   *
   * @param forms the list of forms to test
   * @param url the URL of the page that contains the forms
   */
  public void checkCsrfProtection(List<FormData> forms, String url) {
    for (FormData form : forms) {
      if (!form.isStateChanging() || !csrfSettings.isTestForms()) {
        continue;
      }

      checkFormCsrfProtection(form, url);
    }
  }

  /**
   * Performs specific CSRF tests on a form and reports vulnerabilities.
   *
   * @param form the form to test
   * @param pageUrl the URL of the page that contains the form
   */
  private void checkFormCsrfProtection(FormData form, String pageUrl) {
    URI formActionUri = URI.create(form.action());

    if (!form.hasCSRFToken()) {
      reportCsrfVulnerability(form, pageUrl, CsrfTestScenario.NO_TOKEN_TEST);
    }

    try {
      simulateFormSubmission(form, formActionUri, pageUrl, null, CsrfTestScenario.NO_TOKEN_TEST);

    } catch (IOException e) {
      logger.warn("Error testing CSRF protection on {}: {}", pageUrl, e.getMessage());
    }
  }

  /**
   * Simulates a form submission with various scenarios (e.g., without token) and checks the
   * response for CSRF protection vulnerabilities.
   */
  private void simulateFormSubmission(
      FormData form, URI formActionUri, String pageUrl, String token, CsrfTestScenario scenario)
      throws IOException {

    Headers.Builder headersBuilder = new Headers.Builder();
    headersBuilder.add("Content-Type", "application/x-www-form-urlencoded");

    if (csrfSettings.isCheckSameSiteCookies()) {
      headersBuilder.add("Cookie", "key=value; SameSite=None");
    }

    if (scenario == CsrfTestScenario.NO_TOKEN_TEST) {
      token = null;
    }

    String formData = UrlUtils.buildFormData(form.inputs(), token, "token");
    RequestBody body = RequestBody.create(formData.getBytes());

    Request request =
        new Request.Builder()
            .url(formActionUri.toString())
            .post(body)
            .headers(headersBuilder.build())
            .build();

    try (Response response = httpClientService.executeRequest(request)) {
      if (!response.isSuccessful() || response.body() == null) {
        return;
      }

      String responseText = response.body().string();
      if (responseText.contains("CSRF token missing or incorrect")) {
        reportCsrfVulnerability(form, pageUrl, scenario);
      }
    }
  }

  private void reportCsrfVulnerability(FormData form, String pageUrl, CsrfTestScenario scenario) {
    String message =
        String.format(
            "CSRF vulnerability detected: %s (Form action: %s)",
            scenario.getDescription(), form.action());
    logger.warn(message);
    reportService.reportVulnerability(
        form.hasCSRFToken()
            ? new Vulnerability(
                scenario.getDisplayName(), pageUrl, form.getTokenNameOrEmpty(), "Detected")
            : new Vulnerability(scenario.getDisplayName(), pageUrl, "None", "Token missing"));
  }
}
