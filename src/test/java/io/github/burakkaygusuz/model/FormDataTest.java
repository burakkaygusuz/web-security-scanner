package io.github.burakkaygusuz.model;

import static org.assertj.core.api.Assertions.*;

import java.util.Map;
import java.util.Optional;
import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.Test;

class FormDataTest {

  @Test
  void testFormDataCreation() {
    Map<String, String> inputs = Map.of("username", "test", "password", "secret");
    FormData formData =
        new FormData(
            "https://example.com/login",
            "POST",
            true,
            Optional.of("csrf_token"),
            Optional.of("abc123"),
            inputs);

    assertThat(formData)
        .extracting(
            FormData::action,
            FormData::method,
            FormData::hasCSRFToken,
            FormData::tokenName,
            FormData::tokenValue,
            FormData::inputs)
        .containsExactly(
            "https://example.com/login",
            "POST",
            true,
            Optional.of("csrf_token"),
            Optional.of("abc123"),
            inputs);
  }

  @Test
  void testFormDataWithoutCSRFToken() {
    Map<String, String> inputs = Map.of("username", "test");
    FormData formData =
        new FormData(
            "https://example.com/contact",
            "POST",
            false,
            Optional.empty(),
            Optional.empty(),
            inputs);

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(formData.action()).isEqualTo("https://example.com/contact");
          softly.assertThat(formData.method()).isEqualTo("POST");
          softly.assertThat(formData.hasCSRFToken()).isFalse();
          softly.assertThat(formData.tokenName()).isEmpty();
          softly.assertThat(formData.tokenValue()).isEmpty();
          softly.assertThat(formData.inputs()).isEqualTo(inputs);
        });
  }

  @Test
  void testIsStateChanging() {
    FormData postForm = createFormData("POST");
    FormData putForm = createFormData("PUT");
    FormData deleteForm = createFormData("DELETE");
    FormData patchForm = createFormData("PATCH");
    FormData getForm = createFormData("GET");

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(postForm.isStateChanging()).isTrue();
          softly.assertThat(putForm.isStateChanging()).isTrue();
          softly.assertThat(deleteForm.isStateChanging()).isTrue();
          softly.assertThat(patchForm.isStateChanging()).isTrue();
          softly.assertThat(getForm.isStateChanging()).isFalse();
        });
  }

  @Test
  void testGetTokenNameOrEmpty() {
    FormData withToken =
        new FormData(
            "https://example.com/form",
            "POST",
            true,
            Optional.of("csrf_token"),
            Optional.of("value"),
            Map.of());

    FormData withoutToken =
        new FormData(
            "https://example.com/form",
            "POST",
            false,
            Optional.empty(),
            Optional.empty(),
            Map.of());

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(withToken.getTokenNameOrEmpty()).isEqualTo("csrf_token");
          softly.assertThat(withoutToken.getTokenNameOrEmpty()).isEmpty();
        });
  }

  @Test
  void testGetTokenValueOrEmpty() {
    FormData withToken =
        new FormData(
            "https://example.com/form",
            "POST",
            true,
            Optional.of("csrf_token"),
            Optional.of("abc123"),
            Map.of());

    FormData withoutToken =
        new FormData(
            "https://example.com/form",
            "POST",
            false,
            Optional.empty(),
            Optional.empty(),
            Map.of());

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(withToken.getTokenValueOrEmpty()).isEqualTo("abc123");
          softly.assertThat(withoutToken.getTokenValueOrEmpty()).isEmpty();
        });
  }

  @Test
  void testValidationErrors() {
    SoftAssertions.assertSoftly(
        softly -> {
          // Null action
          softly
              .assertThatThrownBy(
                  () ->
                      new FormData(
                          null, "POST", false, Optional.empty(), Optional.empty(), Map.of()))
              .isInstanceOf(NullPointerException.class)
              .hasMessageContaining("Form action cannot be null");

          // Null method
          softly
              .assertThatThrownBy(
                  () ->
                      new FormData(
                          "https://example.com",
                          null,
                          false,
                          Optional.empty(),
                          Optional.empty(),
                          Map.of()))
              .isInstanceOf(NullPointerException.class)
              .hasMessageContaining("Form method cannot be null");

          // Null token name Optional
          softly
              .assertThatThrownBy(
                  () ->
                      new FormData(
                          "https://example.com", "POST", false, null, Optional.empty(), Map.of()))
              .isInstanceOf(NullPointerException.class)
              .hasMessageContaining("Token name Optional cannot be null");

          // Null token value Optional
          softly
              .assertThatThrownBy(
                  () ->
                      new FormData(
                          "https://example.com", "POST", false, Optional.empty(), null, Map.of()))
              .isInstanceOf(NullPointerException.class)
              .hasMessageContaining("Token value Optional cannot be null");

          // Null inputs
          softly
              .assertThatThrownBy(
                  () ->
                      new FormData(
                          "https://example.com",
                          "POST",
                          false,
                          Optional.empty(),
                          Optional.empty(),
                          null))
              .isInstanceOf(NullPointerException.class)
              .hasMessageContaining("Form inputs cannot be null");
        });
  }

  @Test
  void testInputsImmutability() {
    Map<String, String> originalInputs = Map.of("field1", "value1");
    FormData formData =
        new FormData(
            "https://example.com",
            "POST",
            false,
            Optional.empty(),
            Optional.empty(),
            originalInputs);

    assertThatThrownBy(() -> formData.inputs().put("field2", "value2"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void testCaseInsensitiveMethodCheck() {
    FormData lowerCasePost = createFormData("post");
    FormData upperCasePost = createFormData("POST");
    FormData mixedCasePost = createFormData("Post");

    assertThat(lowerCasePost.isStateChanging()).isTrue();
    assertThat(upperCasePost.isStateChanging()).isTrue();
    assertThat(mixedCasePost.isStateChanging()).isTrue();
  }

  @Test
  void testFormDataEquality() {
    Map<String, String> inputs = Map.of("field", "value");

    FormData form1 =
        new FormData(
            "https://example.com",
            "POST",
            true,
            Optional.of("token"),
            Optional.of("value"),
            inputs);

    FormData form2 =
        new FormData(
            "https://example.com",
            "POST",
            true,
            Optional.of("token"),
            Optional.of("value"),
            inputs);

    FormData form3 =
        new FormData(
            "https://different.com",
            "POST",
            true,
            Optional.of("token"),
            Optional.of("value"),
            inputs);

    SoftAssertions.assertSoftly(
        softly -> {
          softly.assertThat(form1).isEqualTo(form2);
          softly.assertThat(form1).isNotEqualTo(form3);
          softly.assertThat(form1).hasSameHashCodeAs(form2);
        });
  }

  @Test
  void testFormDataToString() {
    FormData formData =
        new FormData(
            "https://example.com/form",
            "POST",
            true,
            Optional.of("csrf_token"),
            Optional.of("abc123"),
            Map.of("username", "test"));

    assertThat(formData.toString())
        .contains("FormData")
        .contains("https://example.com/form")
        .contains("POST")
        .contains("csrf_token");
  }

  // Helper method
  private FormData createFormData(String method) {
    return new FormData(
        "https://example.com/" + method.toLowerCase(),
        method,
        false,
        Optional.empty(),
        Optional.empty(),
        Map.of());
  }
}
